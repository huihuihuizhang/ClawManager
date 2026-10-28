package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"time"
)

const recoveryFenceDigest = "system-backup-producer-recovery-fence.c1"

// RecoveryFenceRequest is a CAS target, never a management credential. A
// trusted admission must independently bind both identity hashes to the
// current deployment before this transaction can change the fence.
type RecoveryFenceRequest struct {
	Scope              Scope       `json:"scope"`
	Operation          string      `json:"operation"` // register, rotate, revoke
	IdentityHash       Hash        `json:"identity_hash"`
	NextIdentityHash   *Hash       `json:"next_identity_hash"`
	ExpectedEpoch      ZeroCounter `json:"expected_epoch"`
	ExpectedRowVersion ZeroCounter `json:"expected_row_version"`
	ReasonHash         Hash        `json:"reason_hash"`
}

func RecoveryFenceHash(r RecoveryFenceRequest) (Hash, error) {
	if !in(r.Operation, "register", "rotate", "revoke") || validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	if r.Operation != "rotate" && r.NextIdentityHash != nil || r.Operation == "register" && (r.ExpectedEpoch != "0" || r.ExpectedRowVersion != "0") || r.Operation != "register" && (r.ExpectedEpoch == "0" || r.ExpectedRowVersion == "0") {
		return "", ErrInvalid
	}
	if v, err := r.ExpectedEpoch.Uint64(); err != nil || v > 1<<63-1 {
		return "", ErrInvalid
	}
	if v, err := r.ExpectedRowVersion.Uint64(); err != nil || v > 1<<63-1 {
		return "", ErrInvalid
	}
	if r.Operation != "register" {
		if next, err := resultNext(r.ExpectedEpoch); err != nil {
			return "", err
		} else if _, err = next.SQLInt64(); err != nil {
			return "", err
		}
		if next, err := resultNext(r.ExpectedRowVersion); err != nil {
			return "", err
		} else if _, err = next.SQLInt64(); err != nil {
			return "", err
		}
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(recoveryFenceDigest, m)
}

type RecoveryFenceEnvironment interface {
	PrepareRecoveryFence(context.Context, RecoveryFenceRequest) (RecoveryFenceSession, error)
}

type RecoveryFenceSession interface {
	// L0/L1 must lock the installation and current deployment admission.
	LockInstallation(context.Context, SQL, RecoveryFenceRequest) error
	// The admission must come from an independent current management identity,
	// bind both old/new hashes and the exact request, and check deployment state.
	Authorize(context.Context, SQL, RecoveryFenceRequest, RecoveryFenceRow) (RecoveryFenceAdmission, error)
	// Emergency revoke audit must have capacity independent of normal admission.
	Audit(context.Context, SQL, RecoveryFenceRequest, string) error
	Recheck(context.Context, ReadSQL, RecoveryFenceRequest, RecoveryFenceRow, time.Time) error
}

type RecoveryFenceAdmission struct {
	VerifiedRequestHash Hash
	IdentityExpiresAt   Timestamp
	ManagementAllowed   bool
}

type RecoveryFenceRow struct {
	IdentityHash Hash
	Epoch        Counter
	RowVersion   Counter
	Revoked      bool
}

type RecoveryFenceManager struct {
	db          *sql.DB
	scope       Scope
	environment RecoveryFenceEnvironment
	clock       func() time.Time
}

func NewRecoveryFenceManager(db *sql.DB, scope Scope, environment RecoveryFenceEnvironment) (*RecoveryFenceManager, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &RecoveryFenceManager{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

// ChangeFence commits exactly once. On an unknown COMMIT it returns no row;
// callers must use a fresh independently authorized read before acting.
func (s *RecoveryFenceManager) ChangeFence(ctx context.Context, request RecoveryFenceRequest) (RecoveryFenceRow, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return RecoveryFenceRow{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return RecoveryFenceRow{}, ErrInvalid
	}
	hash, err := RecoveryFenceHash(request)
	if err != nil {
		return RecoveryFenceRow{}, err
	}
	request = detached(request)
	session, err := s.environment.PrepareRecoveryFence(ctx, detached(request))
	if err != nil {
		return RecoveryFenceRow{}, err
	}
	if nilEnvironment(session) {
		return RecoveryFenceRow{}, ErrGuardRequired
	}
	p := &recoveryFencePolicy{request: request, hash: hash, session: session}
	tx, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return RecoveryFenceRow{}, err
	}
	tx.clock = s.clock
	committed, err := tx.Run(ctx, p.write)
	if !committed.Committed() {
		return RecoveryFenceRow{}, err
	}
	return detached(p.result), err
}

type recoveryFencePolicy struct {
	request  RecoveryFenceRequest
	hash     Hash
	session  RecoveryFenceSession
	current  RecoveryFenceRow
	result   RecoveryFenceRow
	oldRow   RecoveryFenceRow
	newRow   RecoveryFenceRow
	scopeKey []byte
	oldKey   []byte
	newKey   []byte
	deadline time.Time
}

const recoveryFenceSelect = `SELECT revocation_epoch,revoked_at,row_version FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=? FOR UPDATE`
const recoveryFenceRecheck = `SELECT revocation_epoch,revoked_at,row_version FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=?`
const recoveryFenceInsert = `INSERT INTO system_backup_v2_producer_recovery_revocations (scope_key,workload_identity_hash,revocation_epoch,revoked_at,row_version,updated_at) VALUES (?,?,?,NULL,?,UTC_TIMESTAMP(6))`
const recoveryFenceUpdate = `UPDATE system_backup_v2_producer_recovery_revocations SET revocation_epoch=?,revoked_at=?,row_version=?,updated_at=UTC_TIMESTAMP(6) WHERE scope_key=? AND workload_identity_hash=? AND revocation_epoch=? AND row_version=? AND ((revoked_at IS NULL AND ?=0) OR (revoked_at IS NOT NULL AND ?=1))`

func readRecoveryFence(ctx context.Context, tx SQL, scopeKey, identityKey []byte, identity Hash) (RecoveryFenceRow, bool, error) {
	var epoch, version int64
	var revoked sql.NullTime
	err := tx.QueryRowContext(ctx, recoveryFenceSelect, scopeKey, identityKey).Scan(&epoch, &revoked, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryFenceRow{}, false, nil
	}
	if err != nil {
		return RecoveryFenceRow{}, false, ErrUnavailable
	}
	if epoch < 1 || version < 1 {
		return RecoveryFenceRow{}, false, ErrGuardRequired
	}
	return RecoveryFenceRow{IdentityHash: identity, Epoch: Counter(strconv.FormatInt(epoch, 10)), RowVersion: Counter(strconv.FormatInt(version, 10)), Revoked: revoked.Valid}, true, nil
}

func (p *recoveryFencePolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := p.session.LockInstallation(ctx, tx, detached(p.request)); err != nil {
		return GuardPlan{}, err
	}
	var err error
	p.scopeKey, err = recoveryScopeKey(scope)
	if err != nil {
		return GuardPlan{}, err
	}
	p.oldKey, err = hex.DecodeString(string(p.request.IdentityHash))
	if err != nil || len(p.oldKey) != 32 {
		return GuardPlan{}, ErrInvalid
	}
	var found bool
	p.current, found, err = readRecoveryFence(ctx, tx, p.scopeKey, p.oldKey, p.request.IdentityHash)
	if err != nil {
		return GuardPlan{}, err
	}
	if p.request.Operation == "register" {
		if found {
			return GuardPlan{}, ErrConflict
		}
	} else if !found || string(p.current.Epoch) != string(p.request.ExpectedEpoch) || string(p.current.RowVersion) != string(p.request.ExpectedRowVersion) || p.current.Revoked {
		return GuardPlan{}, ErrConflict
	}
	if p.request.Operation == "rotate" && p.request.NextIdentityHash != nil && *p.request.NextIdentityHash != p.request.IdentityHash {
		p.newKey, err = hex.DecodeString(string(*p.request.NextIdentityHash))
		if err != nil || len(p.newKey) != 32 {
			return GuardPlan{}, ErrInvalid
		}
		if _, exists, err := readRecoveryFence(ctx, tx, p.scopeKey, p.newKey, *p.request.NextIdentityHash); err != nil {
			return GuardPlan{}, err
		} else if exists {
			return GuardPlan{}, ErrConflict // no identity hash or epoch reuse
		}
	}
	admission, err := p.session.Authorize(ctx, tx, detached(p.request), detached(p.current))
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.ManagementAllowed || admission.VerifiedRequestHash != p.hash {
		return GuardPlan{}, ErrGuardRequired
	}
	p.deadline, err = admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{p.deadline}}, nil
}

func (p *recoveryFencePolicy) write(ctx context.Context, tx *Transaction) error {
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	if p.request.Operation == "register" {
		p.result = RecoveryFenceRow{IdentityHash: p.request.IdentityHash, Epoch: "1", RowVersion: "1"}
		if err := tx.CAS(ctx, recoveryFenceInsert, p.scopeKey, p.oldKey, int64(1), int64(1)); err != nil {
			return err
		}
	} else {
		epoch, err := resultNext(ZeroCounter(p.current.Epoch))
		if err != nil {
			return err
		}
		version, err := resultNext(ZeroCounter(p.current.RowVersion))
		if err != nil {
			return err
		}
		p.result = RecoveryFenceRow{IdentityHash: p.request.IdentityHash, Epoch: epoch, RowVersion: version, Revoked: p.request.Operation == "revoke"}
		var revokedAt any
		if p.result.Revoked || p.newKey != nil {
			var now time.Time
			if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
				return ErrUnavailable
			}
			revokedAt = now
		}
		if p.newKey != nil {
			p.result.IdentityHash = *p.request.NextIdentityHash
			p.result.RowVersion = "1"
			p.oldRow = RecoveryFenceRow{IdentityHash: p.request.IdentityHash, Epoch: epoch, RowVersion: version, Revoked: true}
			p.newRow = p.result
		} else {
			p.oldRow = p.result
		}
		oldEpoch, err := p.current.Epoch.SQLInt64()
		if err != nil {
			return err
		}
		oldVersion, err := p.current.RowVersion.SQLInt64()
		if err != nil {
			return err
		}
		newEpoch, err := epoch.SQLInt64()
		if err != nil {
			return err
		}
		newVersion, err := version.SQLInt64()
		if err != nil {
			return err
		}
		oldRevoked := 0
		if p.current.Revoked {
			oldRevoked = 1
		}
		if err := tx.CAS(ctx, recoveryFenceUpdate, newEpoch, revokedAt, newVersion, p.scopeKey, p.oldKey, oldEpoch, oldVersion, oldRevoked, oldRevoked); err != nil {
			return err
		}
		if p.newKey != nil {
			if err := tx.CAS(ctx, recoveryFenceInsert, p.scopeKey, p.newKey, newEpoch, int64(1)); err != nil {
				return err
			}
		}
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}

func (p *recoveryFencePolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	// Only the rows acquired by LockAndAuthorize may be read here.
	actual := p.result
	key := p.oldKey
	if p.newKey != nil {
		actual = p.oldRow
	}
	if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, key, actual); err != nil {
		return err
	}
	if p.newKey != nil {
		if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, p.newKey, p.newRow); err != nil {
			return err
		}
	}
	if err := p.session.Recheck(ctx, tx, detached(p.request), detached(p.result), now); err != nil {
		return err
	}
	return nil
}

func checkRecoveryFenceRow(ctx context.Context, tx ReadSQL, scopeKey, identityKey []byte, want RecoveryFenceRow) error {
	var epoch, version int64
	var revoked sql.NullTime
	if err := tx.QueryRowContext(ctx, recoveryFenceRecheck, scopeKey, identityKey).Scan(&epoch, &revoked, &version); err != nil {
		return ErrGuardRequired
	}
	wantEpoch, err := want.Epoch.SQLInt64()
	if err != nil {
		return err
	}
	wantVersion, err := want.RowVersion.SQLInt64()
	if err != nil {
		return err
	}
	if epoch != wantEpoch || version != wantVersion || revoked.Valid != want.Revoked {
		return ErrGuardRequired
	}
	return nil
}
