package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"reflect"
	"strconv"
	"time"
)

const recoveryAuthorityDigest = "system-backup-recovery-authority.c1"

// RecoveryAuthorityRequest is a CAS target, never a management credential.
// The manager identity and proposed deployment come only from the session.
type RecoveryAuthorityRequest struct {
	Fence                     RecoveryFenceRequest `json:"fence"`
	ExpectedDeploymentVersion ZeroCounter          `json:"expected_deployment_version"`
	Nonce                     ID                   `json:"nonce"`
	BudgetUntil               Timestamp            `json:"budget_until"`
}

func RecoveryAuthorityHash(r RecoveryAuthorityRequest) (Hash, error) {
	if _, err := RecoveryFenceHash(r.Fence); err != nil || validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	if r.Fence.Operation == "register" && r.ExpectedDeploymentVersion != "0" ||
		r.Fence.Operation != "register" && r.ExpectedDeploymentVersion == "0" {
		return "", ErrInvalid
	}
	if _, err := recoveryZeroSQLInt64(r.ExpectedDeploymentVersion); err != nil {
		return "", ErrInvalid
	}
	if _, err := r.BudgetUntil.Time(); err != nil {
		return "", ErrInvalid
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(recoveryAuthorityDigest, m)
}

// RecoveryDeploymentProposal is an authenticated L1a replacement, supplied
// only by the trusted manager session. These fields do not grant authority by
// themselves; D compares them with the locked L1a/L2 rows and writes both.
type RecoveryDeploymentProposal struct {
	WorkloadIdentityHash Hash      `json:"workload_identity_hash"`
	IssuerIdentityHash   Hash      `json:"issuer_identity_hash"`
	SubjectHash          Hash      `json:"subject_hash"`
	ManagementIssuerHash Hash      `json:"management_issuer_hash"`
	ActorIdentityHash    Hash      `json:"actor_identity_hash"`
	AdmissionHash        Hash      `json:"admission_hash"`
	ClientCASHA256       Hash      `json:"client_ca_sha256"`
	CertificateSHA256    Hash      `json:"certificate_sha256"`
	StatProfileHash      Hash      `json:"stat_profile_hash"`
	Enabled              bool      `json:"enabled"`
	Epoch                Counter   `json:"epoch"`
	AuthorizedUntil      Timestamp `json:"authorized_until"`
	RowVersion           Counter   `json:"row_version"`
}

func (p RecoveryDeploymentProposal) row(scope Scope) (recoveryDeploymentRow, error) {
	if validateTyped(reflect.ValueOf(p)) != nil {
		return recoveryDeploymentRow{}, ErrInvalid
	}
	decode := func(h Hash) ([]byte, error) {
		b, err := hex.DecodeString(string(h))
		if err != nil || len(b) != 32 {
			return nil, ErrInvalid
		}
		return b, nil
	}
	var row recoveryDeploymentRow
	row.installation = string(scope.Installation)
	for _, field := range []struct {
		hash Hash
		out  *[]byte
	}{{p.WorkloadIdentityHash, &row.workload}, {p.IssuerIdentityHash, &row.issuer},
		{p.SubjectHash, &row.subject}, {p.ManagementIssuerHash, &row.managerIssuer},
		{p.ActorIdentityHash, &row.actor}, {p.AdmissionHash, &row.admission},
		{p.ClientCASHA256, &row.clientCA}, {p.CertificateSHA256, &row.certificate},
		{p.StatProfileHash, &row.statProfile}} {
		b, err := decode(field.hash)
		if err != nil {
			return recoveryDeploymentRow{}, err
		}
		*field.out = b
	}
	var err error
	if row.epoch, err = p.Epoch.SQLInt64(); err != nil {
		return recoveryDeploymentRow{}, err
	}
	if row.version, err = p.RowVersion.SQLInt64(); err != nil {
		return recoveryDeploymentRow{}, err
	}
	if row.authorizedUntil, err = p.AuthorizedUntil.Time(); err != nil {
		return recoveryDeploymentRow{}, err
	}
	row.enabled = p.Enabled
	if !row.valid(scope) {
		return recoveryDeploymentRow{}, ErrInvalid
	}
	return row, nil
}

func recoveryDeploymentProposal(row recoveryDeploymentRow) RecoveryDeploymentProposal {
	toHash := func(b []byte) Hash { return Hash(hex.EncodeToString(b)) }
	return RecoveryDeploymentProposal{
		WorkloadIdentityHash: toHash(row.workload), IssuerIdentityHash: toHash(row.issuer),
		SubjectHash: toHash(row.subject), ManagementIssuerHash: toHash(row.managerIssuer),
		ActorIdentityHash: toHash(row.actor), AdmissionHash: toHash(row.admission),
		ClientCASHA256: toHash(row.clientCA), CertificateSHA256: toHash(row.certificate),
		StatProfileHash: toHash(row.statProfile), Enabled: row.enabled,
		Epoch:           Counter(strconv.FormatInt(row.epoch, 10)),
		AuthorizedUntil: Timestamp(row.authorizedUntil.UTC().Format(timeLayout)),
		RowVersion:      Counter(strconv.FormatInt(row.version, 10)),
	}
}

type RecoveryAuthorityEnvironment interface {
	PrepareRecoveryAuthority(context.Context, RecoveryAuthorityRequest) (RecoveryAuthoritySession, error)
}

// LockManager is L1b. D has already locked L0 and L1a when it is called.
// It must obtain fresh A-authenticated management facts, lock the exact L1b
// row, check write_fence and manage_deployment independently, then bind the
// exact request hash and trusted next deployment. RecheckManager must reread
// only that locked row and current authentication facts during FinalGuard.
type RecoveryAuthoritySession interface {
	LockManager(context.Context, SQL, RecoveryAuthorityRequest, *RecoveryDeploymentProposal) (RecoveryAuthorityAdmission, error)
	Audit(context.Context, SQL, RecoveryAuthorityRequest, string) error
	RecheckManager(context.Context, ReadSQL, RecoveryAuthorityRequest, time.Time) error
}

type RecoveryAuthorityAdmission struct {
	VerifiedRequestHash Hash
	ManagerExpiresAt    Timestamp
	WriteFenceAllowed   bool
	ManageAllowed       bool
	NextDeployment      RecoveryDeploymentProposal
}

type RecoveryAuthorityResult struct {
	WorkloadIdentityHash Hash
	DeploymentEpoch      Counter
	DeploymentVersion    Counter
	Enabled              bool
}

type RecoveryAuthorityManager struct {
	db          *sql.DB
	scope       Scope
	environment RecoveryAuthorityEnvironment
	clock       func() time.Time
}

func NewRecoveryAuthorityManager(db *sql.DB, scope Scope, env RecoveryAuthorityEnvironment) (*RecoveryAuthorityManager, error) {
	if db == nil || nilEnvironment(env) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &RecoveryAuthorityManager{db: db, scope: scope, environment: env, clock: time.Now}, nil
}

// Change updates the current deployment and its exact revocation row(s) in
// one SQL transaction. It returns no authorization or result on uncertain
// commit. A separately authorized read is needed to observe current state.
func (m *RecoveryAuthorityManager) Change(ctx context.Context, request RecoveryAuthorityRequest) (RecoveryAuthorityResult, error) {
	if m == nil || m.db == nil || nilEnvironment(m.environment) || ctx == nil || ctx.Err() != nil {
		return RecoveryAuthorityResult{}, ErrGuardRequired
	}
	if request.Fence.Scope != m.scope {
		return RecoveryAuthorityResult{}, ErrInvalid
	}
	hash, err := RecoveryAuthorityHash(request)
	if err != nil {
		return RecoveryAuthorityResult{}, err
	}
	request = detached(request)
	session, err := m.environment.PrepareRecoveryAuthority(ctx, detached(request))
	if err != nil {
		return RecoveryAuthorityResult{}, err
	}
	if nilEnvironment(session) {
		return RecoveryAuthorityResult{}, ErrGuardRequired
	}
	p := &recoveryAuthorityPolicy{request: request, hash: hash, session: session}
	tx, err := NewTransactions(m.db, m.scope, p)
	if err != nil {
		return RecoveryAuthorityResult{}, err
	}
	tx.clock = m.clock
	commit, err := tx.Run(ctx, p.write)
	if !commit.Committed() {
		return RecoveryAuthorityResult{}, err
	}
	return RecoveryAuthorityResult{WorkloadIdentityHash: p.nextProposal.WorkloadIdentityHash,
		DeploymentEpoch: p.nextProposal.Epoch, DeploymentVersion: p.nextProposal.RowVersion,
		Enabled: p.nextProposal.Enabled}, err
}

type recoveryAuthorityPolicy struct {
	request      RecoveryAuthorityRequest
	hash         Hash
	session      RecoveryAuthoritySession
	current      *recoveryDeploymentRow
	next         recoveryDeploymentRow
	nextProposal RecoveryDeploymentProposal
	scopeKey     []byte
	oldKey       []byte
	newKey       []byte
	oldFence     RecoveryFenceRow
	oldResult    RecoveryFenceRow
	newResult    RecoveryFenceRow
}

// lockRecoveryAuthorityParent makes missing L1a/L1b/L2 rows serialize on the
// existing installation row. It never creates an installation implicitly.
func lockRecoveryAuthorityParent(ctx context.Context, tx SQL, scope Scope) error {
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return ErrUnavailable
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return ErrUnavailable
		}
		count++
		if count > 10000 {
			rows.Close()
			return ErrGuardRequired
		}
		found = found || installation == string(scope.Installation)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || !found {
		return ErrGuardRequired
	}
	var installation string
	if tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", string(scope.Installation)).Scan(&installation) != nil || installation != string(scope.Installation) {
		return ErrGuardRequired
	}
	return nil
}

func (p *recoveryAuthorityPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Fence.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := lockRecoveryAuthorityParent(ctx, tx, scope); err != nil {
		return GuardPlan{}, err
	}
	row, found, err := readRecoveryDeployment(ctx, tx, scope, true)
	if err != nil {
		return GuardPlan{}, err
	}
	if found {
		p.current = &row
	}
	if p.request.Fence.Operation == "register" && found || p.request.Fence.Operation != "register" && !found {
		return GuardPlan{}, ErrConflict
	}
	if found {
		version, err := recoveryZeroSQLInt64(p.request.ExpectedDeploymentVersion)
		if err != nil || row.version != version || row.epoch != mustRecoveryEpoch(p.request.Fence.ExpectedEpoch) ||
			hex.EncodeToString(row.workload) != string(p.request.Fence.IdentityHash) {
			return GuardPlan{}, ErrConflict
		}
	}
	var current *RecoveryDeploymentProposal
	if found {
		view := recoveryDeploymentProposal(row)
		current = &view
	}
	admission, err := p.session.LockManager(ctx, tx, detached(p.request), detached(current))
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.WriteFenceAllowed || !admission.ManageAllowed || admission.VerifiedRequestHash != p.hash {
		return GuardPlan{}, ErrGuardRequired
	}
	managerUntil, err := admission.ManagerExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	p.nextProposal = detached(admission.NextDeployment)
	p.next, err = p.nextProposal.row(scope)
	if err != nil {
		return GuardPlan{}, err
	}
	p.scopeKey, err = recoveryScopeKey(scope)
	if err != nil {
		return GuardPlan{}, err
	}
	p.oldKey, err = hex.DecodeString(string(p.request.Fence.IdentityHash))
	if err != nil || len(p.oldKey) != 32 {
		return GuardPlan{}, ErrInvalid
	}
	p.oldFence, found, err = readRecoveryFence(ctx, tx, p.scopeKey, p.oldKey, p.request.Fence.IdentityHash)
	if err != nil {
		return GuardPlan{}, err
	}
	if p.request.Fence.Operation == "register" {
		if found {
			return GuardPlan{}, ErrConflict
		}
	} else if !found || string(p.oldFence.Epoch) != string(p.request.Fence.ExpectedEpoch) ||
		string(p.oldFence.RowVersion) != string(p.request.Fence.ExpectedRowVersion) ||
		p.current.epoch != mustRecoveryEpoch(ZeroCounter(p.oldFence.Epoch)) ||
		p.oldFence.Revoked ||
		p.request.Fence.Operation == "rotate" && !p.current.enabled {
		return GuardPlan{}, ErrConflict
	}
	if p.request.Fence.Operation == "rotate" && p.request.Fence.NextIdentityHash != nil && *p.request.Fence.NextIdentityHash != p.request.Fence.IdentityHash {
		p.newKey, err = hex.DecodeString(string(*p.request.Fence.NextIdentityHash))
		if err != nil || len(p.newKey) != 32 {
			return GuardPlan{}, ErrInvalid
		}
		if _, exists, err := readRecoveryFence(ctx, tx, p.scopeKey, p.newKey, *p.request.Fence.NextIdentityHash); err != nil {
			return GuardPlan{}, err
		} else if exists {
			return GuardPlan{}, ErrConflict
		}
	}
	wantEpoch := int64(1)
	wantVersion := int64(1)
	if p.current != nil {
		if p.current.epoch == 1<<63-1 || p.current.version == 1<<63-1 {
			return GuardPlan{}, ErrInvalid
		}
		wantEpoch, wantVersion = p.current.epoch+1, p.current.version+1
	}
	wantIdentity := p.request.Fence.IdentityHash
	if p.newKey != nil {
		wantIdentity = *p.request.Fence.NextIdentityHash
	}
	if p.next.epoch != wantEpoch || p.next.version != wantVersion ||
		hex.EncodeToString(p.next.workload) != string(wantIdentity) ||
		p.next.enabled != (p.request.Fence.Operation != "revoke") {
		return GuardPlan{}, ErrGuardRequired
	}
	budget, err := p.request.BudgetUntil.Time()
	if err != nil {
		return GuardPlan{}, err
	}
	deadlines := []time.Time{managerUntil, budget}
	if p.request.Fence.Operation != "revoke" {
		deadlines = append(deadlines, p.next.authorizedUntil)
	}
	return GuardPlan{BindingHash: p.hash, Deadlines: deadlines}, nil
}

func recoveryZeroSQLInt64(c ZeroCounter) (int64, error) {
	v, err := c.Uint64()
	if err != nil || v > 1<<63-1 {
		return 0, ErrInvalid
	}
	return int64(v), nil
}

func mustRecoveryEpoch(c ZeroCounter) int64 {
	v, err := recoveryZeroSQLInt64(c)
	if err != nil {
		return -1
	}
	return v
}

func (p *recoveryAuthorityPolicy) write(ctx context.Context, tx *Transaction) error {
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	if err := stageRecoveryDeployment(ctx, tx, p.request.Fence.Scope, p.current, p.next); err != nil {
		return err
	}
	if p.request.Fence.Operation == "register" {
		p.oldResult = RecoveryFenceRow{IdentityHash: p.request.Fence.IdentityHash, Epoch: "1", RowVersion: "1"}
		if err := tx.CAS(ctx, recoveryFenceInsert, p.scopeKey, p.oldKey, int64(1), int64(1)); err != nil {
			return err
		}
	} else {
		epoch := p.next.epoch
		oldVersion, err := p.oldFence.RowVersion.SQLInt64()
		if err != nil || oldVersion == 1<<63-1 {
			return ErrInvalid
		}
		var revokedAt any
		if p.request.Fence.Operation == "revoke" || p.newKey != nil {
			var now time.Time
			if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
				return ErrUnavailable
			}
			revokedAt = now
		}
		p.oldResult = RecoveryFenceRow{IdentityHash: p.request.Fence.IdentityHash,
			Epoch: Counter(strconv.FormatInt(epoch, 10)), RowVersion: Counter(strconv.FormatInt(oldVersion+1, 10)),
			Revoked: revokedAt != nil}
		oldEpoch, _ := p.oldFence.Epoch.SQLInt64()
		wasRevoked := 0
		if p.oldFence.Revoked {
			wasRevoked = 1
		}
		if err := tx.CAS(ctx, recoveryFenceUpdate, epoch, revokedAt, oldVersion+1,
			p.scopeKey, p.oldKey, oldEpoch, oldVersion, wasRevoked, wasRevoked); err != nil {
			return err
		}
		if p.newKey != nil {
			p.newResult = RecoveryFenceRow{IdentityHash: *p.request.Fence.NextIdentityHash,
				Epoch: p.oldResult.Epoch, RowVersion: "1"}
			if err := tx.CAS(ctx, recoveryFenceInsert, p.scopeKey, p.newKey, epoch, int64(1)); err != nil {
				return err
			}
		}
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}

func (p *recoveryAuthorityPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Fence.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	if err := recheckRecoveryDeployment(ctx, tx, scope, p.next); err != nil {
		return err
	}
	if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, p.oldKey, p.oldResult); err != nil {
		return err
	}
	if p.newKey != nil {
		if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, p.newKey, p.newResult); err != nil {
			return err
		}
	}
	return p.session.RecheckManager(ctx, tx, detached(p.request), now)
}
