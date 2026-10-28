package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"time"
)

const recoveryFenceReadDigest = "system-backup-producer-recovery-fence-read.c1"

// RecoveryFenceReadRequest is an exact lookup target. It is not a credential
// and cannot authorize a mutation, recovery claim, or provider operation.
type RecoveryFenceReadRequest struct {
	Scope        Scope     `json:"scope"`
	IdentityHash Hash      `json:"identity_hash"`
	Nonce        ID        `json:"nonce"`
	BudgetUntil  Timestamp `json:"budget_until"`
}

func RecoveryFenceReadHash(r RecoveryFenceReadRequest) (Hash, error) {
	if validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	if _, err := r.BudgetUntil.Time(); err != nil {
		return "", err
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(recoveryFenceReadDigest, m)
}

type RecoveryFenceReadEnvironment interface {
	PrepareRecoveryFenceRead(context.Context, RecoveryFenceReadRequest) (RecoveryFenceReadSession, error)
}

type RecoveryFenceReadSession interface {
	// L0/L1 must lock and verify current installation/deployment admission.
	LockReadInstallation(context.Context, SQL, RecoveryFenceReadRequest) error
	// L2 independently authenticates current management read permission and
	// binds the exact request digest; a prior ChangeFence session is not reused.
	AuthorizeRead(context.Context, SQL, RecoveryFenceReadRequest, Hash) (RecoveryFenceReadAdmission, error)
	// FinalGuard rechecks only facts already locked above and the exact row.
	RecheckRead(context.Context, ReadSQL, RecoveryFenceReadRequest, RecoveryFenceObservation, time.Time) error
}

type RecoveryFenceReadAdmission struct {
	VerifiedRequestHash Hash
	IdentityExpiresAt   Timestamp
	ReadAllowed         bool
}

// RecoveryFenceObservation describes current state only. It cannot establish
// which request committed after a lost acknowledgement or serve as a bearer.
type RecoveryFenceObservation struct {
	Found bool
	Row   RecoveryFenceRow
}

type RecoveryFenceReader struct {
	db          *sql.DB
	scope       Scope
	environment RecoveryFenceReadEnvironment
	clock       func() time.Time
}

func NewRecoveryFenceReader(db *sql.DB, scope Scope, environment RecoveryFenceReadEnvironment) (*RecoveryFenceReader, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &RecoveryFenceReader{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

func (s *RecoveryFenceReader) ReadRecoveryFence(ctx context.Context, request RecoveryFenceReadRequest) (RecoveryFenceObservation, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return RecoveryFenceObservation{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return RecoveryFenceObservation{}, ErrInvalid
	}
	hash, err := RecoveryFenceReadHash(request)
	if err != nil {
		return RecoveryFenceObservation{}, err
	}
	request = detached(request)
	session, err := s.environment.PrepareRecoveryFenceRead(ctx, detached(request))
	if err != nil {
		return RecoveryFenceObservation{}, err
	}
	if nilEnvironment(session) {
		return RecoveryFenceObservation{}, ErrGuardRequired
	}
	p := &recoveryFenceReadPolicy{request: request, hash: hash, session: session}
	tx, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return RecoveryFenceObservation{}, err
	}
	tx.clock = s.clock
	committed, err := tx.Run(ctx, func(context.Context, *Transaction) error { return nil })
	if !committed.Committed() || err != nil {
		return RecoveryFenceObservation{}, err
	}
	return detached(p.observation), nil
}

type recoveryFenceReadPolicy struct {
	request     RecoveryFenceReadRequest
	hash        Hash
	session     RecoveryFenceReadSession
	observation RecoveryFenceObservation
	scopeKey    []byte
	identityKey []byte
}

func (p *recoveryFenceReadPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := p.session.LockReadInstallation(ctx, tx, detached(p.request)); err != nil {
		return GuardPlan{}, err
	}
	admission, err := p.session.AuthorizeRead(ctx, tx, detached(p.request), p.hash)
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.ReadAllowed || admission.VerifiedRequestHash != p.hash || validateTyped(reflect.ValueOf(admission)) != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	identityUntil, err := admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	budgetUntil, err := p.request.BudgetUntil.Time()
	if err != nil {
		return GuardPlan{}, err
	}
	p.scopeKey, err = recoveryScopeKey(scope)
	if err != nil {
		return GuardPlan{}, err
	}
	p.identityKey, err = hex.DecodeString(string(p.request.IdentityHash))
	if err != nil || len(p.identityKey) != 32 {
		return GuardPlan{}, ErrInvalid
	}
	row, found, err := readRecoveryFence(ctx, tx, p.scopeKey, p.identityKey, p.request.IdentityHash)
	if err != nil {
		return GuardPlan{}, err
	}
	p.observation = RecoveryFenceObservation{Found: found, Row: row}
	return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{identityUntil, budgetUntil}}, nil
}

func (p *recoveryFenceReadPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	if p.observation.Found {
		if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, p.identityKey, p.observation.Row); err != nil {
			return err
		}
	} else {
		var epoch, version int64
		var revoked sql.NullTime
		err := tx.QueryRowContext(ctx, recoveryFenceRecheck, p.scopeKey, p.identityKey).Scan(&epoch, &revoked, &version)
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrGuardRequired
		}
	}
	return p.session.RecheckRead(ctx, tx, detached(p.request), detached(p.observation), now)
}
