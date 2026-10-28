package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"reflect"
	"time"
)

const recoveryAuthorityReadDigest = "system-backup-recovery-authority-read.c1"

// RecoveryAuthorityReadRequest names one current scope. It carries no
// management credential and cannot prove which earlier request committed.
type RecoveryAuthorityReadRequest struct {
	Scope       Scope     `json:"scope"`
	Nonce       ID        `json:"nonce"`
	BudgetUntil Timestamp `json:"budget_until"`
}

func RecoveryAuthorityReadHash(r RecoveryAuthorityReadRequest) (Hash, error) {
	if validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	if _, err := r.BudgetUntil.Time(); err != nil {
		return "", ErrInvalid
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(recoveryAuthorityReadDigest, m)
}

type RecoveryAuthorityReadEnvironment interface {
	PrepareRecoveryAuthorityRead(context.Context, RecoveryAuthorityReadRequest) (RecoveryAuthorityReadSession, error)
}

// LockManagerRead obtains and authorizes L1b after D locks L0/L1a. It must
// bind the exact read hash and independently reauthenticate management read.
type RecoveryAuthorityReadSession interface {
	LockManagerRead(context.Context, SQL, RecoveryAuthorityReadRequest, *RecoveryDeploymentProposal, Hash) (RecoveryAuthorityReadAdmission, error)
	RecheckManagerRead(context.Context, ReadSQL, RecoveryAuthorityReadRequest, time.Time) error
}

type RecoveryAuthorityReadAdmission struct {
	VerifiedRequestHash Hash
	ManagerExpiresAt    Timestamp
	ReadAllowed         bool
}

// RecoveryAuthorityObservation is only a current-state observation. In
// particular, equal values cannot identify which operation produced them.
type RecoveryAuthorityObservation struct {
	DeploymentFound bool
	Deployment      RecoveryDeploymentProposal
	FenceFound      bool
	Fence           RecoveryFenceRow
}

type RecoveryAuthorityReader struct {
	db          *sql.DB
	scope       Scope
	environment RecoveryAuthorityReadEnvironment
	clock       func() time.Time
}

func NewRecoveryAuthorityReader(db *sql.DB, scope Scope, environment RecoveryAuthorityReadEnvironment) (*RecoveryAuthorityReader, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &RecoveryAuthorityReader{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

func (r *RecoveryAuthorityReader) Read(ctx context.Context, request RecoveryAuthorityReadRequest) (RecoveryAuthorityObservation, error) {
	if r == nil || r.db == nil || nilEnvironment(r.environment) || ctx == nil || ctx.Err() != nil {
		return RecoveryAuthorityObservation{}, ErrGuardRequired
	}
	if request.Scope != r.scope {
		return RecoveryAuthorityObservation{}, ErrInvalid
	}
	hash, err := RecoveryAuthorityReadHash(request)
	if err != nil {
		return RecoveryAuthorityObservation{}, err
	}
	request = detached(request)
	session, err := r.environment.PrepareRecoveryAuthorityRead(ctx, detached(request))
	if err != nil {
		return RecoveryAuthorityObservation{}, err
	}
	if nilEnvironment(session) {
		return RecoveryAuthorityObservation{}, ErrGuardRequired
	}
	p := &recoveryAuthorityReadPolicy{request: request, hash: hash, session: session}
	tx, err := NewTransactions(r.db, r.scope, p)
	if err != nil {
		return RecoveryAuthorityObservation{}, err
	}
	tx.clock = r.clock
	receipt, err := tx.Run(ctx, func(context.Context, *Transaction) error { return nil })
	if !receipt.Committed() {
		return RecoveryAuthorityObservation{}, err
	}
	return detached(p.observation), nil
}

type recoveryAuthorityReadPolicy struct {
	request     RecoveryAuthorityReadRequest
	hash        Hash
	session     RecoveryAuthorityReadSession
	observation RecoveryAuthorityObservation
	deployment  *recoveryDeploymentRow
	scopeKey    []byte
	identityKey []byte
}

func (p *recoveryAuthorityReadPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := lockRecoveryAuthorityParent(ctx, tx, scope); err != nil {
		return GuardPlan{}, err
	}
	row, found, err := readRecoveryDeployment(ctx, tx, scope, true)
	if err != nil {
		return GuardPlan{}, err
	}
	var current *RecoveryDeploymentProposal
	if found {
		p.deployment = &row
		view := recoveryDeploymentProposal(row)
		current = &view
	}
	admission, err := p.session.LockManagerRead(ctx, tx, detached(p.request), detached(current), p.hash)
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.ReadAllowed || admission.VerifiedRequestHash != p.hash || validateTyped(reflect.ValueOf(admission)) != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	managerUntil, err := admission.ManagerExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	budgetUntil, err := p.request.BudgetUntil.Time()
	if err != nil {
		return GuardPlan{}, ErrInvalid
	}
	p.observation.DeploymentFound = found
	if found {
		p.observation.Deployment = *current
		p.scopeKey, err = recoveryScopeKey(scope)
		if err != nil {
			return GuardPlan{}, err
		}
		p.identityKey = append([]byte(nil), row.workload...)
		identity := Hash(hex.EncodeToString(row.workload))
		p.observation.Fence, p.observation.FenceFound, err = readRecoveryFence(ctx, tx, p.scopeKey, p.identityKey, identity)
		if err != nil {
			return GuardPlan{}, err
		}
		if !p.observation.FenceFound || p.observation.Fence.Epoch != p.observation.Deployment.Epoch {
			return GuardPlan{}, ErrGuardRequired
		}
	}
	return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{managerUntil, budgetUntil}}, nil
}

func (p *recoveryAuthorityReadPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	if p.deployment != nil {
		if err := recheckRecoveryDeployment(ctx, tx, scope, *p.deployment); err != nil {
			return err
		}
		if err := checkRecoveryFenceRow(ctx, tx, p.scopeKey, p.identityKey, p.observation.Fence); err != nil {
			return err
		}
	} else if _, found, err := readRecoveryDeployment(ctx, tx, scope, false); err != nil || found {
		return ErrGuardRequired
	}
	return p.session.RecheckManagerRead(ctx, tx, detached(p.request), now)
}
