package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

const domainRevokeDigest = "system-backup-producer-domain-revoke.c1"

// DomainRevokeRequest carries a CAS expectation and a redacted reason digest.
// It is not a management credential or a source of issuer identity.
type DomainRevokeRequest struct {
	Scope              Scope   `json:"scope"`
	ExpectedEpoch      Counter `json:"expected_epoch"`
	ExpectedRowVersion Counter `json:"expected_row_version"`
	ReasonHash         Hash    `json:"reason_hash"`
}

func DomainRevokeHash(r DomainRevokeRequest) (Hash, error) {
	if validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(domainRevokeDigest, m)
}

// DomainRevokeEnvironment supplies independently authenticated management
// authority. Its audit path must have reserved emergency capacity; revocation
// cannot depend on admission capacity for a new producer command or receipt.
type DomainRevokeEnvironment interface {
	PrepareDomainRevoke(context.Context, DomainRevokeRequest) (DomainRevokeSession, error)
}

type DomainRevokeSession interface {
	LockInstallation(context.Context, SQL, DomainRevokeRequest) error
	Authorize(context.Context, SQL, DomainRevokeRequest, DomainRecord) (DomainRevokeAdmission, error)
	Audit(context.Context, SQL, DomainRevokeRequest, string) error
	Recheck(context.Context, ReadSQL, DomainRevokeRequest, DomainRecord, time.Time) error
}

type DomainRevokeAdmission struct {
	VerifiedRequestHash Hash
	IdentityExpiresAt   Timestamp
	ManagementAllowed   bool
}

type DomainRevoker struct {
	db          *sql.DB
	scope       Scope
	environment DomainRevokeEnvironment
	clock       func() time.Time
}

func NewDomainRevoker(db *sql.DB, scope Scope, environment DomainRevokeEnvironment) (*DomainRevoker, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &DomainRevoker{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

// RevokeDomain atomically fences every old grant by advancing the domain epoch.
// It deliberately leaves grant/run/evidence/history rows untouched. A failed or
// uncertain commit returns no domain record; callers must independently read
// current state before deciding whether to submit a new request.
func (s *DomainRevoker) RevokeDomain(ctx context.Context, request DomainRevokeRequest) (DomainRecord, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return DomainRecord{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return DomainRecord{}, ErrInvalid
	}
	hash, err := DomainRevokeHash(request)
	if err != nil {
		return DomainRecord{}, err
	}
	request = detached(request)
	session, err := s.environment.PrepareDomainRevoke(ctx, detached(request))
	if err != nil {
		return DomainRecord{}, err
	}
	if nilEnvironment(session) {
		return DomainRecord{}, ErrGuardRequired
	}
	p := &domainRevokePolicy{request: request, hash: hash, session: session}
	tx, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return DomainRecord{}, err
	}
	tx.clock = s.clock
	committed, err := tx.Run(ctx, p.write)
	if !committed.Committed() {
		return DomainRecord{}, err
	}
	return detached(p.domain), err
}

type domainRevokePolicy struct {
	request DomainRevokeRequest
	hash    Hash
	session DomainRevokeSession
	domain  DomainRecord
	locked  *LockedRecord
}

func (p *domainRevokePolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := p.session.LockInstallation(ctx, tx, detached(p.request)); err != nil {
		return GuardPlan{}, err
	}
	var err error
	p.locked, err = tx.LockRecord(ctx, RecordKey{}, &p.domain)
	if err != nil {
		return GuardPlan{}, err
	}
	if !p.locked.Found() || p.domain.State == "revoked" || p.domain.Epoch != p.request.ExpectedEpoch || p.domain.RowVersion != p.request.ExpectedRowVersion {
		return GuardPlan{}, ErrConflict
	}
	admission, err := p.session.Authorize(ctx, tx, detached(p.request), detached(p.domain))
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.ManagementAllowed || admission.VerifiedRequestHash != p.hash {
		return GuardPlan{}, ErrGuardRequired
	}
	identityUntil, err := admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{identityUntil}}, nil
}

func (p *domainRevokePolicy) write(ctx context.Context, tx *Transaction) error {
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil || !validDBTime(now) {
		return ErrUnavailable
	}
	epoch, err := resultNext(ZeroCounter(p.domain.Epoch))
	if err != nil {
		return err
	}
	version, err := resultNext(ZeroCounter(p.domain.RowVersion))
	if err != nil {
		return err
	}
	p.domain.Epoch = epoch
	p.domain.RowVersion = version
	p.domain.State = "revoked"
	p.domain.UpdatedAt = Timestamp(now.Format(timeLayout))
	if err := tx.ReplaceRecord(ctx, p.locked, &p.domain); err != nil {
		return err
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}

func (p *domainRevokePolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	return p.session.Recheck(ctx, tx, detached(p.request), detached(p.domain), now)
}
