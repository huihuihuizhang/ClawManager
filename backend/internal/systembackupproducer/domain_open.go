package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

const domainOpenDigest = "system-backup-producer-domain-open.c1"

// DomainOpenRequest is a CAS intent, not a deployment signature. The issuer,
// admission, and expiry are supplied only by a trusted deployment authority.
type DomainOpenRequest struct {
	Scope              Scope       `json:"scope"`
	Operation          string      `json:"operation"` // provision or rotate
	ExpectedEpoch      ZeroCounter `json:"expected_epoch"`
	ExpectedRowVersion ZeroCounter `json:"expected_row_version"`
	DeploymentHash     Hash        `json:"deployment_hash"`
}

func DomainOpenHash(r DomainOpenRequest) (Hash, error) {
	if !in(r.Operation, "provision", "rotate") || validateTyped(reflect.ValueOf(r)) != nil {
		return "", ErrInvalid
	}
	m, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree(domainOpenDigest, m)
}

type DomainOpenEnvironment interface {
	// Pins deployment and capacity inputs before BEGIN; no implicit candidate
	// promotion or installation/config creation is permitted.
	PrepareDomainOpen(context.Context, DomainOpenRequest) (PreparedDomainOpen, error)
}

type PreparedDomainOpen struct {
	Session            DomainOpenSession
	CapacityObservedAt time.Time
}

type DomainOpenSession interface {
	// L0/L1 must check installation/config presence or absence, including orphan
	// config rows, and bind the exact deployment receipt and scope.
	LockInstallation(context.Context, SQL, DomainOpenRequest) error
	// L2 authenticates current issuer, management permission, revocation, and
	// the reviewed deployment receipt. Next admission may not come from caller.
	Authorize(context.Context, SQL, DomainOpenRequest, *DomainRecord) (DomainOpenAdmission, error)
	Reserve(context.Context, SQL, DomainOpenRequest, uint64) error
	Audit(context.Context, SQL, DomainOpenRequest, string) error
	Recheck(context.Context, ReadSQL, DomainOpenRequest, DomainRecord, time.Time) error
}

type DomainOpenAdmission struct {
	VerifiedRequestHash Hash
	IdentityExpiresAt   Timestamp
	IssuerIdentityHash  Hash
	Admission           Admission
	AdmissionExpiresAt  Timestamp
	AdditionalCost      ZeroCounter
	ManagementAllowed   bool
}

type DomainOpener struct {
	db          *sql.DB
	scope       Scope
	environment DomainOpenEnvironment
	clock       func() time.Time
}

func NewDomainOpener(db *sql.DB, scope Scope, environment DomainOpenEnvironment) (*DomainOpener, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &DomainOpener{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

// OpenDomain inserts the first domain or rotates an existing one. The domain
// epoch is never reused. A new deployment receipt and current authority must
// be checked even when rotating a previously revoked domain.
func (s *DomainOpener) OpenDomain(ctx context.Context, request DomainOpenRequest) (DomainRecord, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return DomainRecord{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return DomainRecord{}, ErrInvalid
	}
	hash, err := DomainOpenHash(request)
	if err != nil {
		return DomainRecord{}, err
	}
	request = detached(request)
	prepared, err := s.environment.PrepareDomainOpen(ctx, detached(request))
	if err != nil {
		return DomainRecord{}, err
	}
	if nilEnvironment(prepared.Session) || !validDBTime(prepared.CapacityObservedAt) {
		return DomainRecord{}, ErrGuardRequired
	}
	sample := prepared.CapacityObservedAt
	p := &domainOpenPolicy{request: request, hash: hash, session: prepared.Session, sample: sample}
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

type domainOpenPolicy struct {
	request DomainOpenRequest
	hash    Hash
	session DomainOpenSession
	sample  time.Time
	before  *DomainRecord
	domain  DomainRecord
	locked  *LockedRecord
	cost    uint64
}

func (p *domainOpenPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := p.session.LockInstallation(ctx, tx, detached(p.request)); err != nil {
		return GuardPlan{}, err
	}
	var current DomainRecord
	var err error
	p.locked, err = tx.LockRecord(ctx, RecordKey{}, &current)
	if err != nil {
		return GuardPlan{}, err
	}
	if p.request.Operation == "provision" {
		if p.locked.Found() || p.request.ExpectedEpoch != "0" || p.request.ExpectedRowVersion != "0" {
			return GuardPlan{}, ErrConflict
		}
	} else {
		if !p.locked.Found() || string(p.request.ExpectedEpoch) != string(current.Epoch) || string(p.request.ExpectedRowVersion) != string(current.RowVersion) {
			return GuardPlan{}, ErrConflict
		}
		p.before = &current
	}
	admission, err := p.session.Authorize(ctx, tx, detached(p.request), detached(p.before))
	if err != nil {
		return GuardPlan{}, err
	}
	if validateTyped(reflect.ValueOf(admission)) != nil || !admission.ManagementAllowed || admission.VerifiedRequestHash != p.hash {
		return GuardPlan{}, ErrGuardRequired
	}
	identityUntil, err := admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	admissionUntil, err := admission.AdmissionExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	extra, err := admission.AdditionalCost.Uint64()
	if err != nil {
		return GuardPlan{}, ErrInvalid
	}
	base := uint64(65536)
	if p.request.Operation == "provision" {
		base += 65536 + 16384
	}
	if extra > 1<<63-1-base {
		return GuardPlan{}, ErrInvalid
	}
	p.cost = base + extra
	p.domain = DomainRecord{Scope: scope, IssuerIdentityHash: admission.IssuerIdentityHash, Admission: detached(admission.Admission), AdmissionExpiresAt: admission.AdmissionExpiresAt, State: "open"}
	if p.before != nil {
		p.domain.CreatedAt = p.before.CreatedAt
		epoch, err := resultNext(ZeroCounter(p.before.Epoch))
		if err != nil {
			return GuardPlan{}, err
		}
		version, err := resultNext(ZeroCounter(p.before.RowVersion))
		if err != nil {
			return GuardPlan{}, err
		}
		p.domain.Epoch, p.domain.RowVersion = epoch, version
	} else {
		p.domain.Epoch, p.domain.RowVersion = "1", "1"
	}
	return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{identityUntil, admissionUntil}, CapacityObservedAt: &p.sample}, nil
}

func (p *domainOpenPolicy) write(ctx context.Context, tx *Transaction) error {
	if err := p.session.Reserve(ctx, tx, detached(p.request), p.cost); err != nil {
		return err
	}
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil || !validDBTime(now) {
		return ErrUnavailable
	}
	p.domain.UpdatedAt = Timestamp(now.Format(timeLayout))
	if p.before == nil {
		p.domain.CreatedAt = p.domain.UpdatedAt
		if err := tx.InsertRecord(ctx, p.locked, &p.domain); err != nil {
			return err
		}
	} else if err := tx.ReplaceRecord(ctx, p.locked, &p.domain); err != nil {
		return err
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}

func (p *domainOpenPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	return p.session.Recheck(ctx, tx, detached(p.request), detached(p.domain), now)
}
