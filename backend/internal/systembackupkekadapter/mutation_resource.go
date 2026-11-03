package systembackupkekadapter

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// SQLMutationKEKResource supplies both the real reference:kek resolver slot
// and service.KEK. Resolve actual source admission ONCE outside owner locks;
// the original service later fences/stages/rechecks that SAME opaque object.
type SQLMutationKEKResource struct {
	origin      *SQLMutationKEKResource
	db          *sql.DB
	preparation *SQLMutationKEKPreparation
	mu          sync.Mutex
	pending     map[context.Context]*sqlMutationKEKObservation
}

func NewSQLMutationKEKResource(db *sql.DB, cfg SQLBootstrapKEKConfig) (*SQLMutationKEKResource, error) {
	if db == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	p, err := NewSQLMutationKEKPreparation(cfg)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	resource := &SQLMutationKEKResource{db: db, preparation: p, pending: map[context.Context]*sqlMutationKEKObservation{}}
	resource.origin = resource
	return resource, nil
}

func (*SQLMutationKEKResource) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

func (p *SQLMutationKEKResource) Prepare(ctx context.Context, input sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if p == nil || p.origin != p || p.db == nil || p.preparation == nil || nilSource(ctx) || !reflect.ValueOf(ctx).Comparable() || ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	if old := p.pending[ctx]; old != nil {
		old.mu.Lock()
		old.failed = true
		old.mu.Unlock()
		p.mu.Unlock()
		return nil, sec.ErrRegistrationUnavailable
	}
	if len(p.pending) >= 64 {
		p.mu.Unlock()
		return nil, sec.ErrRegistrationUnavailable
	}
	check := &sqlMutationKEKObservation{owner: p, ctx: ctx, input: input}
	check.origin = check
	p.pending[ctx] = check
	p.mu.Unlock()
	context.AfterFunc(ctx, func() {
		p.mu.Lock()
		if p.pending[ctx] == check {
			delete(p.pending, ctx)
		}
		p.mu.Unlock()
	})
	actual, err := p.preparation.PrepareConfigMutationKEK(ctx, p.db, input)
	check.mu.Lock()
	defer check.mu.Unlock()
	if err != nil || nilSource(actual) || check.failed || ctx.Err() != nil {
		check.failed = true
		return nil, sec.ErrRegistrationUnavailable
	}
	check.actual = actual
	return check, nil
}

func (p *SQLMutationKEKResource) PrepareConfigMutationKEK(ctx context.Context, db *sql.DB, input sec.ConfigMutationResourceInput) (reg.PreparedAdmission, error) {
	if p == nil || p.origin != p || db == nil || db != p.db || nilSource(ctx) || !reflect.ValueOf(ctx).Comparable() || ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	check := p.pending[ctx]
	p.mu.Unlock()
	if check == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	check.mu.Lock()
	defer check.mu.Unlock()
	current, proposed := input.Configs()
	oldCurrent, oldProposed := check.input.Configs()
	if check.origin != check || check.failed || check.started || nilSource(check.actual) || input.Slot() != "reference:kek" || input.InstallationID() != check.input.InstallationID() || current.SHA256() != oldCurrent.SHA256() || proposed.SHA256() != oldProposed.SHA256() || !reflect.DeepEqual(input.Actor(), check.input.Actor()) {
		check.failed = true
		return nil, sec.ErrRegistrationUnavailable
	}
	check.started = true
	return check.actual, nil
}

type sqlMutationKEKObservation struct {
	mu      sync.Mutex
	origin  *sqlMutationKEKObservation
	owner   *SQLMutationKEKResource
	ctx     context.Context
	input   sec.ConfigMutationResourceInput
	actual  reg.PreparedAdmission
	tx      *sql.Tx
	started bool
	failed  bool
}

func (*sqlMutationKEKObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

func (p *sqlMutationKEKObservation) Risk() sec.ConfigMutationRisk {
	if p == nil || p.origin != p || nilSource(p.actual) {
		return sec.ConfigMutationRisk{SecurityBoundary: true, ProtectionReduction: true}
	}
	risk := p.actual.Risk()
	return sec.ConfigMutationRisk{SecurityBoundary: risk.SecurityBoundary, ProtectionReduction: risk.ProtectionReduction}
}

func (p *sqlMutationKEKObservation) ValidUntil() time.Time {
	if p == nil || p.origin != p || nilSource(p.actual) {
		return time.Time{}
	}
	return p.actual.ValidUntil()
}

func (p *sqlMutationKEKObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return sec.ErrRegistrationUnavailable
	}
	if p.origin != p {
		if p.origin != nil {
			p.origin.mu.Lock()
			p.origin.failed = true
			p.origin.mu.Unlock()
		}
		return sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || !p.started || nilSource(p.actual) || nilSource(ctx) || !reflect.ValueOf(ctx).Comparable() || ctx != p.ctx || ctx.Err() != nil || tx == nil || p.tx != nil && p.tx != tx || now.IsZero() || now.Before(p.actual.ExpectedSnapshot().ObservedAt) || now.Before(p.actual.Observation().NotBefore) || !now.Before(p.actual.ValidUntil()) {
		p.failed = true
		return sec.ErrRegistrationUnavailable
	}
	p.tx = tx
	// Do NOT acquire the original mapping/evidence or KEK fence early here.
	// The actual service.KEK object above is mandatory before this can pass;
	// D must then lock its evidence union, fence, CompleteScan/StageAdmission
	// and final Recheck using that same transaction and SAME actual admission.
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*SQLMutationKEKResource)(nil)
var _ sec.ConfigMutationKEKPreparation = (*SQLMutationKEKResource)(nil)
