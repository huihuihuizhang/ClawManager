package systembackupsecurity

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// PreparedConfigBootstrapCandidateAttempt is an opaque, one-use deployment
// attempt, not permission or a receipt. Real independent authority preparation
// finishes before Apply is given the database opener. Copies share consumption
// and cancellation; a failure requires a new attempt under the same request key.
type PreparedConfigBootstrapCandidateAttempt struct {
	state *configBootstrapCandidateAttemptState
}

type configBootstrapCandidateAttemptState struct {
	ctx       context.Context
	cancel    context.CancelFunc
	plan      *ConfigBootstrapCandidates
	authority pd.PreparedBootstrapAuthority
	used      atomic.Bool
}

func (PreparedConfigBootstrapCandidateAttempt) String() string {
	return "PreparedConfigBootstrapCandidateAttempt"
}
func (PreparedConfigBootstrapCandidateAttempt) GoString() string {
	return "PreparedConfigBootstrapCandidateAttempt"
}
func (PreparedConfigBootstrapCandidateAttempt) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*PreparedConfigBootstrapCandidateAttempt) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}

// PrepareConfigBootstrapCandidateAttempt uses the original trusted Go assembly,
// never an HTTP candidate list or approval DTO. Errors never invoke a DSN/DB
// opener. An original authority may capture non-authorizing physical failures
// in a closed session: only the later locked L3 branch can permit exact history;
// that session must still deny first use without observations or capacity.
func PrepareConfigBootstrapCandidateAttempt(ctx context.Context, g OfflineBootstrapGrant, raw []byte, selections []pd.BootstrapCandidateSelection, authority BootstrapCandidateAuthority, canonicalSnapshot bool) (*PreparedConfigBootstrapCandidateAttempt, error) {
	if candidateAuthorityNil(ctx) || ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	plan, err := newConfigBootstrapCandidatePlan(nil, g, raw, selections, authority)
	if err != nil {
		return nil, err
	}
	// Hash validation above uses D's normalizer. Match its callback ordering
	// before preparing original sources; do not mutate caller-owned selection data.
	sort.Slice(plan.request.Candidates, func(i, j int) bool {
		return plan.request.Candidates[i].Purpose < plan.request.Candidates[j].Purpose
	})
	attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.config.numbers["operation_deadline_seconds"])*time.Second)
	environment := &configBootstrapCandidateEnvironment{plan: plan, canonical: canonicalSnapshot}
	prepared, err := environment.PrepareBootstrapConsumption(attemptCtx, plan.request)
	if err != nil || attemptCtx.Err() != nil {
		cancel()
		return nil, ErrRegistrationUnavailable
	}
	if prepared.CapacityObservedAt != nil {
		original := *prepared.CapacityObservedAt
		_, offset := original.Zone()
		if original.IsZero() || offset != 0 || original.Year() < 1000 || original.Year() > 9999 || original.Nanosecond()%1000 != 0 {
			cancel()
			return nil, ErrRegistrationUnavailable
		}
		prepared.CapacityObservedAt = &original
	}
	return &PreparedConfigBootstrapCandidateAttempt{&configBootstrapCandidateAttemptState{
		ctx: attemptCtx, cancel: cancel, plan: plan, authority: prepared,
	}}, nil
}

// Close cancels an abandoned attempt, or an in-progress Apply. It cannot reset
// one-use state, refresh observations or cancel the caller's parent context.
func (a *PreparedConfigBootstrapCandidateAttempt) Close() {
	if a != nil && a.state != nil {
		a.state.cancel()
	}
}

// Apply owns the returned database and always closes it. The opener is fixed
// deployment code; it is invoked only after successful original preparation.
// D then creates its own issuer-bound prepared token using the captured session,
// request and context, without repeating preparation or generating a new op ID.
func (a *PreparedConfigBootstrapCandidateAttempt) Apply(openDatabase func() (*sql.DB, error)) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if a == nil || a.state == nil || !a.state.used.CompareAndSwap(false, true) {
		return zero, ErrRegistrationUnavailable
	}
	s := a.state
	defer s.cancel()
	if openDatabase == nil || s.ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	db, err := openDatabase()
	if db != nil {
		defer db.Close()
	}
	if err != nil || db == nil || s.ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	environment := &preparedConfigBootstrapEnvironment{state: s}
	consumer, err := pd.NewBootstrapCandidateConsumer(db, s.plan.request.Scope, environment)
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	prepared, err := consumer.PrepareBootstrapConsumption(s.ctx, s.plan.request)
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	return consumePreparedConfigBootstrap(s.ctx, db, s.plan.grant, consumer, prepared)
}

type preparedConfigBootstrapEnvironment struct {
	state *configBootstrapCandidateAttemptState
	used  atomic.Bool
}

func (e *preparedConfigBootstrapEnvironment) PrepareBootstrapConsumption(ctx context.Context, request pd.BootstrapConsumptionRequest) (pd.PreparedBootstrapAuthority, error) {
	var zero pd.PreparedBootstrapAuthority
	if e == nil || e.state == nil || candidateAuthorityNil(ctx) || !reflect.ValueOf(ctx).Comparable() || ctx != e.state.ctx || ctx.Err() != nil || !e.used.CompareAndSwap(false, true) {
		return zero, pd.ErrGuardRequired
	}
	want, err := pd.BootstrapConsumptionHash(e.state.plan.request)
	got, inputErr := pd.BootstrapConsumptionHash(request)
	if err != nil || inputErr != nil || got != want {
		return zero, pd.ErrConflict
	}
	return e.state.authority, nil
}
