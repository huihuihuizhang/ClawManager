package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var bootstrapPurposePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var bootstrapOperationPattern = regexp.MustCompile(`^sop_[A-Za-z0-9._:-]{1,124}$`)
var bootstrapKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

type PreparedBootstrapConsumption struct{ state *bootstrapConsumptionState }
type bootstrapConsumptionState struct {
	issuer    *BootstrapCandidateConsumer
	ctx       context.Context
	request   BootstrapConsumptionRequest
	hash      Hash
	authority PreparedBootstrapAuthority
	used      atomic.Bool
}

func (PreparedBootstrapConsumption) String() string               { return "PreparedBootstrapConsumption" }
func (PreparedBootstrapConsumption) GoString() string             { return "PreparedBootstrapConsumption" }
func (PreparedBootstrapConsumption) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*PreparedBootstrapConsumption) UnmarshalJSON([]byte) error  { return ErrInvalid }

func sameBootstrapContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if !av.Comparable() || !bv.Comparable() || (av.Kind() == reflect.Pointer && av.IsNil()) || (bv.Kind() == reflect.Pointer && bv.IsNil()) {
		return false
	}
	return a == b
}

func NewBootstrapCandidateConsumer(db *sql.DB, scope Scope, environment BootstrapConsumptionEnvironment) (*BootstrapCandidateConsumer, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &BootstrapCandidateConsumer{db: db, scope: scope, environment: environment}, nil
}

// BootstrapConsumptionHash is an internal operation identity, not authority.
// Sorting associations preserves their purpose/ref mapping; swapping the
// candidates between two purposes changes the identity even for the same set.
func BootstrapConsumptionHash(request BootstrapConsumptionRequest) (Hash, error) {
	r, err := normalizeBootstrapConsumption(request)
	if err != nil {
		return "", err
	}
	tree, err := recordTree(r)
	if err != nil {
		return "", err
	}
	return hashTree("system-backup-bootstrap-committed-candidate-consumption.c1", tree)
}

func normalizeBootstrapConsumption(r BootstrapConsumptionRequest) (BootstrapConsumptionRequest, error) {
	if validateTyped(reflect.ValueOf(r.Scope)) != nil || !hashPattern.MatchString(string(r.OfflineGrantHash)) || !hashPattern.MatchString(string(r.ConfigHash)) || !hashPattern.MatchString(string(r.RegistrySetHash)) || !hashPattern.MatchString(string(r.RefSetHash)) || len(r.Candidates) == 0 || len(r.Candidates) > 20 || !bootstrapKeyPattern.MatchString(r.IdempotencyKey) || len(r.Endpoint) == 0 || len(r.Endpoint) > 256 || !utf8.ValidString(r.Endpoint) || len(r.Username) == 0 || len(r.Username) > 128 || !utf8.ValidString(r.Username) || !in(r.MatrixKey, "k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node") {
		return BootstrapConsumptionRequest{}, ErrInvalid
	}
	if _, err := r.ActorID.SQLInt64(); err != nil {
		return BootstrapConsumptionRequest{}, ErrInvalid
	}
	r = detached(r)
	for _, c := range r.Candidates {
		if !bootstrapPurposePattern.MatchString(c.Purpose) || validateTyped(reflect.ValueOf(c.ReferenceIdentityHash)) != nil || validateTyped(reflect.ValueOf(c.ReferenceVersion)) != nil || validateTyped(reflect.ValueOf(c.MappingHash)) != nil || validateTyped(reflect.ValueOf(c.ResultVersion)) != nil || c.Request.Scope != r.Scope || c.Request.Admission.Unconfigured == nil || c.Request.Admission.Configured != nil {
			return BootstrapConsumptionRequest{}, ErrInvalid
		}
		if _, err := ResultHashes(c.Request); err != nil {
			return BootstrapConsumptionRequest{}, err
		}
		a := c.Request.Admission.Unconfigured
		if a.CandidateHash != r.ConfigHash || a.RegistrySetHash != r.RegistrySetHash || a.RefSetHash != r.RefSetHash {
			return BootstrapConsumptionRequest{}, ErrConflict
		}
		next, err := resultNext(c.Request.ExpectedResultVersion)
		if err != nil || c.ResultVersion != next {
			return BootstrapConsumptionRequest{}, ErrConflict
		}
	}
	sort.Slice(r.Candidates, func(i, j int) bool { return r.Candidates[i].Purpose < r.Candidates[j].Purpose })
	for i := 1; i < len(r.Candidates); i++ {
		if r.Candidates[i-1].Purpose == r.Candidates[i].Purpose {
			return BootstrapConsumptionRequest{}, ErrConflict
		}
	}
	return r, nil
}

func (s *BootstrapCandidateConsumer) PrepareBootstrapConsumption(ctx context.Context, request BootstrapConsumptionRequest) (*PreparedBootstrapConsumption, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || !sameBootstrapContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrGuardRequired
	}
	r, err := normalizeBootstrapConsumption(request)
	if err != nil || r.Scope != s.scope {
		return nil, ErrInvalid
	}
	hash, err := BootstrapConsumptionHash(r)
	if err != nil {
		return nil, err
	}
	a, err := s.environment.PrepareBootstrapConsumption(ctx, detached(r))
	if err != nil {
		return nil, bootstrapBoundaryError(err)
	}
	if nilEnvironment(a.Session) || !bootstrapOperationPattern.MatchString(a.OperationPublicID) {
		return nil, ErrGuardRequired
	}
	if a.CapacityObservedAt != nil {
		sample := *a.CapacityObservedAt
		if !validDBTime(sample) {
			return nil, ErrInvalid
		}
		a.CapacityObservedAt = &sample
	}
	return &PreparedBootstrapConsumption{&bootstrapConsumptionState{issuer: s, ctx: ctx, request: r, hash: hash, authority: a}}, nil
}

// ConsumeBootstrapInTx consumes even a failed binding attempt. Copies share the
// same one-shot state. No Commit/Rollback or provider operation occurs here.
func (s *BootstrapCandidateConsumer) ConsumeBootstrapInTx(ctx context.Context, tx *sql.Tx, prepared *PreparedBootstrapConsumption) (BootstrapConsumptionResult, error) {
	zero := BootstrapConsumptionResult{}
	if prepared == nil || prepared.state == nil || !prepared.state.used.CompareAndSwap(false, true) {
		return zero, ErrGuardRequired
	}
	v := prepared.state
	if s == nil || v.issuer != s || tx == nil || !sameBootstrapContext(ctx, v.ctx) || ctx.Err() != nil {
		return zero, ErrGuardRequired
	}
	p := &bootstrapConsumptionPolicy{request: detached(v.request), hash: v.hash, authority: v.authority}
	runner, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return zero, err
	}
	if err = runner.GuardInTx(ctx, tx, p.write); err != nil {
		return zero, bootstrapBoundaryError(err)
	}
	return BootstrapConsumptionResult{OperationPublicID: p.operationID(), Replayed: p.facts.Replayed}, nil
}

// Private adapters must not export provider/grant descriptors through errors.
func bootstrapBoundaryError(err error) error {
	switch err {
	case ErrInvalid, ErrUnavailable, ErrExpired, ErrConflict, ErrGuardRequired:
		return err
	default:
		return ErrUnavailable
	}
}

type bootstrapConsumptionPolicy struct {
	request           BootstrapConsumptionRequest
	hash              Hash
	authority         PreparedBootstrapAuthority
	facts             BootstrapConsumptionFacts
	tx                *Transaction
	domainLock        *LockedRecord
	locks             []*LockedRecord
	closed            DomainRecord
	snapshots         []bootstrapSQLSnapshot
	plan              GuardPlan
	callbacksComplete bool
}

func (p *bootstrapConsumptionPolicy) operationID() string {
	if p.facts.Replayed {
		return p.facts.Operation.PublicID
	}
	return p.authority.OperationPublicID
}

func (p *bootstrapConsumptionPolicy) LockAndAuthorize(ctx context.Context, sqltx SQL, scope Scope) (GuardPlan, error) {
	tx, ok := sqltx.(*Transaction)
	if !ok || scope != p.request.Scope {
		return GuardPlan{}, ErrGuardRequired
	}
	p.tx = tx
	env, r := p.authority.Session, p.request
	if err := env.LockInstallation(ctx, tx, detached(r)); err != nil {
		return GuardPlan{}, err
	}
	var err error
	p.domainLock, err = tx.LockRecord(ctx, RecordKey{}, &p.facts.Domain)
	if err != nil {
		return GuardPlan{}, err
	}
	if !p.domainLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.locks = append(p.locks, p.domainLock)
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return GuardPlan{}, err
	}
	p.facts.Admission, err = env.Authorize(ctx, tx, detached(r), detached(p.facts.Domain), now)
	if err != nil {
		return GuardPlan{}, err
	}
	if p.facts.Admission.BindingHash != p.hash {
		return GuardPlan{}, ErrGuardRequired
	}
	identity, err := p.facts.Admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, err
	}
	plan := GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{identity}}
	if err = checkTime(ctx, plan, now); err != nil {
		return GuardPlan{}, err
	}
	p.facts.Operation, err = env.LockOperation(ctx, tx, detached(r), p.hash, p.authority.OperationPublicID)
	if err != nil {
		return GuardPlan{}, err
	}
	op := p.facts.Operation
	if op.Found {
		if op.RequestHash != p.hash {
			return GuardPlan{}, ErrConflict
		}
		if !bootstrapOperationPattern.MatchString(op.PublicID) || op.Status != "succeeded" || op.Version != 1 || op.HTTPStatus != 201 {
			return GuardPlan{}, ErrConflict
		}
		p.facts.Replayed = true
		// No old observation/domain freshness or capacity charge on historical read.
		p.plan = copyPlan(plan)
		return plan, nil
	}
	d := p.facts.Domain
	if d.State != "open" || d.Admission.Unconfigured == nil || d.Admission.Configured != nil {
		return GuardPlan{}, ErrConflict
	}
	if p.authority.CapacityObservedAt == nil {
		return GuardPlan{}, ErrGuardRequired
	}
	sample := *p.authority.CapacityObservedAt
	plan.CapacityObservedAt = &sample
	if err = p.lockCandidates(ctx); err != nil {
		return GuardPlan{}, err
	}
	if err = env.LockHosts(ctx, tx, detached(r), detached(p.facts)); err != nil {
		return GuardPlan{}, err
	}
	if err = p.lockTargets(ctx); err != nil {
		return GuardPlan{}, err
	}
	if err = env.LockReferences(ctx, tx, detached(r), detached(p.facts)); err != nil {
		return GuardPlan{}, err
	}
	if err = p.lockReferences(ctx); err != nil {
		return GuardPlan{}, err
	}
	now, err = tx.SampleTime(ctx)
	if err != nil {
		return GuardPlan{}, err
	}
	// Compress applicable bounds to one minimum rather than violating the shared
	// GuardPlan's bounded deadline list for a batch. Old execution budgets are
	// deliberately excluded; current state/observation identity remains required.
	minimum := identity
	add := func(ts Timestamp) error {
		value, e := ts.Time()
		if e != nil {
			return e
		}
		if value.Before(minimum) {
			minimum = value
		}
		return nil
	}
	for _, ts := range []Timestamp{d.AdmissionExpiresAt, p.facts.Admission.DependencyExpiresAt} {
		if err = add(ts); err != nil {
			return GuardPlan{}, err
		}
	}
	stamp := Timestamp(now.Format(timeLayout))
	for _, f := range p.facts.Candidates {
		if f.Receipt.Request.ObservedAt > stamp || f.History.CreatedAt > stamp || f.Receipt.CommittedAt > stamp {
			return GuardPlan{}, ErrInvalid
		}
		for _, ts := range []Timestamp{f.Receipt.Request.ObservationExpiresAt, f.History.RetentionExpiresAt, f.Receipt.RetentionExpiresAt} {
			if err = add(ts); err != nil {
				return GuardPlan{}, err
			}
		}
		for _, ref := range f.References {
			if err = add(ref.ProtectedUntil); err != nil {
				return GuardPlan{}, err
			}
		}
	}
	plan.Deadlines = []time.Time{minimum}
	if err = checkTime(ctx, plan, now); err != nil {
		return GuardPlan{}, err
	}
	if err = env.Reserve(ctx, tx, detached(r), detached(p.facts)); err != nil {
		return GuardPlan{}, err
	}
	p.plan = copyPlan(plan)
	return plan, nil
}

// bootstrapReadView closes every retained A callback capability before fixed
// readback. Internal final sampling continues through the original Transaction.
type bootstrapReadView struct{ state *bootstrapReadState }

// Even a reflected whole-value copy must share closure and query dispatch.
// Keeping open/mu in the view itself would let a retained copy outlive Work.
type bootstrapReadState struct {
	mu   sync.Mutex
	open bool
	read ReadSQL
	tx   *Transaction
}

// SameBootstrapTransaction compares the original guarded write capability and
// its still-live private final-read view. It exposes no SQL handle, token or
// authority. A capacity/ref adapter can therefore reject a different tx even
// though final readback deliberately uses a narrower interface than Work.
func SameBootstrapTransaction(write BootstrapSQL, read BootstrapReadSQL) bool {
	t, ok := write.(*Transaction)
	if !ok || t.rejectCopy() {
		return false
	}
	switch r := read.(type) {
	case *Transaction:
		if r != t {
			return false
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.open && t.tx != nil && t.clockContext != nil
	case *bootstrapReadView:
		if r == nil || r.state == nil {
			return false
		}
		s := r.state
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.open || s.tx != t {
			return false
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.tx != nil && t.clockContext != nil
	default:
		return false
	}
}

func (v *bootstrapReadView) close() {
	if v == nil || v.state == nil {
		return
	}
	s := v.state
	s.mu.Lock()
	s.open = false
	s.mu.Unlock()
}
func (v *bootstrapReadView) SampleTime(ctx context.Context) (time.Time, error) {
	if v == nil || v.state == nil {
		return time.Time{}, ErrGuardRequired
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return time.Time{}, ErrGuardRequired
	}
	return s.tx.sampleGuardTime(ctx, true)
}
func (v *bootstrapReadView) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if v == nil || v.state == nil {
		return nil, ErrGuardRequired
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return nil, ErrGuardRequired
	}
	return s.read.QueryContext(ctx, q, args...)
}
func (v *bootstrapReadView) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	if v == nil || v.state == nil {
		return nil
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return s.read.QueryRowContext(canceled, q, args...)
	}
	return s.read.QueryRowContext(ctx, q, args...)
}
