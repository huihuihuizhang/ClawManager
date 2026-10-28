package systembackupproducer

import (
	"context"
	"reflect"
	"time"
)

// PendingRequest is data, not proof of A preparation. The trusted environment
// must independently validate the original A manifest/chunks and observation.
type PendingRequest struct {
	History            HistoricalBindingRecord `json:"history"`
	ExpectedRunVersion Counter                 `json:"expected_run_version"`
	PolicyHash         Hash                    `json:"policy_hash"`
	BudgetUntil        Timestamp               `json:"budget_until"`
}
type PendingBinding struct {
	Scope           Scope          `json:"scope"`
	Subject         Hash           `json:"subject"`
	GrantID         ID             `json:"grant_id"`
	GrantGeneration Counter        `json:"grant_generation"`
	GrantVersion    Counter        `json:"grant_version"`
	RunID           ID             `json:"run_id"`
	Request         PendingRequest `json:"request"`
}

// PreparePending runs before BEGIN. It freezes A's successfully prepared exact
// manifest/chunks without re-Wrap, independent policy and the capacity sample.
// No implementation is supplied here: arbitrary request hashes are not proof.
type PendingEnvironment interface {
	PreparePending(context.Context, PendingBinding) (PreparedPending, error)
}
type PreparedPending struct {
	Session            PendingSession
	CapacityObservedAt *time.Time
}
type PendingSession interface {
	LockInstallation(context.Context, SQL, PendingBinding) error
	Authenticate(context.Context, SQL, PendingBinding, DomainRecord) (PendingAdmission, error)
	LockHost(context.Context, SQL, PendingBinding, GrantRecord) error
	// L5: lock all additional legacy/new refs, holds and projections in the
	// complete preplanned order. D's exact pending hold has already been locked.
	LockReferences(context.Context, SQL, PendingBinding, PendingFacts) error
	Reserve(context.Context, SQL, PendingBinding, uint64) error // L6
	Audit(context.Context, SQL, PendingBinding, string) error   // L7/L9
	// L8: lock exact evidence and ordered chunks, including absence ranges.
	// Existing=true requires independent byte-for-byte comparison of original
	// manifest/chunks, owner/type/ref, retention and observation with prepared A
	// data and History. Do not trust fields copied from the request alone.
	LockEvidence(context.Context, SQL, PendingBinding, PendingFacts) (PendingEvidence, error)
	// L8: insert A's registry/chunks and any prelocked legacy refs using THIS
	// transaction. It has no Commit. Never call legacy PersistPending, Wrap or
	// providers here. Any error must roll back every D and A write.
	InsertEvidence(context.Context, SQL, PendingBinding, PendingFacts) error
	// Current reads of already locked authority and resulting D/A rows only.
	Recheck(context.Context, ReadSQL, PendingBinding, PendingFacts, time.Time) error
}
type PendingAdmission struct {
	RequestHash         Hash
	IdentityHash        Hash
	IdentityExpiresAt   Timestamp
	DependencyExpiresAt Timestamp
	PolicyHash          Hash
	// Independently verified A preparation must bind the entire immutable
	// history, including manifest/content/object/ref/retention and original times.
	PreparedHistoryHash Hash
	AdditionalCost      Counter // A registry/chunks/legacy refs/audits, once
	ReadExisting        bool    // independent exact existing-pending read authority
}
type PendingEvidence struct {
	Existing    bool
	EvidenceID  EvidenceID
	HistoryHash Hash
	RowVersion  ZeroCounter
	State       string // absent, pending or write_unknown
}
type PendingFacts struct {
	Domain    DomainRecord
	Grant     GrantRecord
	Run       RunRecord
	Target    TargetRecord
	History   HistoricalBindingRecord
	Reference ReferenceRecord
	Admission PendingAdmission
	Evidence  PendingEvidence
	Replayed  bool
}
type Pending struct {
	execution   *Execution
	environment PendingEnvironment
}

func NewPending(execution *Execution, environment PendingEnvironment) (*Pending, error) {
	if execution == nil || execution.lifecycle == nil || execution.lifecycle.db == nil || nilEnvironment(execution.environment) || nilEnvironment(environment) {
		return nil, ErrGuardRequired
	}
	return &Pending{execution, environment}, nil
}
func PendingHistoryHash(h HistoricalBindingRecord) (Hash, error) {
	if validateTyped(reflect.ValueOf(h)) != nil {
		return "", ErrInvalid
	}
	m, e := recordTree(h)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-pending-history.c1", m)
}
func PendingBindingHash(b PendingBinding) (Hash, error) {
	if validateTyped(reflect.ValueOf(b)) != nil || b.Scope != b.Request.History.Scope || b.GrantID != b.Request.History.GrantID || b.GrantGeneration != b.Request.History.GrantGeneration || b.RunID != b.Request.History.RunID {
		return "", ErrInvalid
	}
	m, e := recordTree(b)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-pending-request.c1", m)
}

// PendingResult is committed historical data only, never a publication claim.
// Commit uncertainty yields zero; known late commit returns data with an error.
type PendingResult struct {
	EvidenceID  EvidenceID
	HistoryHash Hash
	RunVersion  Counter
	Replayed    bool
}

// AdmitPending owns the outer transaction; A writes compose inside it through
// PendingSession. The transaction and its locked prefix cannot escape this call.
// ClaimPublication must be a separate, freshly authenticated committed step.
func (s *Pending) AdmitPending(ctx context.Context, handle *ExecutionHandle, request PendingRequest) (PendingResult, error) {
	if s == nil || !s.execution.validHandle(handle) || nilEnvironment(s.environment) || ctx.Err() != nil {
		return PendingResult{}, ErrGuardRequired
	}
	b := PendingBinding{handle.scope, handle.subject, handle.grant, handle.generation, handle.version, handle.run, request}
	h, e := PendingBindingHash(b)
	if e != nil {
		return PendingResult{}, e
	}
	b = detached(b)
	prepared, e := s.environment.PreparePending(ctx, detached(b))
	if e != nil {
		return PendingResult{}, e
	}
	if nilEnvironment(prepared.Session) {
		return PendingResult{}, ErrGuardRequired
	}
	p := &pendingPolicy{binding: b, requestHash: h, environment: prepared.Session}
	if prepared.CapacityObservedAt != nil {
		sample := *prepared.CapacityObservedAt
		if !validDBTime(sample) {
			return PendingResult{}, ErrInvalid
		}
		p.sample = &sample
	}
	r, e := NewTransactions(s.execution.lifecycle.db, handle.scope, p)
	if e != nil {
		return PendingResult{}, e
	}
	r.clock = s.execution.lifecycle.clock
	commit, e := r.Run(ctx, p.write)
	if !commit.Committed() {
		return PendingResult{}, e
	}
	return PendingResult{b.Request.History.Evidence.EvidenceID, p.historyHash, p.facts.Run.RowVersion, p.facts.Replayed}, e
}

type pendingPolicy struct {
	binding                             PendingBinding
	requestHash, historyHash            Hash
	environment                         PendingSession
	sample                              *time.Time
	facts                               PendingFacts
	runLock, historyLock, referenceLock *LockedRecord
	plan                                GuardPlan
}

func (p *pendingPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	b, env := p.binding, p.environment
	if scope != b.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if e := env.LockInstallation(ctx, tx, detached(b)); e != nil {
		return GuardPlan{}, e
	}
	l, e := tx.LockRecord(ctx, RecordKey{}, &p.facts.Domain)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() || p.facts.Domain.State != "open" {
		return GuardPlan{}, ErrGuardRequired
	}
	a, e := env.Authenticate(ctx, tx, detached(b), detached(p.facts.Domain))
	if e != nil {
		return GuardPlan{}, e
	}
	p.historyHash, e = PendingHistoryHash(b.Request.History)
	if e != nil {
		return GuardPlan{}, e
	}
	if validateTyped(reflect.ValueOf(a)) != nil || a.RequestHash != p.requestHash || a.IdentityHash != b.Subject || a.PolicyHash != b.Request.PolicyHash || a.PreparedHistoryHash != p.historyHash {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.Admission = detached(a)
	l, e = tx.LockRecord(ctx, RecordKey{ID: b.GrantID}, &p.facts.Grant)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.runLock, e = tx.LockRecord(ctx, RecordKey{ID: b.RunID}, &p.facts.Run)
	if e != nil {
		return GuardPlan{}, e
	}
	if !p.runLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.historyLock, e = tx.LockRecord(ctx, RecordKey{EvidenceID: b.Request.History.Evidence.EvidenceID}, &p.facts.History)
	if e != nil {
		return GuardPlan{}, e
	}
	if e = env.LockHost(ctx, tx, detached(b), detached(p.facts.Grant)); e != nil {
		return GuardPlan{}, e
	}
	targetHash, e := targetDigest(p.facts.Grant.Target)
	if e != nil {
		return GuardPlan{}, e
	}
	l, e = tx.LockRecord(ctx, RecordKey{Hash: targetHash}, &p.facts.Target)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	d, g, run, target, h := p.facts.Domain, p.facts.Grant, p.facts.Run, p.facts.Target, b.Request.History
	if g.State != "active" || g.Generation != b.GrantGeneration || g.RowVersion != b.GrantVersion || g.SubjectIdentityHash != b.Subject || g.IssuerIdentityHash != d.IssuerIdentityHash || g.DomainEpoch != d.Epoch || !reflect.DeepEqual(g.Admission, d.Admission) || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != targetHash || run.TargetGeneration != target.Generation || target.CurrentRunID != run.RunID || !reflect.DeepEqual(g.Target, target.Target) || !in(run.State, "acquired", "pending") {
		return GuardPlan{}, ErrConflict
	}
	if run.ObservedAt == nil || run.ObservationExpiresAt == nil || h.Evidence.EvidenceID != run.EvidenceID || h.DomainEpoch != d.Epoch || !reflect.DeepEqual(h.Admission, g.Admission) || h.TargetHash != run.TargetHash || h.InputHash != run.InputHash || h.OwnerWriteExpiresAt != run.OwnerWriteExpiresAt || h.ObservedAt != *run.ObservedAt || h.ObservationExpiresAt != *run.ObservationExpiresAt || h.RetentionExpiresAt < h.ObservationExpiresAt {
		return GuardPlan{}, ErrConflict
	}
	next, e := nextCounter(b.Request.ExpectedRunVersion)
	if e != nil {
		return GuardPlan{}, e
	}
	if p.historyLock.Found() {
		if !a.ReadExisting || !reflect.DeepEqual(p.facts.History, h) || run.State != "pending" || run.RowVersion != next {
			return GuardPlan{}, ErrConflict
		}
		p.facts.Replayed = true
	} else {
		if run.State != "acquired" || run.RowVersion != b.Request.ExpectedRunVersion {
			return GuardPlan{}, ErrConflict
		}
		p.facts.History = detached(h)
	}
	// A single immutable hold links this pending evidence to its original run.
	// It protects through retention, independently of later result projections.
	refHash, e := pendingReferenceHash(h)
	if e != nil {
		return GuardPlan{}, e
	}
	want := ReferenceRecord{Scope: b.Scope, EvidenceID: run.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: refHash, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}
	p.referenceLock, e = tx.LockRecord(ctx, RecordKey{EvidenceID: run.EvidenceID, ReferenceKind: "hold", Hash: refHash}, &p.facts.Reference)
	if e != nil {
		return GuardPlan{}, e
	}
	if p.facts.Replayed {
		if !p.referenceLock.Found() || !reflect.DeepEqual(p.facts.Reference, want) {
			return GuardPlan{}, ErrConflict
		}
	} else {
		if p.referenceLock.Found() {
			return GuardPlan{}, ErrConflict
		}
		p.facts.Reference = want
	}
	if e = env.LockReferences(ctx, tx, detached(b), detached(p.facts)); e != nil {
		return GuardPlan{}, e
	}
	p.plan = GuardPlan{BindingHash: p.requestHash}
	for _, stamp := range []Timestamp{d.AdmissionExpiresAt, g.LeaseExpiresAt, g.AuthorizationExpiresAt, a.IdentityExpiresAt, a.DependencyExpiresAt, b.Request.BudgetUntil, run.OwnerWriteExpiresAt, *run.ObservationExpiresAt} {
		v, e := stamp.Time()
		if e != nil {
			return GuardPlan{}, e
		}
		p.plan.Deadlines = append(p.plan.Deadlines, v)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return GuardPlan{}, ErrUnavailable
	}
	created, _ := h.CreatedAt.Time()
	observed, _ := h.ObservedAt.Time()
	if created.After(now) || created.Before(observed) {
		return GuardPlan{}, ErrInvalid
	}
	if !p.facts.Replayed {
		if p.sample == nil {
			return GuardPlan{}, ErrGuardRequired
		}
		sample := *p.sample
		p.plan.CapacityObservedAt = &sample
		extra, _ := a.AdditionalCost.Uint64()
		cost, e := commandCost(extra, []any{&p.facts.History, &p.facts.Reference})
		if e != nil {
			return GuardPlan{}, e
		}
		if e = env.Reserve(ctx, tx, detached(b), cost); e != nil {
			return GuardPlan{}, e
		}
	}
	return p.plan, nil
}
func pendingReferenceHash(h HistoricalBindingRecord) (Hash, error) {
	m, e := recordTree(struct {
		Scope      Scope
		RunID      ID
		EvidenceID EvidenceID
	}{h.Scope, h.RunID, h.Evidence.EvidenceID})
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-pending-reference.c1", m)
}
func (p *pendingPolicy) write(ctx context.Context, tx *Transaction) error {
	env, b := p.environment, p.binding
	if !p.facts.Replayed {
		if e := env.Audit(ctx, tx, detached(b), "intent"); e != nil {
			return e
		}
	}
	evidence, e := env.LockEvidence(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return e
	}
	if validateTyped(reflect.ValueOf(evidence)) != nil || evidence.EvidenceID != p.facts.Run.EvidenceID || evidence.HistoryHash != p.historyHash {
		return ErrGuardRequired
	}
	p.facts.Evidence = detached(evidence)
	if p.facts.Replayed {
		if !evidence.Existing || !in(evidence.State, "pending", "write_unknown") || evidence.RowVersion == "0" {
			return ErrConflict
		}
		return nil
	}
	if evidence.Existing || evidence.State != "absent" || evidence.RowVersion != "0" {
		return ErrConflict
	}
	if e = env.InsertEvidence(ctx, tx, detached(b), detached(p.facts)); e != nil {
		return e
	}
	if e = tx.InsertRecord(ctx, p.historyLock, &p.facts.History); e != nil {
		return e
	}
	if e = tx.InsertRecord(ctx, p.referenceLock, &p.facts.Reference); e != nil {
		return e
	}
	next, e := nextCounter(p.facts.Run.RowVersion)
	if e != nil {
		return e
	}
	p.facts.Run.RowVersion = next
	p.facts.Run.State = "pending"
	if e = tx.ReplaceRecord(ctx, p.runLock, &p.facts.Run); e != nil {
		return e
	}
	p.facts.Evidence = PendingEvidence{Existing: true, EvidenceID: evidence.EvidenceID, HistoryHash: p.historyHash, RowVersion: "1", State: "pending"}
	return env.Audit(ctx, tx, detached(b), "result")
}
func (p *pendingPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.binding.Scope || plan.BindingHash != p.requestHash {
		return ErrGuardRequired
	}
	return p.environment.Recheck(ctx, tx, detached(p.binding), detached(p.facts), now)
}
