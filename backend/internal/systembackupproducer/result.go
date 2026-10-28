package systembackupproducer

import (
	"context"
	"reflect"
	"sort"
	"strconv"
	"time"
)

type ResultBinding struct {
	Subject      Hash          `json:"subject"`
	GrantVersion Counter       `json:"grant_version"`
	Request      ResultRequest `json:"request"`
}
type ResultEnvironment interface {
	PrepareResult(context.Context, ResultBinding) (PreparedResult, error)
}
type PreparedResult struct {
	Session            ResultSession
	CapacityObservedAt *time.Time
}
type ResultSession interface {
	LockInstallation(context.Context, SQL, ResultBinding) error
	// Independently authenticate current identity and evaluator provenance for the
	// COMPLETE result request, including all slots/status/reasons/original times.
	// Receipt-read permission is independent and does not grant execution rights.
	Authenticate(context.Context, SQL, ResultBinding, DomainRecord) (ResultAdmission, error)
	LockHost(context.Context, SQL, ResultBinding, GrantRecord) error
	// L5: complete evidence reference/hold prefix ranges (including absence),
	// legacy projection keys and config-owned canonical-target mapping. No later
	// callback may acquire earlier-layer locks. Noncanonical targets are candidate.
	LockProjectionReferences(context.Context, SQL, ResultBinding, ResultFacts) (ResultProjection, error)
	Reserve(context.Context, SQL, ResultBinding, uint64) error
	Audit(context.Context, SQL, ResultBinding, string) error
	// L8 A registry/chunks: exact original manifest/content/object/immutable ref,
	// system owner/type, ready, retention/protection and no GC/publication claim.
	LockEvidence(context.Context, SQL, ResultBinding, ResultFacts) (ResultEvidence, error)
	// Configured mode only: atomically apply the COMPLETE admitted slot set and
	// legacy refs to prelocked keys. Candidate mode must not touch live slots.
	ApplyProjections(context.Context, SQL, ResultBinding, ResultFacts) error
	Recheck(context.Context, ReadSQL, ResultBinding, ResultFacts, time.Time) error
}
type ResultAdmission struct {
	BindingHash, IdentityHash, VerifiedRequestHash                Hash
	IdentityExpiresAt, DependencyExpiresAt, ReceiptRetentionUntil Timestamp
	AdditionalCost                                                Counter
	ReadReceipt                                                   bool
}
type ResultProjection struct {
	BindingHash, TargetHash, MappingHash Hash
	Mode                                 string // candidate or configured; never caller-selected
}
type ResultEvidence struct {
	Evidence                           EvidenceBinding
	RowVersion                         Counter
	State                              string
	Failure                            string
	ClaimOwner                         *ID
	ClaimExpiresAt                     *Timestamp
	RetentionExpiresAt, ProtectedUntil Timestamp
}
type ResultFacts struct {
	Domain     DomainRecord
	Admission  ResultAdmission
	Grant      *GrantRecord
	Run        *RunRecord
	History    *HistoricalBindingRecord
	Target     *TargetRecord
	Receipt    *ReceiptRecord
	Projection *ResultProjection
	Evidence   *ResultEvidence
	References []ReferenceRecord
	Replayed   bool
}
type ResultsService struct {
	execution   *Execution
	environment ResultEnvironment
}

func NewResults(execution *Execution, environment ResultEnvironment) (*ResultsService, error) {
	if execution == nil || execution.lifecycle == nil || execution.lifecycle.db == nil || nilEnvironment(execution.environment) || nilEnvironment(environment) {
		return nil, ErrGuardRequired
	}
	return &ResultsService{execution, environment}, nil
}
func ResultBindingHash(b ResultBinding) (Hash, error) {
	if validateTyped(reflect.ValueOf(b)) != nil {
		return "", ErrInvalid
	}
	m, e := recordTree(b)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-result-commit.c1", m)
}

type CommittedResult struct {
	Receipt  ReceiptRecord
	Replayed bool
}

// CommitResult owns one guarded transaction. A receipt replay returns historical
// data only; it cannot mint a handle, claim, lease or refreshed observation.
func (s *ResultsService) CommitResult(ctx context.Context, handle *ExecutionHandle, r ResultRequest) (CommittedResult, error) {
	if s == nil || !s.execution.validHandle(handle) || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return CommittedResult{}, ErrGuardRequired
	}
	if r.Scope != handle.scope || r.GrantID != handle.grant || r.GrantGeneration != handle.generation || r.RunID != handle.run {
		return CommittedResult{}, ErrConflict
	}
	b := ResultBinding{handle.subject, handle.version, r}
	hash, e := ResultBindingHash(b)
	if e != nil {
		return CommittedResult{}, e
	}
	digests, e := ResultHashes(r)
	if e != nil {
		return CommittedResult{}, e
	}
	b = detached(b)
	prepared, e := s.environment.PrepareResult(ctx, detached(b))
	if e != nil {
		return CommittedResult{}, e
	}
	if nilEnvironment(prepared.Session) {
		return CommittedResult{}, ErrGuardRequired
	}
	p := &resultPolicy{binding: b, hash: hash, digests: digests, environment: prepared.Session}
	if prepared.CapacityObservedAt != nil {
		sample := *prepared.CapacityObservedAt
		if !validDBTime(sample) {
			return CommittedResult{}, ErrInvalid
		}
		p.sample = &sample
	}
	tx, e := NewTransactions(s.execution.lifecycle.db, r.Scope, p)
	if e != nil {
		return CommittedResult{}, e
	}
	tx.clock = s.execution.lifecycle.clock
	committed, e := tx.Run(ctx, p.write)
	if !committed.Committed() {
		return CommittedResult{}, e
	}
	return CommittedResult{Receipt: detached(*p.facts.Receipt), Replayed: p.facts.Replayed}, e
}

type resultPolicy struct {
	binding                          ResultBinding
	hash                             Hash
	digests                          ResultDigests
	environment                      ResultSession
	sample                           *time.Time
	facts                            ResultFacts
	receiptLock, runLock, targetLock *LockedRecord
	referenceLocks                   []*LockedRecord
	cost                             uint64
}

func resultNext(c ZeroCounter) (Counter, error) {
	n, e := c.Uint64()
	if e != nil || n == ^uint64(0) {
		return "", ErrInvalid
	}
	v := Counter(strconv.FormatUint(n+1, 10))
	if _, e = v.SQLInt64(); e != nil {
		return "", e
	}
	return v, nil
}
func (p *resultPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	b, env := p.binding, p.environment
	r := b.Request
	if scope != r.Scope {
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
	if validateTyped(reflect.ValueOf(a)) != nil || a.BindingHash != p.hash || a.IdentityHash != b.Subject || a.VerifiedRequestHash != p.digests.Request {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.Admission = detached(a)
	var receipt ReceiptRecord
	p.receiptLock, e = tx.LockRecord(ctx, RecordKey{Hash: p.digests.Key}, &receipt)
	if e != nil {
		return GuardPlan{}, e
	}
	if p.receiptLock.Found() {
		if !a.ReadReceipt || receipt.RequestHash != p.digests.Request || !reflect.DeepEqual(receipt.Request, r) {
			return GuardPlan{}, ErrConflict
		}
		p.facts.Receipt = &receipt
		p.facts.Replayed = true
		identity, _ := a.IdentityExpiresAt.Time()
		retention, _ := receipt.RetentionExpiresAt.Time()
		return GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{identity, retention}}, nil
	}
	g := new(GrantRecord)
	run := new(RunRecord)
	h := new(HistoricalBindingRecord)
	target := new(TargetRecord)
	l, e = tx.LockRecord(ctx, RecordKey{ID: r.GrantID}, g)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.runLock, e = tx.LockRecord(ctx, RecordKey{ID: r.RunID}, run)
	if e != nil {
		return GuardPlan{}, e
	}
	if !p.runLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	l, e = tx.LockRecord(ctx, RecordKey{EvidenceID: r.Evidence.EvidenceID}, h)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	if e = env.LockHost(ctx, tx, detached(b), detached(*g)); e != nil {
		return GuardPlan{}, e
	}
	p.targetLock, e = tx.LockRecord(ctx, RecordKey{Hash: p.digests.Target}, target)
	if e != nil {
		return GuardPlan{}, e
	}
	if !p.targetLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	d := p.facts.Domain
	if g.State != "active" || g.RowVersion != b.GrantVersion || g.Generation != r.GrantGeneration || g.SubjectIdentityHash != b.Subject || g.IssuerIdentityHash != d.IssuerIdentityHash || g.DomainEpoch != d.Epoch || r.DomainEpoch != d.Epoch || !reflect.DeepEqual(g.Admission, d.Admission) || !reflect.DeepEqual(r.Admission, d.Admission) || !reflect.DeepEqual(g.Target, r.Target) || run.State != "published" || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != p.digests.Target || run.TargetGeneration != r.TargetGeneration || run.TargetGeneration != target.Generation || target.CurrentRunID != run.RunID || !reflect.DeepEqual(target.Target, r.Target) || target.ResultVersion != r.ExpectedResultVersion {
		return GuardPlan{}, ErrConflict
	}
	pendingEvidence := r.Evidence
	pendingEvidence.ImmutableVersion = nil
	if run.ObservedAt == nil || run.ObservationExpiresAt == nil || run.EvidenceID != r.Evidence.EvidenceID || run.InputHash != r.InputHash || *run.ObservedAt != r.ObservedAt || *run.ObservationExpiresAt != r.ObservationExpiresAt || h.RunID != run.RunID || h.GrantID != g.GrantID || h.GrantGeneration != g.Generation || h.DomainEpoch != d.Epoch || !reflect.DeepEqual(h.Admission, d.Admission) || h.TargetHash != p.digests.Target || h.InputHash != run.InputHash || h.OwnerWriteExpiresAt != run.OwnerWriteExpiresAt || h.ObservedAt != r.ObservedAt || h.ObservationExpiresAt != r.ObservationExpiresAt || h.Evidence != pendingEvidence {
		return GuardPlan{}, ErrConflict
	}
	if !validObjectVersion(r.Evidence.ImmutableVersion) || a.ReceiptRetentionUntil < h.RetentionExpiresAt || a.ReceiptRetentionUntil < g.AuthorizationExpiresAt || a.ReceiptRetentionUntil < r.ObservationExpiresAt {
		return GuardPlan{}, ErrInvalid
	}
	p.facts.Grant = g
	p.facts.Run = run
	p.facts.History = h
	p.facts.Target = target
	projection, e := env.LockProjectionReferences(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return GuardPlan{}, e
	}
	if validateTyped(reflect.ValueOf(projection)) != nil || projection.BindingHash != p.hash || projection.TargetHash != p.digests.Target || !in(projection.Mode, "candidate", "configured") || r.Admission.Unconfigured != nil && projection.Mode != "candidate" {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.Projection = &projection
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return GuardPlan{}, ErrUnavailable
	}
	stamp := Timestamp(now.Format(timeLayout))
	if r.ObservedAt > stamp || h.CreatedAt > stamp {
		return GuardPlan{}, ErrInvalid
	}
	next, e := resultNext(r.ExpectedResultVersion)
	if e != nil {
		return GuardPlan{}, e
	}
	if _, e = nextCounter(run.RowVersion); e != nil {
		return GuardPlan{}, e
	}
	if _, e = nextCounter(target.RowVersion); e != nil {
		return GuardPlan{}, e
	}
	kind := "producer_result"
	if projection.Mode == "candidate" {
		kind = "bootstrap_candidate"
	}
	refs := []ReferenceRecord{{Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: kind, ReferenceKeyHash: p.digests.Key, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: stamp}, {Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: "producer_receipt", ReferenceKeyHash: p.digests.Key, ProtectedUntil: a.ReceiptRetentionUntil, CreatedAt: stamp}}
	// All keys are locked in reference_kind/key order, including the immutable
	// pending hold. Prefix/legacy ranges were locked by the L5 environment first.
	holdHash, e := pendingReferenceHash(*h)
	if e != nil {
		return GuardPlan{}, e
	}
	hold := ReferenceRecord{Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: holdHash, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}
	keys := append(append([]ReferenceRecord(nil), refs...), hold)
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ReferenceKind != keys[j].ReferenceKind {
			return keys[i].ReferenceKind < keys[j].ReferenceKind
		}
		return keys[i].ReferenceKeyHash < keys[j].ReferenceKeyHash
	})
	for _, ref := range keys {
		var found ReferenceRecord
		lock, e := tx.LockRecord(ctx, RecordKey{EvidenceID: ref.EvidenceID, ReferenceKind: ref.ReferenceKind, Hash: ref.ReferenceKeyHash}, &found)
		if e != nil {
			return GuardPlan{}, e
		}
		if ref.ReferenceKind == "hold" {
			if !lock.Found() || !reflect.DeepEqual(found, hold) {
				return GuardPlan{}, ErrGuardRequired
			}
		} else {
			if lock.Found() {
				return GuardPlan{}, ErrConflict
			}
			p.facts.References = append(p.facts.References, ref)
			p.referenceLocks = append(p.referenceLocks, lock)
		}
	}
	receipt = ReceiptRecord{Scope: scope, ReceiptKeyHash: p.digests.Key, RequestHash: p.digests.Request, Request: detached(r), ResultVersion: next, CommittedAt: stamp, RetentionExpiresAt: a.ReceiptRetentionUntil, ChargedBytes: "1"}
	p.facts.Receipt = &receipt
	records := []any{p.facts.Receipt}
	for i := range p.facts.References {
		records = append(records, &p.facts.References[i])
	}
	extra, _ := a.AdditionalCost.Uint64()
	p.cost, e = commandCost(extra, records)
	if e != nil {
		return GuardPlan{}, e
	}
	receipt.ChargedBytes = Counter(strconv.FormatUint(p.cost, 10))
	if p.sample == nil {
		return GuardPlan{}, ErrGuardRequired
	}
	sample := *p.sample
	plan := GuardPlan{BindingHash: p.hash, CapacityObservedAt: &sample}
	for _, ts := range []Timestamp{d.AdmissionExpiresAt, g.LeaseExpiresAt, g.AuthorizationExpiresAt, a.IdentityExpiresAt, a.DependencyExpiresAt, run.OwnerWriteExpiresAt, r.ObservationExpiresAt, a.ReceiptRetentionUntil} {
		v, e := ts.Time()
		if e != nil {
			return GuardPlan{}, e
		}
		plan.Deadlines = append(plan.Deadlines, v)
	}
	if e = env.Reserve(ctx, tx, detached(b), p.cost); e != nil {
		return GuardPlan{}, e
	}
	return plan, nil
}
func (p *resultPolicy) write(ctx context.Context, tx *Transaction) error {
	if p.facts.Replayed {
		return nil
	}
	b, env := p.binding, p.environment
	r := b.Request
	if e := env.Audit(ctx, tx, detached(b), "intent"); e != nil {
		return e
	}
	evidence, e := env.LockEvidence(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return e
	}
	evidence = detached(evidence)
	if validateTyped(reflect.ValueOf(evidence)) != nil || !reflect.DeepEqual(evidence.Evidence, r.Evidence) || evidence.RowVersion != r.ExpectedEvidenceVersion || evidence.State != "ready" || evidence.Failure != "none" || evidence.ClaimOwner != nil || evidence.ClaimExpiresAt != nil || evidence.RetentionExpiresAt < p.facts.Receipt.RetentionExpiresAt || evidence.ProtectedUntil < p.facts.Receipt.RetentionExpiresAt {
		return ErrGuardRequired
	}
	p.facts.Evidence = &evidence
	if p.facts.Projection.Mode == "configured" {
		if e = env.ApplyProjections(ctx, tx, detached(b), detached(p.facts)); e != nil {
			return e
		}
	}
	target := detached(*p.facts.Target)
	target.ResultVersion = ZeroCounter(p.facts.Receipt.ResultVersion)
	target.RowVersion, e = nextCounter(target.RowVersion)
	if e != nil {
		return e
	}
	if e = tx.ReplaceRecord(ctx, p.targetLock, &target); e != nil {
		return e
	}
	p.facts.Target = &target
	run := detached(*p.facts.Run)
	run.State = "committed"
	run.RowVersion, e = nextCounter(run.RowVersion)
	if e != nil {
		return e
	}
	if e = tx.ReplaceRecord(ctx, p.runLock, &run); e != nil {
		return e
	}
	p.facts.Run = &run
	for i := range p.referenceLocks {
		if e = tx.InsertRecord(ctx, p.referenceLocks[i], &p.facts.References[i]); e != nil {
			return e
		}
	}
	if e = tx.InsertRecord(ctx, p.receiptLock, p.facts.Receipt); e != nil {
		return e
	}
	return env.Audit(ctx, tx, detached(b), "result")
}
func (p *resultPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.binding.Request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	return p.environment.Recheck(ctx, tx, detached(p.binding), detached(p.facts), now)
}
