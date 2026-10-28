package systembackupproducer

import (
	"context"
	"reflect"
	"time"
)

// FinishRequest carries data from an independently verified C object result.
// Neither a caller checksum nor a successful PUT response establishes proof.
// Ready requires exact immutable version/checksum/size. An inconclusive result
// may register write_unknown, never ready. Remote work must precede this call.
type FinishRequest struct {
	State            string    `json:"state"`
	ProofHash        Hash      `json:"proof_hash"`
	ObjectHash       Hash      `json:"object_hash"`
	ObjectBytes      Counter   `json:"object_bytes"`
	ImmutableVersion *Text     `json:"immutable_version"`
	ObservedAt       Timestamp `json:"observed_at"`
	BudgetUntil      Timestamp `json:"budget_until"`
}
type FinishBinding struct {
	Scope           Scope         `json:"scope"`
	Subject         Hash          `json:"subject"`
	GrantID         ID            `json:"grant_id"`
	GrantGeneration Counter       `json:"grant_generation"`
	GrantVersion    Counter       `json:"grant_version"`
	RunID           ID            `json:"run_id"`
	Claim           ClaimBinding  `json:"claim"`
	Request         FinishRequest `json:"request"`
}
type FinishEnvironment interface {
	// Before BEGIN, freeze the verified result and the original capacity sample.
	// A separate session is mandatory; no network I/O inside the transaction.
	PrepareFinish(context.Context, FinishBinding) (PreparedFinish, error)
}
type PreparedFinish struct {
	Session            FinishSession
	CapacityObservedAt *time.Time
}
type FinishSession interface {
	LockInstallation(context.Context, SQL, FinishBinding) error
	// Independently verify current principal AND C proof provenance for this full
	// scope/run/claim/store/ref/key/manifest/object/version/state/time tuple. An
	// unavailable provider can authorize only the inconclusive write_unknown path.
	Authenticate(context.Context, SQL, FinishBinding, DomainRecord) (FinishAdmission, error)
	LockHost(context.Context, SQL, FinishBinding, GrantRecord) error
	LockReferences(context.Context, SQL, FinishBinding, FinishFacts) (ReferenceApproval, error)
	Reserve(context.Context, SQL, FinishBinding, uint64) error
	Audit(context.Context, SQL, FinishBinding, string) error
	// L8 independently checks A's complete original manifest/chunks/history and
	// locks exact registry/claim, including current retention/hold/GC conflicts.
	LockEvidence(context.Context, SQL, FinishBinding, FinishFacts) (FinishEvidence, error)
	Recheck(context.Context, ReadSQL, FinishBinding, FinishFacts, time.Time) error
}
type FinishAdmission struct {
	RequestHash, IdentityHash, VerifiedProofHash Hash
	IdentityExpiresAt, ProofExpiresAt            Timestamp
	AdditionalCost                               Counter
}
type FinishEvidence struct {
	ClaimEvidence    ClaimEvidence
	ImmutableVersion *Text
	Failure          string
}
type FinishFacts struct {
	Domain     DomainRecord
	Grant      GrantRecord
	Run        RunRecord
	History    HistoricalBindingRecord
	Target     TargetRecord
	Reference  ReferenceRecord
	Admission  FinishAdmission
	References ReferenceApproval
	Evidence   FinishEvidence
}
type Finalizer struct {
	execution   *Execution
	environment FinishEnvironment
}

func NewFinalizer(execution *Execution, environment FinishEnvironment) (*Finalizer, error) {
	if execution == nil || execution.lifecycle == nil || execution.lifecycle.db == nil || nilEnvironment(execution.environment) || nilEnvironment(environment) {
		return nil, ErrGuardRequired
	}
	return &Finalizer{execution, environment}, nil
}
func validObjectVersion(v *Text) bool {
	if v == nil || *v == "" || *v == "null" || len(*v) > 256 {
		return false
	}
	for _, b := range []byte(*v) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}
func FinishBindingHash(b FinishBinding) (Hash, error) {
	if validateTyped(reflect.ValueOf(b)) != nil || !in(b.Request.State, "ready", "write_unknown") {
		return "", ErrInvalid
	}
	if b.Request.State == "ready" {
		if !validObjectVersion(b.Request.ImmutableVersion) {
			return "", ErrInvalid
		}
	} else if b.Request.ImmutableVersion != nil {
		return "", ErrInvalid
	}
	if _, e := b.Claim.EvidenceVersion.SQLInt64(); e != nil {
		return "", e
	}
	next, e := nextCounter(b.Claim.EvidenceVersion)
	if e != nil {
		return "", e
	}
	if _, e = next.SQLInt64(); e != nil {
		return "", e
	}
	m, e := recordTree(b)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-finish-publication.c1", m)
}

// FinishResult is committed historical metadata. It grants no execution or
// successful evaluator result. CommitResult must independently check ready data.
type FinishResult struct {
	EvidenceID       EvidenceID
	EvidenceVersion  Counter
	State            string
	ImmutableVersion *Text
}

func (s *Finalizer) FinishPublication(ctx context.Context, claim *PublicationClaim, r FinishRequest) (FinishResult, error) {
	if s == nil || s.execution == nil || claim == nil || claim.issuer != s.execution || !s.execution.validHandle(&claim.handle) || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return FinishResult{}, ErrGuardRequired
	}
	h := claim.handle
	b := FinishBinding{h.scope, h.subject, h.grant, h.generation, h.version, h.run, claim.binding, r}
	hash, e := FinishBindingHash(b)
	if e != nil {
		return FinishResult{}, e
	}
	b = detached(b)
	prepared, e := s.environment.PrepareFinish(ctx, detached(b))
	if e != nil {
		return FinishResult{}, e
	}
	if nilEnvironment(prepared.Session) || prepared.CapacityObservedAt == nil {
		return FinishResult{}, ErrGuardRequired
	}
	sample := *prepared.CapacityObservedAt
	if !validDBTime(sample) {
		return FinishResult{}, ErrInvalid
	}
	p := &finishPolicy{binding: b, hash: hash, environment: prepared.Session, sample: sample}
	tx, e := NewTransactions(s.execution.lifecycle.db, h.scope, p)
	if e != nil {
		return FinishResult{}, e
	}
	tx.clock = s.execution.lifecycle.clock
	receipt, e := tx.Run(ctx, p.write)
	if !receipt.Committed() {
		return FinishResult{}, e
	}
	next, _ := nextCounter(b.Claim.EvidenceVersion)
	return detached(FinishResult{EvidenceID: b.Claim.EvidenceID, EvidenceVersion: next, State: b.Request.State, ImmutableVersion: b.Request.ImmutableVersion}), e
}

type finishPolicy struct {
	binding     FinishBinding
	hash        Hash
	environment FinishSession
	sample      time.Time
	facts       FinishFacts
	runLock     *LockedRecord
}

func (p *finishPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
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
	if validateTyped(reflect.ValueOf(a)) != nil || a.RequestHash != p.hash || a.IdentityHash != b.Subject || a.VerifiedProofHash != b.Request.ProofHash {
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
	l, e = tx.LockRecord(ctx, RecordKey{ID: b.RunID}, &p.facts.Run)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.runLock = l
	l, e = tx.LockRecord(ctx, RecordKey{EvidenceID: b.Claim.EvidenceID}, &p.facts.History)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
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
	d, g, run, target, h := p.facts.Domain, p.facts.Grant, p.facts.Run, p.facts.Target, p.facts.History
	if g.State != "active" || g.Generation != b.GrantGeneration || g.RowVersion != b.GrantVersion || g.SubjectIdentityHash != b.Subject || g.IssuerIdentityHash != d.IssuerIdentityHash || g.DomainEpoch != d.Epoch || !reflect.DeepEqual(g.Admission, d.Admission) || run.State != "pending" || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != targetHash || run.TargetGeneration != target.Generation || target.CurrentRunID != run.RunID || !reflect.DeepEqual(target.Target, g.Target) {
		return GuardPlan{}, ErrConflict
	}
	if run.ObservedAt == nil || run.ObservationExpiresAt == nil || run.EvidenceID != b.Claim.EvidenceID || h.RunID != run.RunID || h.GrantID != g.GrantID || h.GrantGeneration != g.Generation || h.DomainEpoch != d.Epoch || !reflect.DeepEqual(h.Admission, g.Admission) || h.TargetHash != targetHash || h.InputHash != run.InputHash || h.OwnerWriteExpiresAt != run.OwnerWriteExpiresAt || h.ObservedAt != *run.ObservedAt || h.ObservationExpiresAt != *run.ObservationExpiresAt || h.Evidence.ManifestHash != b.Claim.ManifestHash || h.Evidence.ObjectHash != b.Request.ObjectHash || h.Evidence.ObjectBytes != b.Request.ObjectBytes {
		return GuardPlan{}, ErrConflict
	}
	refHash, e := pendingReferenceHash(h)
	if e != nil {
		return GuardPlan{}, e
	}
	l, e = tx.LockRecord(ctx, RecordKey{EvidenceID: run.EvidenceID, ReferenceKind: "hold", Hash: refHash}, &p.facts.Reference)
	if e != nil {
		return GuardPlan{}, e
	}
	want := ReferenceRecord{Scope: scope, EvidenceID: run.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: refHash, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}
	if !l.Found() || !reflect.DeepEqual(p.facts.Reference, want) {
		return GuardPlan{}, ErrGuardRequired
	}
	refs, e := env.LockReferences(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return GuardPlan{}, e
	}
	if validateTyped(reflect.ValueOf(refs)) != nil || refs.RequestHash != p.hash || refs.PolicyHash != b.Claim.PolicyHash || refs.VersionHash != b.Claim.RefsVersionHash {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.References = detached(refs)
	plan := GuardPlan{BindingHash: p.hash, CapacityObservedAt: &p.sample}
	for _, stamp := range []Timestamp{d.AdmissionExpiresAt, g.LeaseExpiresAt, g.AuthorizationExpiresAt, a.IdentityExpiresAt, a.ProofExpiresAt, refs.DependencyExpiresAt, b.Request.BudgetUntil, b.Claim.ExpiresAt, run.OwnerWriteExpiresAt, *run.ObservationExpiresAt, h.RetentionExpiresAt} {
		v, e := stamp.Time()
		if e != nil {
			return GuardPlan{}, e
		}
		plan.Deadlines = append(plan.Deadlines, v)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return GuardPlan{}, ErrUnavailable
	}
	observed, _ := b.Request.ObservedAt.Time()
	if observed.After(now) || b.Request.ObservedAt < h.CreatedAt || b.Request.ObservedAt >= a.ProofExpiresAt {
		return GuardPlan{}, ErrExpired
	}
	extra, _ := a.AdditionalCost.Uint64()
	cost, e := commandCost(extra, nil)
	if e != nil {
		return GuardPlan{}, e
	}
	if e = env.Reserve(ctx, tx, detached(b), cost); e != nil {
		return GuardPlan{}, e
	}
	return plan, nil
}

const finishPublicationCAS = `UPDATE system_backup_v2_evidence SET storage_state=?,evidence_failure_code=?,storage_immutable_version=?,claim_owner=NULL,claim_expires_at=NULL,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner=? AND claim_expires_at=? AND storage_immutable_version IS NULL`

func (p *finishPolicy) write(ctx context.Context, tx *Transaction) error {
	b, env := p.binding, p.environment
	if e := env.Audit(ctx, tx, detached(b), "intent"); e != nil {
		return e
	}
	v, e := env.LockEvidence(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return e
	}
	v = detached(v)
	historyHash, e := PendingHistoryHash(p.facts.History)
	if e != nil {
		return e
	}
	if validateTyped(reflect.ValueOf(v)) != nil || v.ClaimEvidence.HistoryHash != historyHash || v.ClaimEvidence.RetentionExpiresAt < p.facts.History.RetentionExpiresAt || v.ClaimEvidence.ProtectedUntil < p.facts.History.RetentionExpiresAt || v.ImmutableVersion != nil {
		return ErrGuardRequired
	}
	row := v.ClaimEvidence.Evidence
	if row.EvidenceID != b.Claim.EvidenceID || row.OwnerType != "system" || row.OwnerID != b.Scope.Installation || row.EvidenceType != "capability_snapshot" || !in(row.State, "pending", "write_unknown") || row.RowVersion != ZeroCounter(b.Claim.EvidenceVersion) || row.ManifestHash == nil || *row.ManifestHash != b.Claim.ManifestHash || row.ClaimOwner == nil || *row.ClaimOwner != b.Claim.Owner || row.ClaimExpiresAt == nil || *row.ClaimExpiresAt != b.Claim.ExpiresAt {
		return ErrConflict
	}
	if row.State == "pending" && v.Failure != "none" || row.State == "write_unknown" && !in(v.Failure, "provider_unavailable", "deadline_exceeded") {
		return ErrInvalid
	}
	failure := "none"
	var versionArg any
	if b.Request.State == "ready" {
		versionArg = string(*b.Request.ImmutableVersion)
	} else {
		failure = "provider_unavailable"
	}
	version, _ := b.Claim.EvidenceVersion.SQLInt64()
	expiry, _ := b.Claim.ExpiresAt.Time()
	if e = tx.CAS(ctx, finishPublicationCAS, b.Request.State, failure, versionArg, string(b.Claim.EvidenceID), version, string(b.Scope.Installation), row.State, string(b.Claim.Owner), expiry); e != nil {
		return e
	}
	next, _ := nextCounter(b.Claim.EvidenceVersion)
	row.State = b.Request.State
	row.RowVersion = ZeroCounter(next)
	row.ClaimOwner = nil
	row.ClaimExpiresAt = nil
	v.ClaimEvidence.Evidence = row
	v.Failure = failure
	v.ImmutableVersion = b.Request.ImmutableVersion
	p.facts.Evidence = detached(v)
	if b.Request.State == "ready" {
		run := detached(p.facts.Run)
		run.State = "published"
		run.RowVersion, e = nextCounter(run.RowVersion)
		if e != nil {
			return e
		}
		if e = tx.ReplaceRecord(ctx, p.runLock, &run); e != nil {
			return e
		}
		p.facts.Run = run
	}
	return env.Audit(ctx, tx, detached(b), "result")
}
func (p *finishPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.binding.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	return p.environment.Recheck(ctx, tx, detached(p.binding), detached(p.facts), now)
}
