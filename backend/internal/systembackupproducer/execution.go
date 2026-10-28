package systembackupproducer

import (
	"context"
	"encoding/json"
	"reflect"
	"time"
)

// These are internal lookup/binding inputs, never caller authentication proofs.
type CallRequest struct {
	Purpose         string          `json:"purpose"`
	EvidenceID      EvidenceID      `json:"evidence_id"`
	RefIdentityHash Hash            `json:"ref_identity_hash"`
	RefVersion      ProviderVersion `json:"ref_version"`
	PolicyHash      Hash            `json:"policy_hash"`
	BudgetUntil     Timestamp       `json:"budget_until"`
}
type ObservationRequest struct {
	ExpectedRunVersion Counter   `json:"expected_run_version"`
	ObservedAt         Timestamp `json:"observed_at"`
	ExpiresAt          Timestamp `json:"expires_at"`
	AttestationHash    Hash      `json:"attestation_hash"`
}
type ClaimBinding struct {
	EvidenceID      EvidenceID `json:"evidence_id"`
	EvidenceVersion Counter    `json:"evidence_version"`
	ManifestHash    Hash       `json:"manifest_hash"`
	Owner           ID         `json:"owner"`
	ExpiresAt       Timestamp  `json:"expires_at"`
	PolicyHash      Hash       `json:"policy_hash"`
	RefsVersionHash Hash       `json:"refs_version_hash"`
}

// PublicationClaim is minted by Publication only after a confirmed claim CAS
// or independently authorized same-request readback of the committed claim.
// Ordinary ClaimBinding data, pending rows or JSON cannot construct this object.
type PublicationClaim struct {
	issuer  *Execution
	handle  ExecutionHandle
	binding ClaimBinding
}

func (PublicationClaim) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*PublicationClaim) UnmarshalJSON([]byte) error  { return ErrInvalid }

type ExecutionBinding struct {
	Kind              string              `json:"kind"`
	Scope             Scope               `json:"scope"`
	Subject           Hash                `json:"subject"`
	GrantID           ID                  `json:"grant_id"`
	GrantGeneration   Counter             `json:"grant_generation"`
	GrantVersion      Counter             `json:"grant_version"`
	RunID             ID                  `json:"run_id"`
	Call              CallRequest         `json:"call"`
	Claim             *ClaimBinding       `json:"claim"`
	Observation       *ObservationRequest `json:"observation"`
	ProbeSnapshotHash *Hash               `json:"probe_snapshot_hash"`
}

type ExecutionEnvironment interface {
	// Before BEGIN: freeze inputs and, for observation mutation, capacity report.
	// A separate session per invocation avoids cross-call mutable state.
	PrepareExecution(context.Context, ExecutionBinding) (PreparedExecution, error)
}
type PreparedExecution struct {
	Session            ExecutionSession
	CapacityObservedAt *time.Time
}
type ExecutionSession interface {
	LockInstallation(context.Context, SQL, ExecutionBinding) error // L0-L1 prefix
	// L2 live identity/revocation. For binding, independently verify evaluator
	// provenance and that its attestation binds this original probe snapshot,
	// scope/run/input/profile and exact times. Hashing caller fields is not proof.
	Authenticate(context.Context, SQL, ExecutionBinding, DomainRecord) (ExecutionAdmission, error)
	LockHost(context.Context, SQL, ExecutionBinding, GrantRecord) error                               // L4
	LockReferences(context.Context, SQL, ExecutionBinding, ExecutionFacts) (ReferenceApproval, error) // L5
	Reserve(context.Context, SQL, ExecutionBinding, uint64) error                                     // L6, bind only
	Audit(context.Context, SQL, ExecutionBinding, string) error                                       // L7/L9, bind only
	// L8 exact evidence key/current claim or locked absence. Validate the system
	// owner, type and original immutable manifest/refs, not caller projections.
	// Called only for content/wrap/sts/publish. No provider I/O under SQL locks.
	LockEvidence(context.Context, SQL, ExecutionBinding, ExecutionFacts) (CallEvidence, error)
	// Recheck current already-locked authority after all work, before commit.
	Recheck(context.Context, ReadSQL, ExecutionBinding, ExecutionFacts, time.Time) error
}
type ExecutionAdmission struct {
	RequestHash                  Hash
	IdentityHash                 Hash
	IdentityVersionHash          Hash
	IdentityExpiresAt            Timestamp
	AuthenticatedAttestationHash *Hash
	ObservedNotBefore            *Timestamp
	ObservationExpiresNotAfter   *Timestamp
	AdditionalCost               ZeroCounter
}
type ReferenceApproval struct {
	RequestHash         Hash
	PolicyHash          Hash
	VersionHash         Hash
	DependencyExpiresAt Timestamp
}
type CallEvidence struct {
	EvidenceID     EvidenceID
	OwnerType      string
	OwnerID        Installation
	EvidenceType   string
	State          string
	RowVersion     ZeroCounter
	ManifestHash   *Hash
	ClaimOwner     *ID
	ClaimExpiresAt *Timestamp
}
type ExecutionFacts struct {
	Domain     DomainRecord
	Grant      GrantRecord
	Run        RunRecord
	Target     TargetRecord
	Admission  ExecutionAdmission
	References ReferenceApproval
	Evidence   *CallEvidence
}

type Execution struct {
	lifecycle   *Lifecycle
	environment ExecutionEnvironment
}

func NewExecution(lifecycle *Lifecycle, environment ExecutionEnvironment) (*Execution, error) {
	if lifecycle == nil || lifecycle.db == nil || nilEnvironment(lifecycle.environment) || nilEnvironment(environment) {
		return nil, ErrGuardRequired
	}
	return &Execution{lifecycle: lifecycle, environment: environment}, nil
}

// CallSnapshot is immutable, service-local and unforgeable by JSON. Its hash is
// correlation data, not a bearer credential. Always recheck before AND after I/O.
type CallSnapshot struct {
	issuer   *Execution
	handle   ExecutionHandle
	binding  ExecutionBinding
	facts    ExecutionFacts
	captured time.Time
	until    time.Time
	hash     Hash
}

func (CallSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CallSnapshot) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (s *CallSnapshot) Deadline() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.until
}
func (s *CallSnapshot) BindingHash() Hash {
	if s == nil {
		return ""
	}
	return s.hash
}
func (s *CallSnapshot) Purpose() string {
	if s == nil {
		return ""
	}
	return s.binding.Call.Purpose
}

// SnapshotView is detached adapter input, not authority. An A adapter must keep
// the original CallSnapshot and call RecheckCall; accepting a view from a caller
// would discard the service-local identity and current-revocation checks.
type SnapshotView struct {
	Binding                ExecutionBinding
	Facts                  ExecutionFacts
	CapturedAt, ValidUntil Timestamp
	BindingHash            Hash
}

func (s *CallSnapshot) View() SnapshotView {
	if s == nil || s.issuer == nil {
		return SnapshotView{}
	}
	return detached(SnapshotView{Binding: s.binding, Facts: s.facts, CapturedAt: Timestamp(s.captured.Format(timeLayout)), ValidUntil: Timestamp(s.until.Format(timeLayout)), BindingHash: s.hash})
}

func validCall(r CallRequest) bool {
	return in(r.Purpose, "probe", "content_read", "wrap", "sts", "publish") && validateTyped(reflect.ValueOf(r)) == nil
}
func (s *Execution) validHandle(h *ExecutionHandle) bool {
	return s != nil && s.lifecycle != nil && s.lifecycle.db != nil && !nilEnvironment(s.environment) && h != nil && h.issuer == s.lifecycle && h.scope == s.lifecycle.scope && validateTyped(reflect.ValueOf(h.scope)) == nil
}
func bindingFor(h *ExecutionHandle, r CallRequest) ExecutionBinding {
	return ExecutionBinding{Kind: "call", Scope: h.scope, Subject: h.subject, GrantID: h.grant, GrantGeneration: h.generation, GrantVersion: h.version, RunID: h.run, Call: r}
}

// ExecutionBindingHash is deterministic request data for trusted adapters to
// bind their independently verified answers. Computing it conveys no authority.
func ExecutionBindingHash(b ExecutionBinding) (Hash, error) {
	if !in(b.Kind, "call", "bind_observation") || !validCall(b.Call) || validateTyped(reflect.ValueOf(b)) != nil {
		return "", ErrInvalid
	}
	if b.Kind == "call" {
		if b.Observation != nil || b.ProbeSnapshotHash != nil {
			return "", ErrInvalid
		}
	} else {
		if b.Observation == nil || b.ProbeSnapshotHash == nil || b.Claim != nil || b.Call.Purpose != "probe" || b.Observation.ObservedAt >= b.Observation.ExpiresAt {
			return "", ErrInvalid
		}
	}
	if in(b.Call.Purpose, "sts", "publish") != (b.Claim != nil) {
		return "", ErrInvalid
	}
	m, e := recordTree(b)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-execution-request.c1", m)
}

func (s *Execution) BeginCall(ctx context.Context, h *ExecutionHandle, request CallRequest, claim *PublicationClaim) (*CallSnapshot, error) {
	if !s.validHandle(h) || ctx.Err() != nil {
		return nil, ErrGuardRequired
	}
	if !validCall(request) {
		return nil, ErrInvalid
	}
	b := bindingFor(h, request)
	if in(request.Purpose, "sts", "publish") {
		if claim == nil || claim.issuer != s || claim.handle != *h || claim.binding.EvidenceID != request.EvidenceID || claim.binding.PolicyHash != request.PolicyHash {
			return nil, ErrGuardRequired
		}
		cb := claim.binding
		b.Claim = &cb
	} else if claim != nil {
		return nil, ErrGuardRequired
	}
	p, e := s.policy(ctx, b)
	if e != nil {
		return nil, e
	}
	commit, e := s.run(ctx, p)
	if e != nil || !commit.Committed() {
		return nil, e
	}
	snapshot := &CallSnapshot{issuer: s, handle: *h, binding: detached(b), facts: detached(p.facts), captured: commit.LinearizedAt(), until: minimum(p.plan.Deadlines)}
	snapshot.hash, e = snapshotHash(snapshot)
	if e != nil {
		return nil, e
	}
	return snapshot, nil
}

// RecheckCall never issues a replacement snapshot, deadline or policy. Changed
// renewal/authority/ref/claim/evidence state invalidates the original snapshot.
func (s *Execution) RecheckCall(ctx context.Context, snapshot *CallSnapshot) error {
	if snapshot == nil || snapshot.issuer != s || !s.validHandle(&snapshot.handle) || ctx.Err() != nil {
		return ErrGuardRequired
	}
	p, e := s.policy(ctx, snapshot.binding)
	if e != nil {
		return e
	}
	p.prior = snapshot
	_, e = s.run(ctx, p)
	return e
}

type ObservationResult struct {
	RunVersion            Counter
	ObservedAt, ExpiresAt Timestamp
	Replayed              bool
}

// BindObservation requires the original live probe snapshot and an independent
// evaluator attestation. The pair is write-once; exact replay is readback only.
func (s *Execution) BindObservation(ctx context.Context, h *ExecutionHandle, probe *CallSnapshot, r ObservationRequest) (ObservationResult, error) {
	if !s.validHandle(h) || probe == nil || probe.issuer != s || probe.handle != *h || probe.Purpose() != "probe" || ctx.Err() != nil {
		return ObservationResult{}, ErrGuardRequired
	}
	if validateTyped(reflect.ValueOf(r)) != nil || r.ObservedAt >= r.ExpiresAt || r.ExpectedRunVersion != probe.facts.Run.RowVersion {
		return ObservationResult{}, ErrInvalid
	}
	b := bindingFor(h, probe.binding.Call)
	b.Kind = "bind_observation"
	b.Observation = &r
	hash := probe.hash
	b.ProbeSnapshotHash = &hash
	p, e := s.policy(ctx, b)
	if e != nil {
		return ObservationResult{}, e
	}
	p.probe = probe
	commit, e := s.run(ctx, p)
	if !commit.Committed() {
		return ObservationResult{}, e
	}
	return ObservationResult{RunVersion: p.facts.Run.RowVersion, ObservedAt: r.ObservedAt, ExpiresAt: r.ExpiresAt, Replayed: p.replayed}, e
}

func (s *Execution) policy(ctx context.Context, b ExecutionBinding) (*executionPolicy, error) {
	h, e := ExecutionBindingHash(b)
	if e != nil {
		return nil, e
	}
	b = detached(b)
	prepared, e := s.environment.PrepareExecution(ctx, detached(b))
	if e != nil {
		return nil, e
	}
	if nilEnvironment(prepared.Session) {
		return nil, ErrGuardRequired
	}
	var sample *time.Time
	if prepared.CapacityObservedAt != nil {
		v := *prepared.CapacityObservedAt
		if !validDBTime(v) {
			return nil, ErrInvalid
		}
		sample = &v
	}
	return &executionPolicy{binding: b, requestHash: h, environment: prepared.Session, capacityObservedAt: sample}, nil
}
func (s *Execution) run(ctx context.Context, p *executionPolicy) (CommitReceipt, error) {
	r, e := NewTransactions(s.lifecycle.db, s.lifecycle.scope, p)
	if e != nil {
		return CommitReceipt{}, e
	}
	r.clock = s.lifecycle.clock
	return r.Run(ctx, p.write)
}
func minimum(ds []time.Time) time.Time {
	if len(ds) == 0 {
		return time.Time{}
	}
	v := ds[0]
	for _, d := range ds[1:] {
		if d.Before(v) {
			v = d
		}
	}
	return v
}
func snapshotHash(s *CallSnapshot) (Hash, error) {
	raw, e := json.Marshal(struct {
		Binding  ExecutionBinding
		Facts    ExecutionFacts
		Captured Timestamp
		Until    Timestamp
	}{s.binding, s.facts, Timestamp(s.captured.Format(timeLayout)), Timestamp(s.until.Format(timeLayout))})
	if e != nil {
		return "", ErrInvalid
	}
	v, e := parseJSON(raw)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-call-snapshot.c1", v)
}
