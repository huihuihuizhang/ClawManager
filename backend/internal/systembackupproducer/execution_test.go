package systembackupproducer

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Trusted adapters below are deliberately synthetic. They prove D's binding,
// clocks and rollback boundary, not deployment/evaluator/provider authenticity.
type executionTestEnvironment struct {
	db                                               *fakeDB
	memory                                           *commandMemory
	identityUntil, dependencyUntil, earliest, latest Timestamp
	identityVersion, refVersion, policy              Hash
	fail                                             string
	noReport                                         bool
	installationWait, evidenceWait                   time.Duration
	reserves                                         int
	cost                                             uint64
	evidence                                         *CallEvidence
	altera                                           func(*ExecutionAdmission)
	alterr                                           func(*ReferenceApproval)
	mutateFacts                                      bool
}

func (e *executionTestEnvironment) phase(name string) error {
	e.memory.events = append(e.memory.events, "execution:"+name)
	if e.fail == name {
		return ErrUnavailable
	}
	return nil
}
func (e *executionTestEnvironment) PrepareExecution(context.Context, ExecutionBinding) (PreparedExecution, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedExecution{}, err
	}
	p := PreparedExecution{Session: e}
	if !e.noReport {
		sample := e.db.now
		p.CapacityObservedAt = &sample
	}
	return p, nil
}
func (e *executionTestEnvironment) LockInstallation(context.Context, SQL, ExecutionBinding) error {
	e.db.now = e.db.now.Add(e.installationWait)
	return e.phase("installation")
}
func (e *executionTestEnvironment) Authenticate(_ context.Context, _ SQL, b ExecutionBinding, _ DomainRecord) (ExecutionAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return ExecutionAdmission{}, err
	}
	h, err := ExecutionBindingHash(b)
	if err != nil {
		return ExecutionAdmission{}, err
	}
	a := ExecutionAdmission{RequestHash: h, IdentityHash: b.Subject, IdentityVersionHash: e.identityVersion, IdentityExpiresAt: e.identityUntil, AdditionalCost: "0"}
	if b.Observation != nil {
		hash := b.Observation.AttestationHash
		earliest, latest := e.earliest, e.latest
		a.AuthenticatedAttestationHash = &hash
		a.ObservedNotBefore = &earliest
		a.ObservationExpiresNotAfter = &latest
		a.AdditionalCost = "65536"
	}
	if e.altera != nil {
		e.altera(&a)
	}
	return a, nil
}
func (e *executionTestEnvironment) LockHost(context.Context, SQL, ExecutionBinding, GrantRecord) error {
	return e.phase("host")
}
func (e *executionTestEnvironment) LockReferences(_ context.Context, _ SQL, b ExecutionBinding, _ ExecutionFacts) (ReferenceApproval, error) {
	if err := e.phase("refs"); err != nil {
		return ReferenceApproval{}, err
	}
	h, err := ExecutionBindingHash(b)
	if err != nil {
		return ReferenceApproval{}, err
	}
	r := ReferenceApproval{RequestHash: h, PolicyHash: e.policy, VersionHash: e.refVersion, DependencyExpiresAt: e.dependencyUntil}
	if e.alterr != nil {
		e.alterr(&r)
	}
	return r, nil
}
func (e *executionTestEnvironment) Reserve(_ context.Context, _ SQL, _ ExecutionBinding, cost uint64) error {
	if err := e.phase("reserve"); err != nil {
		return err
	}
	e.reserves++
	e.cost = cost
	return nil
}
func (e *executionTestEnvironment) Audit(_ context.Context, _ SQL, _ ExecutionBinding, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *executionTestEnvironment) LockEvidence(_ context.Context, _ SQL, b ExecutionBinding, _ ExecutionFacts) (CallEvidence, error) {
	e.db.now = e.db.now.Add(e.evidenceWait)
	if err := e.phase("evidence"); err != nil {
		return CallEvidence{}, err
	}
	if e.evidence != nil {
		return detached(*e.evidence), nil
	}
	return CallEvidence{EvidenceID: b.Call.EvidenceID, OwnerType: "system", OwnerID: b.Scope.Installation, EvidenceType: "capability_snapshot", State: "reserved", RowVersion: "0"}, nil
}
func (e *executionTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ ExecutionBinding, f ExecutionFacts, _ time.Time) error {
	if err := e.phase("recheck"); err != nil {
		return err
	}
	if e.mutateFacts {
		f.Run.InputHash = Hash(strings.Repeat("f", 64))
		f.Target.Target.ResultSlots[0] = "mutated"
	}
	return nil
}

func setupExecution(t *testing.T) (*Execution, *ExecutionHandle, *fakeDB, *executionTestEnvironment, *commandMemory) {
	t.Helper()
	life, db, _, m := setupCommands(t)
	acquired := requireAcquire(t, life)
	env := &executionTestEnvironment{db: db, memory: m, identityUntil: Timestamp(db.now.Add(8 * time.Minute).Format(timeLayout)), dependencyUntil: Timestamp(db.now.Add(5 * time.Minute).Format(timeLayout)), earliest: Timestamp(db.now.Format(timeLayout)), latest: Timestamp(db.now.Add(2 * time.Minute).Format(timeLayout)), identityVersion: Hash(strings.Repeat("a", 64)), refVersion: Hash(strings.Repeat("b", 64)), policy: Hash(strings.Repeat("c", 64))}
	execution, err := NewExecution(life, env)
	if err != nil {
		t.Fatal(err)
	}
	m.events = nil
	m.keyEvents = nil
	return execution, acquired.Handle, db, env, m
}
func probeRequest(t *testing.T, db *fakeDB, env *executionTestEnvironment) CallRequest {
	r := commandFixture(t, "acquire")
	return CallRequest{Purpose: "probe", EvidenceID: r.Next.EvidenceID, RefIdentityHash: r.Target.IdentityHash, RefVersion: r.Target.RefVersion, PolicyHash: env.policy, BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
}
func requireProbe(t *testing.T, s *Execution, h *ExecutionHandle, db *fakeDB, env *executionTestEnvironment) *CallSnapshot {
	t.Helper()
	snapshot, err := s.BeginCall(context.Background(), h, probeRequest(t, db, env), nil)
	if err != nil || snapshot == nil {
		t.Fatal("probe", err)
	}
	return snapshot
}
func bindRequest(db *fakeDB, snapshot *CallSnapshot) ObservationRequest {
	return ObservationRequest{ExpectedRunVersion: snapshot.facts.Run.RowVersion, ObservedAt: Timestamp(db.now.Format(timeLayout)), ExpiresAt: Timestamp(db.now.Add(30 * time.Second).Format(timeLayout)), AttestationHash: Hash(strings.Repeat("d", 64))}
}
func requireBound(t *testing.T, s *Execution, h *ExecutionHandle, db *fakeDB, env *executionTestEnvironment) (*CallSnapshot, ObservationRequest) {
	t.Helper()
	probe := requireProbe(t, s, h, db, env)
	db.now = db.now.Add(time.Second)
	r := bindRequest(db, probe)
	result, err := s.BindObservation(context.Background(), h, probe, r)
	if err != nil || result.Replayed || result.RunVersion != "2" {
		t.Fatal("bind", result, err)
	}
	return probe, r
}
func replaceMemory(t *testing.T, m *commandMemory, record any) {
	t.Helper()
	row, err := EncodeStoredRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	m.rows[row.Table][0] = row
}

func TestExecutionProbeReadOnlyAndFixedSnapshot(t *testing.T) {
	s, h, db, env, m := setupExecution(t)
	before := cloneMemory(m.rows)
	env.noReport = true
	env.mutateFacts = true
	r := probeRequest(t, db, env)
	env.dependencyUntil = Timestamp(db.now.Add(25 * time.Second).Format(timeLayout))
	snapshot, err := s.BeginCall(context.Background(), h, r, nil)
	if err != nil || snapshot == nil || snapshot.Purpose() != "probe" || len(snapshot.BindingHash()) != 64 || snapshot.Deadline().Format(timeLayout) != string(env.dependencyUntil) {
		t.Fatal("snapshot bounds", snapshot, err)
	}
	if !reflect.DeepEqual(before, m.rows) || env.reserves != 0 || snapshot.facts.Run.InputHash == Hash(strings.Repeat("f", 64)) {
		t.Fatal("read-only or defensive copy violation")
	}
	want := []string{"execution:prepare", "execution:installation", "lock:system_backup_producer_domains", "execution:authenticate", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "execution:host", "lock:system_backup_producer_targets", "execution:refs", "execution:recheck"}
	if !reflect.DeepEqual(m.events, want) {
		t.Fatal("probe phase order", m.events)
	}
	deadline, digest, captured := snapshot.Deadline(), snapshot.BindingHash(), snapshot.captured
	db.now = db.now.Add(5 * time.Second)
	view := snapshot.View()
	view.Facts.Target.Target.ResultSlots[0] = "caller-change"
	view.Facts.Grant.Host.Service.WorkloadIdentityHash = Hash(strings.Repeat("f", 64))
	view.Binding.Call.PolicyHash = Hash(strings.Repeat("f", 64))
	if err = s.RecheckCall(context.Background(), snapshot); err != nil {
		t.Fatal("recheck", err)
	}
	if snapshot.Deadline() != deadline || snapshot.BindingHash() != digest || snapshot.captured != captured || env.reserves != 0 {
		t.Fatal("recheck refreshed snapshot")
	}
	if _, err = json.Marshal(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatal("serializable snapshot")
	}
	var fake CallSnapshot
	if json.Unmarshal([]byte(`{}`), &fake) == nil {
		t.Fatal("JSON forged snapshot")
	}
	if err = s.RecheckCall(context.Background(), &fake); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("zero snapshot accepted")
	}
}

func TestExecutionBindOnceAndContentBoundaries(t *testing.T) {
	s, h, db, env, m := setupExecution(t)
	probe, request := requireBound(t, s, h, db, env)
	if env.reserves != 1 || env.cost != 131072 {
		t.Fatal("bind reservation", env.cost)
	}
	var run RunRecord
	loadMemoryRecord(t, m, &run, 0)
	if run.State != "acquired" || run.RowVersion != "2" || *run.ObservedAt != request.ObservedAt || *run.ObservationExpiresAt != request.ExpiresAt {
		t.Fatal("stored observation")
	}
	before := cloneMemory(m.rows)
	env.noReport = true
	replay, err := s.BindObservation(context.Background(), h, probe, request)
	if err != nil || !replay.Replayed || env.reserves != 1 || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("bind replay", err)
	}
	changed := request
	changed.ExpiresAt = Timestamp(db.now.Add(31 * time.Second).Format(timeLayout))
	if _, err = s.BindObservation(context.Background(), h, probe, changed); err == nil {
		t.Fatal("observation refreshed")
	}
	if err = s.RecheckCall(context.Background(), probe); err == nil {
		t.Fatal("old probe usable after binding")
	}
	if _, err = s.BeginCall(context.Background(), h, probe.binding.Call, nil); err == nil {
		t.Fatal("new probe after observation")
	}
	for _, purpose := range []string{"content_read", "wrap"} {
		r := probe.binding.Call
		r.Purpose = purpose
		r.RefIdentityHash = Hash(strings.Repeat("e", 64))
		r.RefVersion = "approved-ref-v1"
		snapshot, err := s.BeginCall(context.Background(), h, r, nil)
		if err != nil || snapshot == nil || snapshot.Deadline().Format(timeLayout) != string(request.ExpiresAt) {
			t.Fatal("content fixed expiry", purpose, err)
		}
		if err = s.RecheckCall(context.Background(), snapshot); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, m.rows) {
		t.Fatal("calls changed durable observation")
	}
}

func TestExecutionSnapshotInvalidation(t *testing.T) {
	for _, name := range []string{"renew", "revoke", "takeover", "domain_epoch", "domain_closed", "grant_host", "run_version", "target_version", "identity_version", "identity_deadline", "ref_version", "ref_policy", "dependency_deadline", "expired_budget", "authenticate", "recheck"} {
		t.Run(name, func(t *testing.T) {
			s, h, db, env, m := setupExecution(t)
			snapshot := requireProbe(t, s, h, db, env)
			originalHash, originalUntil := snapshot.BindingHash(), snapshot.Deadline()
			switch name {
			case "renew":
				if _, err := s.lifecycle.Execute(context.Background(), commandFixture(t, "renew"), h); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				if _, err := s.lifecycle.Execute(context.Background(), commandFixture(t, "revoke"), nil); err != nil {
					t.Fatal(err)
				}
			case "takeover":
				c := commandFixture(t, "takeover")
				hash := Hash(strings.Repeat("f", 64))
				c.TerminationDecisionHash = &hash
				s.lifecycle.environment.(*commandTestEnvironment).termination = &hash
				if _, err := s.lifecycle.Execute(context.Background(), c, nil); err != nil {
					t.Fatal(err)
				}
			case "domain_epoch", "domain_closed":
				var r DomainRecord
				loadMemoryRecord(t, m, &r, 0)
				if name == "domain_epoch" {
					r.Epoch = "2"
					r.RowVersion = "2"
				} else {
					r.State = "closed"
				}
				replaceMemory(t, m, &r)
			case "grant_host":
				var r GrantRecord
				loadMemoryRecord(t, m, &r, 0)
				r.Host.Service.WorkloadIdentityHash = Hash(strings.Repeat("f", 64))
				replaceMemory(t, m, &r)
			case "run_version":
				var r RunRecord
				loadMemoryRecord(t, m, &r, 0)
				r.RowVersion = "2"
				replaceMemory(t, m, &r)
			case "target_version":
				var r TargetRecord
				loadMemoryRecord(t, m, &r, 0)
				r.RowVersion = "2"
				replaceMemory(t, m, &r)
			case "identity_version":
				env.identityVersion = Hash(strings.Repeat("f", 64))
			case "identity_deadline":
				env.identityUntil = Timestamp(db.now.Add(9 * time.Minute).Format(timeLayout))
			case "ref_version":
				env.refVersion = Hash(strings.Repeat("f", 64))
			case "ref_policy":
				env.policy = Hash(strings.Repeat("f", 64))
			case "dependency_deadline":
				env.dependencyUntil = Timestamp(db.now.Add(6 * time.Minute).Format(timeLayout))
			case "expired_budget":
				db.now = db.now.Add(time.Minute)
			default:
				env.fail = name
			}
			if err := s.RecheckCall(context.Background(), snapshot); err == nil {
				t.Fatal("stale snapshot accepted")
			}
			if snapshot.BindingHash() != originalHash || snapshot.Deadline() != originalUntil {
				t.Fatal("mutated failed snapshot")
			}
		})
	}
}

func TestExecutionObservationRejectsUnprovenOrExpired(t *testing.T) {
	for _, name := range []string{"attestation_missing", "attestation_mismatch", "future", "before_probe", "expiry_exceeds_admission", "expiry_now", "wrong_run_version", "stale_probe", "renewed_probe", "no_report", "report_wait", "cost_overflow", "reserve", "audit:intent", "audit:result", "recheck", "run_overflow", "commit_unknown", "commit_expired"} {
		t.Run(name, func(t *testing.T) {
			s, h, db, env, m := setupExecution(t)
			if name == "run_overflow" {
				var run RunRecord
				loadMemoryRecord(t, m, &run, 0)
				run.RowVersion = "18446744073709551615"
				replaceMemory(t, m, &run)
			}
			probe := requireProbe(t, s, h, db, env)
			db.now = db.now.Add(time.Second)
			request := bindRequest(db, probe)
			switch name {
			case "attestation_missing":
				env.altera = func(a *ExecutionAdmission) { a.AuthenticatedAttestationHash = nil }
			case "attestation_mismatch":
				env.altera = func(a *ExecutionAdmission) { h := Hash(strings.Repeat("e", 64)); a.AuthenticatedAttestationHash = &h }
			case "future":
				request.ObservedAt = Timestamp(db.now.Add(time.Second).Format(timeLayout))
			case "before_probe":
				request.ObservedAt = Timestamp(probe.captured.Add(-time.Microsecond).Format(timeLayout))
			case "expiry_exceeds_admission":
				request.ExpiresAt = Timestamp(db.now.Add(3 * time.Minute).Format(timeLayout))
			case "expiry_now":
				request.ObservedAt = Timestamp(probe.captured.Format(timeLayout))
				request.ExpiresAt = Timestamp(db.now.Format(timeLayout))
			case "wrong_run_version":
				request.ExpectedRunVersion = "3"
			case "stale_probe":
				db.now = db.now.Add(time.Minute)
				request = bindRequest(db, probe)
			case "renewed_probe":
				renewed, err := s.lifecycle.Execute(context.Background(), commandFixture(t, "renew"), h)
				if err != nil {
					t.Fatal(err)
				}
				h = renewed.Handle
			case "no_report":
				env.noReport = true
			case "report_wait":
				env.installationWait = 6 * time.Second
			case "cost_overflow":
				env.altera = func(a *ExecutionAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "commit_unknown":
				db.commitError = true
			case "commit_expired":
				db.commitWait = 6 * time.Second
			default:
				if name != "run_overflow" {
					env.fail = name
				}
			}
			before := cloneMemory(m.rows)
			result, err := s.BindObservation(context.Background(), h, probe, request)
			if err == nil {
				t.Fatal("unproven/expired observation accepted")
			}
			if name == "commit_unknown" {
				if !errors.Is(err, ErrCommitUnknown) || result.RunVersion != "" {
					t.Fatal("ambiguous observation became success", err)
				}
				return
			}
			if name == "commit_expired" {
				if !errors.Is(err, ErrCommittedExpired) || result.RunVersion != "2" {
					t.Fatal("lost historical known commit", err)
				}
				return
			}
			if !reflect.DeepEqual(before, m.rows) {
				t.Fatal("failed bind persisted observation", err)
			}
		})
	}
}

func TestExecutionCallFailuresAndDeadlines(t *testing.T) {
	for _, name := range []string{"unknown_purpose", "wrong_evidence", "wrong_probe_ref", "no_observation_content", "no_claim_sts", "no_claim_publish", "zero_claim", "foreign_handle", "scope_changed", "identity_binding", "request_binding", "ref_binding", "identity_expired", "dependency_expired", "budget_expired", "prepare", "installation", "authenticate", "host", "refs", "recheck", "commit_unknown", "commit_expired"} {
		t.Run(name, func(t *testing.T) {
			s, h, db, env, _ := setupExecution(t)
			request := probeRequest(t, db, env)
			var claim *PublicationClaim
			switch name {
			case "unknown_purpose":
				request.Purpose = "task_capture"
			case "wrong_evidence":
				request.EvidenceID = "sev_99999999-2222-4333-8444-555555555555"
			case "wrong_probe_ref":
				request.RefIdentityHash = Hash(strings.Repeat("f", 64))
			case "no_observation_content":
				request.Purpose = "content_read"
			case "no_claim_sts":
				request.Purpose = "sts"
			case "no_claim_publish", "zero_claim":
				request.Purpose = "publish"
				if name == "zero_claim" {
					claim = &PublicationClaim{}
				}
			case "foreign_handle":
				copy := *h
				copy.issuer = &Lifecycle{}
				h = &copy
			case "scope_changed":
				copy := *h
				copy.scope.Installation = "installation_other"
				h = &copy
			case "identity_binding":
				env.altera = func(a *ExecutionAdmission) { a.IdentityHash = Hash(strings.Repeat("f", 64)) }
			case "request_binding":
				env.altera = func(a *ExecutionAdmission) { a.RequestHash = Hash(strings.Repeat("f", 64)) }
			case "ref_binding":
				env.alterr = func(r *ReferenceApproval) { r.RequestHash = Hash(strings.Repeat("f", 64)) }
			case "identity_expired":
				env.identityUntil = Timestamp(db.now.Format(timeLayout))
			case "dependency_expired":
				env.dependencyUntil = Timestamp(db.now.Format(timeLayout))
			case "budget_expired":
				request.BudgetUntil = Timestamp(db.now.Format(timeLayout))
			case "commit_unknown":
				db.commitError = true
			case "commit_expired":
				db.commitWait = 2 * time.Minute
			default:
				env.fail = name
			}
			snapshot, err := s.BeginCall(context.Background(), h, request, claim)
			if err == nil || snapshot != nil {
				t.Fatal("invalid call got snapshot", err)
			}
		})
	}
}

func TestExecutionPrivatePublicationClaimGate(t *testing.T) {
	for _, name := range []string{"sts", "publish", "claim_owner", "claim_version", "claim_expired", "claim_refs", "wrong_system_owner", "wrong_type", "wrong_evidence", "claim_foreign_service", "write_cutoff", "evidence_wait"} {
		t.Run(name, func(t *testing.T) {
			s, h, db, env, m := setupExecution(t)
			probe, observation := requireBound(t, s, h, db, env)
			var run RunRecord
			loadMemoryRecord(t, m, &run, 0)
			run.State = "pending"
			run.RowVersion = "3"
			if name == "write_cutoff" {
				run.OwnerWriteExpiresAt = Timestamp(db.now.Format(timeLayout))
			}
			replaceMemory(t, m, &run)
			until := Timestamp(db.now.Add(10 * time.Second).Format(timeLayout))
			manifest := Hash(strings.Repeat("f", 64))
			owner := ID("synthetic-publication-claim")
			// Synthetic private fixture only: there is no production claim issuer.
			binding := ClaimBinding{EvidenceID: run.EvidenceID, EvidenceVersion: "2", ManifestHash: manifest, Owner: owner, ExpiresAt: until, PolicyHash: env.policy, RefsVersionHash: env.refVersion}
			claim := &PublicationClaim{issuer: s, handle: *h, binding: binding}
			env.evidence = &CallEvidence{EvidenceID: run.EvidenceID, OwnerType: "system", OwnerID: h.scope.Installation, EvidenceType: "capability_snapshot", State: "pending", RowVersion: "2", ManifestHash: &manifest, ClaimOwner: &owner, ClaimExpiresAt: &until}
			request := probe.binding.Call
			request.Purpose = "publish"
			request.RefIdentityHash = Hash(strings.Repeat("9", 64))
			request.RefVersion = "evidence-store-v1"
			if name == "sts" {
				request.Purpose = "sts"
			}
			switch name {
			case "claim_owner":
				other := ID("different-claim")
				env.evidence.ClaimOwner = &other
			case "claim_version":
				env.evidence.RowVersion = "3"
			case "claim_expired":
				db.now = db.now.Add(10 * time.Second)
			case "claim_refs":
				env.refVersion = Hash(strings.Repeat("e", 64))
			case "wrong_system_owner":
				env.evidence.OwnerType = "task"
			case "wrong_type":
				env.evidence.EvidenceType = "job_log_chunk"
			case "wrong_evidence":
				env.evidence.EvidenceID = "sev_99999999-2222-4333-8444-555555555555"
			case "claim_foreign_service":
				claim.issuer = &Execution{}
			case "evidence_wait":
				env.evidenceWait = 11 * time.Second
			}
			snapshot, err := s.BeginCall(context.Background(), h, request, claim)
			if !in(name, "sts", "publish") {
				if err == nil || snapshot != nil {
					t.Fatal("invalid publication snapshot", name, err)
				}
				return
			}
			if err != nil || snapshot == nil || snapshot.Deadline().Format(timeLayout) != string(until) {
				t.Fatal("claim deadline", err, observation)
			}
			if err = s.RecheckCall(context.Background(), snapshot); err != nil {
				t.Fatal(err)
			}
			env.evidence.RowVersion = "3"
			if err = s.RecheckCall(context.Background(), snapshot); err == nil {
				t.Fatal("old claim snapshot after evidence CAS")
			}
			if _, err = json.Marshal(claim); !errors.Is(err, ErrInvalid) {
				t.Fatal("claim serializable")
			}
		})
	}
}
