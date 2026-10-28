package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The A row below is a synthetic SQL participant in the SAME driver transaction.
// It proves atomicity/composition, not A framing or actual MySQL behavior.
const pendingTestTable = "synthetic_pending_evidence"

type pendingTestEnvironment struct {
	db                             *fakeDB
	m                              *commandMemory
	expected                       HistoricalBindingRecord
	policy                         Hash
	fail                           string
	noReport                       bool
	installationWait, evidenceWait time.Duration
	reserves                       int
	cost                           uint64
	alterAdmission                 func(*PendingAdmission)
	alterEvidence                  func(*PendingEvidence)
	mutateFacts                    bool
}

func (e *pendingTestEnvironment) phase(name string) error {
	e.m.events = append(e.m.events, "pending:"+name)
	if name == e.fail {
		return ErrUnavailable
	}
	return nil
}
func (e *pendingTestEnvironment) PreparePending(_ context.Context, _ PendingBinding) (PreparedPending, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedPending{}, err
	}
	p := PreparedPending{Session: e}
	if !e.noReport {
		sample := e.db.now
		p.CapacityObservedAt = &sample
	}
	return p, nil
}
func (e *pendingTestEnvironment) LockInstallation(context.Context, SQL, PendingBinding) error {
	e.db.now = e.db.now.Add(e.installationWait)
	return e.phase("installation")
}
func (e *pendingTestEnvironment) Authenticate(_ context.Context, _ SQL, b PendingBinding, _ DomainRecord) (PendingAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return PendingAdmission{}, err
	}
	hash, _ := PendingBindingHash(b)
	prepared, _ := PendingHistoryHash(e.expected)
	a := PendingAdmission{RequestHash: hash, IdentityHash: b.Subject, IdentityExpiresAt: Timestamp(e.db.now.Add(5 * time.Minute).Format(timeLayout)), DependencyExpiresAt: Timestamp(e.db.now.Add(5 * time.Minute).Format(timeLayout)), PolicyHash: e.policy, PreparedHistoryHash: prepared, AdditionalCost: "131072", ReadExisting: true}
	if e.alterAdmission != nil {
		e.alterAdmission(&a)
	}
	return a, nil
}
func (e *pendingTestEnvironment) LockHost(context.Context, SQL, PendingBinding, GrantRecord) error {
	return e.phase("host")
}
func (e *pendingTestEnvironment) LockReferences(_ context.Context, _ SQL, _ PendingBinding, f PendingFacts) error {
	if e.mutateFacts {
		f.Grant.Target.ResultSlots[0] = "mutated"
		f.History.Evidence.ManifestHash = Hash(strings.Repeat("f", 64))
	}
	return e.phase("refs")
}
func (e *pendingTestEnvironment) Reserve(_ context.Context, _ SQL, _ PendingBinding, cost uint64) error {
	e.reserves++
	e.cost = cost
	return e.phase("reserve")
}
func (e *pendingTestEnvironment) Audit(_ context.Context, _ SQL, _ PendingBinding, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *pendingTestEnvironment) LockEvidence(_ context.Context, _ SQL, b PendingBinding, _ PendingFacts) (PendingEvidence, error) {
	e.db.now = e.db.now.Add(e.evidenceWait)
	if err := e.phase("evidence"); err != nil {
		return PendingEvidence{}, err
	}
	hash, _ := PendingHistoryHash(e.expected)
	v := PendingEvidence{EvidenceID: b.Request.History.Evidence.EvidenceID, HistoryHash: hash, RowVersion: "0", State: "absent"}
	if rows := e.m.rows[pendingTestTable]; len(rows) > 0 {
		if rows[0].Columns["evidence_id"] != string(v.EvidenceID) || rows[0].Columns["history_hash"] != string(hash) {
			return PendingEvidence{}, ErrConflict
		}
		v.Existing = true
		v.RowVersion = "1"
		v.State = "pending"
	}
	if e.alterEvidence != nil {
		e.alterEvidence(&v)
	}
	return v, nil
}
func (e *pendingTestEnvironment) InsertEvidence(ctx context.Context, tx SQL, b PendingBinding, _ PendingFacts) error {
	if err := e.phase("insert"); err != nil {
		return err
	}
	if e.fail == "ignored_sql_failure" {
		_, _ = tx.ExecContext(ctx, "CREATE TABLE forbidden (n INT)")
		return nil
	}
	hash, _ := PendingHistoryHash(e.expected)
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+pendingTestTable+" (evidence_id, history_hash) VALUES (?, ?)", string(b.Request.History.Evidence.EvidenceID), string(hash)); err != nil {
		return err
	}
	return e.phase("after_insert")
}
func (e *pendingTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ PendingBinding, f PendingFacts, _ time.Time) error {
	if err := e.phase("recheck"); err != nil {
		return err
	}
	for _, record := range []any{&f.Run, &f.History, &f.Reference} {
		row, err := EncodeStoredRecord(record)
		if err != nil {
			return err
		}
		if len(e.m.rows[row.Table]) != 1 {
			return ErrConflict
		}
		for key, value := range row.Columns {
			if !sqlEqual(e.m.rows[row.Table][0].Columns[key], value) {
				return ErrConflict
			}
		}
	}
	if len(e.m.rows[pendingTestTable]) != 1 || f.Evidence.State != "pending" || !f.Evidence.Existing {
		return ErrConflict
	}
	return nil
}
func setupPending(t *testing.T) (*Pending, *ExecutionHandle, PendingRequest, *fakeDB, *pendingTestEnvironment, *commandMemory) {
	t.Helper()
	execution, handle, db, env, m := setupExecution(t)
	_, _ = requireBound(t, execution, handle, db, env)
	var run RunRecord
	loadMemoryRecord(t, m, &run, 0)
	var domain DomainRecord
	loadMemoryRecord(t, m, &domain, 0)
	h := *recordFixture(t, "HistoricalBindingRecord").(*HistoricalBindingRecord)
	h.Scope = handle.scope
	h.RunID = run.RunID
	h.GrantID = run.GrantID
	h.GrantGeneration = run.GrantGeneration
	h.DomainEpoch = domain.Epoch
	h.Admission = domain.Admission
	h.TargetHash = run.TargetHash
	h.InputHash = run.InputHash
	h.Evidence.EvidenceID = run.EvidenceID
	h.Evidence.OwnerID = handle.scope.Installation
	h.OwnerWriteExpiresAt = run.OwnerWriteExpiresAt
	h.ObservedAt = *run.ObservedAt
	h.ObservationExpiresAt = *run.ObservationExpiresAt
	h.CreatedAt = Timestamp(db.now.Format(timeLayout))
	h.RetentionExpiresAt = Timestamp(db.now.Add(24 * time.Hour).Format(timeLayout))
	r := PendingRequest{History: h, ExpectedRunVersion: run.RowVersion, PolicyHash: Hash(strings.Repeat("e", 64)), BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
	environment := &pendingTestEnvironment{db: db, m: m, expected: detached(h), policy: r.PolicyHash}
	p, err := NewPending(execution, environment)
	if err != nil {
		t.Fatal(err)
	}
	m.events = nil
	return p, handle, r, db, environment, m
}

func TestPendingAtomicAdmissionReplayAndCallFence(t *testing.T) {
	p, h, r, db, env, m := setupPending(t)
	call := CallRequest{Purpose: "wrap", EvidenceID: r.History.Evidence.EvidenceID, RefIdentityHash: r.History.Evidence.KEKIdentityHash, RefVersion: ProviderVersion(r.History.Evidence.KEKVersion), PolicyHash: p.execution.environment.(*executionTestEnvironment).policy, BudgetUntil: r.BudgetUntil}
	snapshot, err := p.execution.BeginCall(context.Background(), h, call, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.events = nil
	beforeCommits := db.commits
	env.mutateFacts = true
	result, err := p.AdmitPending(context.Background(), h, r)
	if err != nil || result.RunVersion != "3" || result.Replayed || db.commits != beforeCommits+1 {
		t.Fatal(result, err)
	}
	if env.reserves != 1 || env.cost != 368640 {
		t.Fatal("exact cost", env.cost)
	}
	var run RunRecord
	loadMemoryRecord(t, m, &run, 0)
	if run.State != "pending" || *run.ObservedAt != r.History.ObservedAt || run.OwnerWriteExpiresAt != r.History.OwnerWriteExpiresAt {
		t.Fatal("run original bounds")
	}
	var history HistoricalBindingRecord
	loadMemoryRecord(t, m, &history, 0)
	if !reflect.DeepEqual(history, r.History) {
		t.Fatal("history drift")
	}
	want := []string{"pending:prepare", "pending:installation", "lock:system_backup_producer_domains", "pending:authenticate", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "lock:system_backup_producer_evidence_bindings", "pending:host", "lock:system_backup_producer_targets", "lock:system_backup_producer_evidence_refs", "pending:refs", "pending:reserve", "pending:audit:intent", "pending:evidence", "pending:insert", "insert:" + pendingTestTable, "pending:after_insert", "insert:system_backup_producer_evidence_bindings", "insert:system_backup_producer_evidence_refs", "update:system_backup_producer_runs", "pending:audit:result", "pending:recheck"}
	if !reflect.DeepEqual(m.events, want) {
		t.Fatal("phase order", m.events)
	}
	before := cloneMemory(m.rows)
	env.noReport = true
	again, err := p.AdmitPending(context.Background(), h, r)
	if err != nil || !again.Replayed || again.HistoryHash != result.HistoryHash || env.reserves != 1 || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("replay", again, err)
	}
	if p.execution.RecheckCall(context.Background(), snapshot) == nil {
		t.Fatal("old wrap survived pending")
	}
	if _, err = p.execution.BeginCall(context.Background(), h, call, nil); err == nil {
		t.Fatal("new wrap after pending")
	}
	call.Purpose = "publish"
	if s, err := p.execution.BeginCall(context.Background(), h, call, nil); err == nil || s != nil {
		t.Fatal("pending minted publication")
	}
}

func TestPendingFailuresRollbackEveryParticipant(t *testing.T) {
	for _, name := range []string{"prepare", "installation", "authenticate", "host", "refs", "reserve", "audit:intent", "evidence", "insert", "after_insert", "audit:result", "recheck", "ignored_sql_failure", "no_report", "stale_report", "evidence_wait", "expired_budget", "expired_observation", "identity_expiry", "dependency_expiry", "wrong_identity", "wrong_request", "wrong_policy", "wrong_preparation", "cost_overflow", "evidence_exists", "evidence_id", "evidence_hash", "evidence_version", "run_cas", "history_insert"} {
		t.Run(name, func(t *testing.T) {
			p, h, r, db, env, m := setupPending(t)
			before := cloneMemory(m.rows)
			env.fail = name
			switch name {
			case "no_report":
				env.noReport = true
			case "stale_report":
				env.installationWait = 6 * time.Second
			case "evidence_wait":
				env.evidenceWait = 6 * time.Second
			case "expired_budget":
				r.BudgetUntil = Timestamp(db.now.Format(timeLayout))
			case "expired_observation":
				db.now = db.now.Add(31 * time.Second)
			case "identity_expiry":
				env.alterAdmission = func(a *PendingAdmission) { a.IdentityExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "dependency_expiry":
				env.alterAdmission = func(a *PendingAdmission) { a.DependencyExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "wrong_identity":
				env.alterAdmission = func(a *PendingAdmission) { a.IdentityHash = Hash(strings.Repeat("f", 64)) }
			case "wrong_request":
				env.alterAdmission = func(a *PendingAdmission) { a.RequestHash = Hash(strings.Repeat("f", 64)) }
			case "wrong_policy":
				env.alterAdmission = func(a *PendingAdmission) { a.PolicyHash = Hash(strings.Repeat("f", 64)) }
			case "wrong_preparation":
				env.alterAdmission = func(a *PendingAdmission) { a.PreparedHistoryHash = Hash(strings.Repeat("f", 64)) }
			case "cost_overflow":
				env.alterAdmission = func(a *PendingAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "evidence_exists":
				env.alterEvidence = func(v *PendingEvidence) { v.Existing = true; v.RowVersion = "1"; v.State = "pending" }
			case "evidence_id":
				env.alterEvidence = func(v *PendingEvidence) { v.EvidenceID = "sev_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" }
			case "evidence_hash":
				env.alterEvidence = func(v *PendingEvidence) { v.HistoryHash = Hash(strings.Repeat("f", 64)) }
			case "evidence_version":
				env.alterEvidence = func(v *PendingEvidence) { v.RowVersion = "1" }
			case "run_cas", "history_insert":
				original := db.execRecord
				db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
					if name == "run_cas" && strings.HasPrefix(q, "UPDATE system_backup_producer_runs") {
						return driver.RowsAffected(0), nil
					}
					if name == "history_insert" && strings.HasPrefix(q, "INSERT INTO system_backup_producer_evidence_bindings") {
						return nil, ErrUnavailable
					}
					return original(q, args)
				}
			}
			result, err := p.AdmitPending(context.Background(), h, r)
			if err == nil || result != (PendingResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("failed admission leaked result/state", result, err)
			}
		})
	}
}

func TestPendingRejectsUnboundHistoryAndReplayDrift(t *testing.T) {
	for _, name := range []string{"scope", "grant", "generation", "run", "epoch", "admission", "target", "input", "evidence", "owner_deadline", "observed", "observation_expiry", "retention", "created_future", "created_before_observation", "run_version", "version_overflow", "immutable_version", "relative_key"} {
		t.Run(name, func(t *testing.T) {
			p, h, r, db, env, m := setupPending(t)
			before := cloneMemory(m.rows)
			switch name {
			case "scope":
				r.History.Scope.Database = "other"
			case "grant":
				r.History.GrantID = "other"
			case "generation":
				r.History.GrantGeneration = "2"
			case "run":
				r.History.RunID = "other"
			case "epoch":
				r.History.DomainEpoch = "2"
			case "admission":
				if r.History.Admission.Unconfigured != nil {
					r.History.Admission.Unconfigured.DeploymentAdmissionID = "other"
				} else {
					r.History.Admission.Configured.CheckAdmissionID = "other"
				}
			case "target":
				r.History.TargetHash = Hash(strings.Repeat("f", 64))
			case "input":
				r.History.InputHash = Hash(strings.Repeat("f", 64))
			case "evidence":
				r.History.Evidence.EvidenceID = "sev_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
			case "owner_deadline":
				r.History.OwnerWriteExpiresAt = Timestamp(db.now.Add(2 * time.Minute).Format(timeLayout))
			case "observed":
				r.History.ObservedAt = Timestamp(db.now.Add(-time.Second).Format(timeLayout))
			case "observation_expiry":
				r.History.ObservationExpiresAt = Timestamp(db.now.Add(31 * time.Second).Format(timeLayout))
			case "retention":
				r.History.RetentionExpiresAt = Timestamp(db.now.Add(time.Second).Format(timeLayout))
			case "created_future":
				r.History.CreatedAt = Timestamp(db.now.Add(time.Second).Format(timeLayout))
			case "created_before_observation":
				r.History.CreatedAt = Timestamp(db.now.Add(-time.Second).Format(timeLayout))
			case "run_version":
				r.ExpectedRunVersion = "1"
			case "version_overflow":
				r.ExpectedRunVersion = "18446744073709551615"
			case "immutable_version":
				v := Text("v1")
				r.History.Evidence.ImmutableVersion = &v
			case "relative_key":
				r.History.RelativeKey = "other"
			}
			// Deliberately authenticate the changed data: D must still bind it
			// against the independently locked original run/domain, not just hashes.
			env.expected = detached(r.History)
			if result, err := p.AdmitPending(context.Background(), h, r); err == nil || result != (PendingResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("unbound history", result, err)
			}
		})
	}
	for _, name := range []string{"manifest", "retention", "no_read_authority", "missing_hold", "missing_evidence", "ready_evidence", "foreign_handle", "revoked"} {
		t.Run("replay_"+name, func(t *testing.T) {
			p, h, r, _, env, m := setupPending(t)
			if _, err := p.AdmitPending(context.Background(), h, r); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "manifest":
				r.History.Evidence.ManifestHash = Hash(strings.Repeat("f", 64))
				env.expected = detached(r.History)
			case "retention":
				r.History.RetentionExpiresAt = "2026-10-02T01:00:00.000001Z"
				env.expected = detached(r.History)
			case "no_read_authority":
				env.alterAdmission = func(a *PendingAdmission) { a.ReadExisting = false }
			case "missing_hold":
				delete(m.rows, "system_backup_producer_evidence_refs")
			case "missing_evidence":
				delete(m.rows, pendingTestTable)
			case "ready_evidence":
				env.alterEvidence = func(v *PendingEvidence) { v.State = "ready" }
			case "foreign_handle":
				other, _, _, _, _, _ := setupPending(t)
				h = &ExecutionHandle{issuer: other.execution.lifecycle}
			case "revoked":
				var grant GrantRecord
				loadMemoryRecord(t, m, &grant, 0)
				grant.State = "revoked"
				replaceMemory(t, m, &grant)
			}
			before := cloneMemory(m.rows)
			if result, err := p.AdmitPending(context.Background(), h, r); err == nil || result != (PendingResult{}) || !reflect.DeepEqual(before, m.rows) || env.reserves != 1 {
				t.Fatal("bad replay", result, err)
			}
		})
	}
}

func TestPendingCommitOutcomeAndConstructors(t *testing.T) {
	for _, name := range []string{"unknown", "expired"} {
		t.Run(name, func(t *testing.T) {
			p, h, r, db, _, m := setupPending(t)
			if name == "unknown" {
				db.commitError = true
			} else {
				db.commitWait = 6 * time.Second
			}
			result, err := p.AdmitPending(context.Background(), h, r)
			if name == "unknown" {
				if !errors.Is(err, ErrCommitUnknown) || result != (PendingResult{}) {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, ErrCommittedExpired) || result.RunVersion != "3" || len(m.rows[pendingTestTable]) != 1 {
				t.Fatal(result, err)
			}
		})
	}
	p, _, _, _, _, _ := setupPending(t)
	var typedNil *pendingTestEnvironment
	if _, err := NewPending(nil, typedNil); err == nil {
		t.Fatal("nil execution")
	}
	if _, err := NewPending(p.execution, typedNil); err == nil {
		t.Fatal("typed nil environment")
	}
}
