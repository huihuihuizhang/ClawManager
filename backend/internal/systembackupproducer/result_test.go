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

type resultTestEnvironment struct {
	db                 *fakeDB
	m                  *commandMemory
	expected           ResultRequest
	evidence           ResultEvidence
	retention          Timestamp
	mode, fail         string
	noReport           bool
	wait, evidenceWait time.Duration
	reserves           int
	cost               uint64
	alterAdmission     func(*ResultAdmission)
	alterProjection    func(*ResultProjection)
	alterEvidence      func(*ResultEvidence)
}

func (e *resultTestEnvironment) phase(n string) error {
	e.m.events = append(e.m.events, "result:"+n)
	if n == e.fail {
		return ErrUnavailable
	}
	return nil
}
func (e *resultTestEnvironment) PrepareResult(context.Context, ResultBinding) (PreparedResult, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedResult{}, err
	}
	p := PreparedResult{Session: e}
	if !e.noReport {
		s := e.db.now
		p.CapacityObservedAt = &s
	}
	return p, nil
}
func (e *resultTestEnvironment) LockInstallation(context.Context, SQL, ResultBinding) error {
	e.db.now = e.db.now.Add(e.wait)
	return e.phase("installation")
}
func (e *resultTestEnvironment) Authenticate(_ context.Context, _ SQL, b ResultBinding, _ DomainRecord) (ResultAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return ResultAdmission{}, err
	}
	if !reflect.DeepEqual(b.Request, e.expected) {
		return ResultAdmission{}, ErrGuardRequired
	}
	hash, _ := ResultBindingHash(b)
	digests, _ := ResultHashes(e.expected)
	a := ResultAdmission{BindingHash: hash, IdentityHash: b.Subject, VerifiedRequestHash: digests.Request, IdentityExpiresAt: Timestamp(e.db.now.Add(time.Hour).Format(timeLayout)), DependencyExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), ReceiptRetentionUntil: e.retention, AdditionalCost: "65536", ReadReceipt: true}
	if e.alterAdmission != nil {
		e.alterAdmission(&a)
	}
	return a, nil
}
func (e *resultTestEnvironment) LockHost(context.Context, SQL, ResultBinding, GrantRecord) error {
	return e.phase("host")
}
func (e *resultTestEnvironment) LockProjectionReferences(_ context.Context, _ SQL, b ResultBinding, _ ResultFacts) (ResultProjection, error) {
	if err := e.phase("projection_locks"); err != nil {
		return ResultProjection{}, err
	}
	h, _ := ResultBindingHash(b)
	d, _ := ResultHashes(b.Request)
	p := ResultProjection{BindingHash: h, TargetHash: d.Target, MappingHash: Hash(strings.Repeat("d", 64)), Mode: e.mode}
	if e.alterProjection != nil {
		e.alterProjection(&p)
	}
	return p, nil
}
func (e *resultTestEnvironment) Reserve(_ context.Context, _ SQL, _ ResultBinding, c uint64) error {
	e.reserves++
	e.cost = c
	return e.phase("reserve")
}
func (e *resultTestEnvironment) Audit(_ context.Context, _ SQL, _ ResultBinding, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *resultTestEnvironment) LockEvidence(context.Context, SQL, ResultBinding, ResultFacts) (ResultEvidence, error) {
	e.db.now = e.db.now.Add(e.evidenceWait)
	if err := e.phase("evidence"); err != nil {
		return ResultEvidence{}, err
	}
	v := detached(e.evidence)
	if e.alterEvidence != nil {
		e.alterEvidence(&v)
	}
	return v, nil
}
func (e *resultTestEnvironment) ApplyProjections(ctx context.Context, tx SQL, b ResultBinding, _ ResultFacts) error {
	if err := e.phase("apply"); err != nil {
		return err
	}
	hash, _ := ResultHashes(b.Request)
	if _, err := tx.ExecContext(ctx, "INSERT INTO synthetic_result_projection (request_hash) VALUES (?)", string(hash.Request)); err != nil {
		return err
	}
	return e.phase("after_apply")
}
func (e *resultTestEnvironment) Recheck(_ context.Context, _ ReadSQL, b ResultBinding, f ResultFacts, _ time.Time) error {
	if err := e.phase("recheck"); err != nil {
		return err
	}
	if f.Receipt == nil || !reflect.DeepEqual(f.Receipt.Request, b.Request) {
		return ErrConflict
	}
	records := []any{f.Receipt}
	if !f.Replayed {
		records = append(records, f.Run, f.Target)
	}
	for _, v := range records {
		row, err := EncodeStoredRecord(v)
		if err != nil {
			return err
		}
		if len(e.m.rows[row.Table]) != 1 {
			return ErrConflict
		}
		for k, value := range row.Columns {
			if !sqlEqual(e.m.rows[row.Table][0].Columns[k], value) {
				return ErrConflict
			}
		}
	}
	return nil
}
func resultFixture(t *testing.T, name string) ResultRequest {
	t.Helper()
	for _, f := range fixtures(t).Positive {
		if f.ID == name {
			var r ResultRequest
			if err := DecodeRecord(f.Value, &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
	}
	t.Fatal(name)
	return ResultRequest{}
}
func setupResult(t *testing.T, scenario, mode string) (*ResultsService, *ExecutionHandle, ResultRequest, *fakeDB, *resultTestEnvironment, *commandMemory) {
	t.Helper()
	finish, claim, fr, db, _, m := setupFinish(t)
	out, err := finish.FinishPublication(context.Background(), claim, fr)
	if err != nil {
		t.Fatal(err)
	}
	var g GrantRecord
	loadMemoryRecord(t, m, &g, 0)
	var run RunRecord
	loadMemoryRecord(t, m, &run, 0)
	var history HistoricalBindingRecord
	loadMemoryRecord(t, m, &history, 0)
	var domain DomainRecord
	loadMemoryRecord(t, m, &domain, 0)
	r := resultFixture(t, scenario+"_artifact")
	if scenario != "unconfigured" {
		domain.Admission = detached(r.Admission)
		g.Admission = detached(r.Admission)
		history.Admission = detached(r.Admission)
		replaceMemory(t, m, &domain)
		replaceMemory(t, m, &g)
		replaceMemory(t, m, &history)
	}
	r.Scope = claim.handle.scope
	r.GrantID = g.GrantID
	r.GrantGeneration = g.Generation
	r.RunID = run.RunID
	r.DomainEpoch = domain.Epoch
	r.Admission = detached(domain.Admission)
	r.Target = detached(g.Target)
	r.InputHash = run.InputHash
	r.TargetGeneration = run.TargetGeneration
	r.ExpectedResultVersion = "0"
	r.Evidence = history.Evidence
	r.Evidence.ImmutableVersion = out.ImmutableVersion
	r.ExpectedEvidenceVersion = out.EvidenceVersion
	r.ObservedAt = *run.ObservedAt
	r.ObservationExpiresAt = *run.ObservationExpiresAt
	env := &resultTestEnvironment{db: db, m: m, expected: detached(r), retention: history.RetentionExpiresAt, mode: mode, evidence: ResultEvidence{Evidence: detached(r.Evidence), RowVersion: out.EvidenceVersion, State: "ready", Failure: "none", RetentionExpiresAt: history.RetentionExpiresAt, ProtectedUntil: history.RetentionExpiresAt}}
	service, err := NewResults(finish.execution, env)
	if err != nil {
		t.Fatal(err)
	}
	m.events = nil
	return service, &claim.handle, r, db, env, m
}
func TestResultCommitCandidateConfiguredAndHistoricalReplay(t *testing.T) {
	for _, variant := range []struct{ scenario, mode string }{{"unconfigured", "candidate"}, {"disabled", "configured"}, {"enabled", "configured"}, {"enabled", "candidate"}} {
		t.Run(variant.scenario+"_"+variant.mode, func(t *testing.T) {
			s, h, r, db, env, m := setupResult(t, variant.scenario, variant.mode)
			before := cloneMemory(m.rows)
			commits := db.commits
			result, err := s.CommitResult(context.Background(), h, r)
			if err != nil || result.Replayed || result.Receipt.ResultVersion != "1" || result.Receipt.ChargedBytes != "442368" || env.cost != 442368 || env.reserves != 1 || db.commits != commits+1 {
				t.Fatal("commit", result, err, env.cost)
			}
			if !reflect.DeepEqual(before[claimTestTable], m.rows[claimTestTable]) || !reflect.DeepEqual(before["system_backup_producer_evidence_bindings"], m.rows["system_backup_producer_evidence_bindings"]) {
				t.Fatal("result changed evidence/history")
			}
			var run RunRecord
			loadMemoryRecord(t, m, &run, 0)
			var target TargetRecord
			loadMemoryRecord(t, m, &target, 0)
			if run.State != "committed" || run.RowVersion != "5" || target.ResultVersion != "1" || target.RowVersion != "2" || len(m.rows["system_backup_producer_evidence_refs"]) != 3 {
				t.Fatal("atomic result state", run, target)
			}
			if (len(m.rows["synthetic_result_projection"]) == 1) != (variant.mode == "configured") {
				t.Fatal("projection mode")
			}
			receiptIndex, grantIndex := -1, -1
			for i, v := range m.events {
				if v == "lock:system_backup_producer_result_receipts" {
					receiptIndex = i
				}
				if v == "lock:system_backup_producer_grants" {
					grantIndex = i
				}
			}
			if receiptIndex < 0 || receiptIndex >= grantIndex {
				t.Fatal("receipt L3 order")
			}
			// Replay uses separate exact historical authority after execution expires
			// and grant is revoked. It returns the old receipt, never a new permission.
			db.now = db.now.Add(time.Hour)
			env.noReport = true
			var g GrantRecord
			loadMemoryRecord(t, m, &g, 0)
			g.State = "revoked"
			replaceMemory(t, m, &g)
			before = cloneMemory(m.rows)
			m.events = nil
			replay, err := s.CommitResult(context.Background(), h, r)
			if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Receipt, result.Receipt) || !reflect.DeepEqual(before, m.rows) || env.reserves != 1 {
				t.Fatal("historical replay", replay, err)
			}
			for _, event := range m.events {
				if event == "result:reserve" || event == "result:evidence" || event == "result:apply" || event == "lock:system_backup_producer_grants" {
					t.Fatal("replay reused execution path", event)
				}
			}
		})
	}
}
func TestResultFailuresRollbackProjectionAndReceipt(t *testing.T) {
	for _, name := range []string{"prepare", "installation", "authenticate", "host", "projection_locks", "reserve", "audit:intent", "evidence", "apply", "after_apply", "audit:result", "recheck", "no_report", "stale_report", "evidence_wait", "binding", "identity", "attestation", "identity_expired", "dependency_expired", "short_retention", "cost_overflow", "projection_target", "projection_mode", "evidence_state", "evidence_version", "evidence_hash", "evidence_claim", "evidence_retention", "evidence_protection", "target_cas", "run_cas", "receipt_insert", "revoked", "renewed", "target_version", "run_committed", "missing_hold"} {
		t.Run(name, func(t *testing.T) {
			s, h, r, db, env, m := setupResult(t, "enabled", "configured")
			env.fail = name
			switch name {
			case "no_report":
				env.noReport = true
			case "stale_report":
				env.wait = 6 * time.Second
			case "evidence_wait":
				env.evidenceWait = 6 * time.Second
			case "binding":
				env.alterAdmission = func(a *ResultAdmission) { a.BindingHash = Hash(strings.Repeat("f", 64)) }
			case "identity":
				env.alterAdmission = func(a *ResultAdmission) { a.IdentityHash = Hash(strings.Repeat("f", 64)) }
			case "attestation":
				env.alterAdmission = func(a *ResultAdmission) { a.VerifiedRequestHash = Hash(strings.Repeat("f", 64)) }
			case "identity_expired":
				env.alterAdmission = func(a *ResultAdmission) { a.IdentityExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "dependency_expired":
				env.alterAdmission = func(a *ResultAdmission) { a.DependencyExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "short_retention":
				env.alterAdmission = func(a *ResultAdmission) {
					a.ReceiptRetentionUntil = Timestamp(db.now.Add(time.Minute).Format(timeLayout))
				}
			case "cost_overflow":
				env.alterAdmission = func(a *ResultAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "projection_target":
				env.alterProjection = func(p *ResultProjection) { p.TargetHash = Hash(strings.Repeat("f", 64)) }
			case "projection_mode":
				env.alterProjection = func(p *ResultProjection) { p.Mode = "other" }
			case "evidence_state":
				env.alterEvidence = func(e *ResultEvidence) { e.State = "write_unknown" }
			case "evidence_version":
				env.alterEvidence = func(e *ResultEvidence) { e.RowVersion = "4" }
			case "evidence_hash":
				env.alterEvidence = func(e *ResultEvidence) { e.Evidence.ContentHash = Hash(strings.Repeat("f", 64)) }
			case "evidence_claim":
				env.alterEvidence = func(e *ResultEvidence) { c := ID("other"); e.ClaimOwner = &c }
			case "evidence_retention":
				env.alterEvidence = func(e *ResultEvidence) { e.RetentionExpiresAt = Timestamp(db.now.Add(time.Minute).Format(timeLayout)) }
			case "evidence_protection":
				env.alterEvidence = func(e *ResultEvidence) { e.ProtectedUntil = Timestamp(db.now.Add(time.Minute).Format(timeLayout)) }
			case "target_cas", "run_cas", "receipt_insert":
				previous := db.execRecord
				db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
					if name == "target_cas" && strings.HasPrefix(q, "UPDATE system_backup_producer_targets") || name == "run_cas" && strings.HasPrefix(q, "UPDATE system_backup_producer_runs") {
						return driver.RowsAffected(0), nil
					}
					if name == "receipt_insert" && strings.HasPrefix(q, "INSERT INTO system_backup_producer_result_receipts") {
						return nil, ErrUnavailable
					}
					return previous(q, a)
				}
			case "revoked", "renewed":
				var g GrantRecord
				loadMemoryRecord(t, m, &g, 0)
				if name == "revoked" {
					g.State = "revoked"
				} else {
					g.RowVersion = "2"
				}
				replaceMemory(t, m, &g)
			case "target_version":
				var target TargetRecord
				loadMemoryRecord(t, m, &target, 0)
				target.ResultVersion = "1"
				replaceMemory(t, m, &target)
			case "run_committed":
				var run RunRecord
				loadMemoryRecord(t, m, &run, 0)
				run.State = "committed"
				replaceMemory(t, m, &run)
			case "missing_hold":
				delete(m.rows, "system_backup_producer_evidence_refs")
			}
			before := cloneMemory(m.rows)
			out, err := s.CommitResult(context.Background(), h, r)
			if err == nil || !reflect.DeepEqual(out, CommittedResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("failed result leaked", out, err)
			}
		})
	}
}
func TestResultRequestBindingReplayAndCommitOutcomes(t *testing.T) {
	for _, name := range []string{"scope", "grant", "run", "domain_epoch", "input", "target_generation", "observed", "observation_expiry", "object_hash", "object_version", "missing_slot", "changed_slot", "unconfigured_live", "new_key_after_commit", "changed_result_replay", "no_receipt_authority", "unknown_commit", "late_commit"} {
		t.Run(name, func(t *testing.T) {
			s, h, r, db, env, m := setupResult(t, "unconfigured", "candidate")
			if in(name, "new_key_after_commit", "changed_result_replay", "no_receipt_authority") {
				if _, err := s.CommitResult(context.Background(), h, r); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "scope":
				r.Scope.Database = "other"
			case "grant":
				r.GrantID = "other"
			case "run":
				r.RunID = "other"
			case "domain_epoch":
				r.DomainEpoch = "2"
			case "input":
				r.InputHash = Hash(strings.Repeat("f", 64))
			case "target_generation":
				r.TargetGeneration = "2"
			case "observed":
				r.ObservedAt = Timestamp(db.now.Add(-2 * time.Second).Format(timeLayout))
			case "observation_expiry":
				r.ObservationExpiresAt = Timestamp(db.now.Add(time.Minute).Format(timeLayout))
			case "object_hash":
				r.Evidence.ObjectHash = Hash(strings.Repeat("f", 64))
			case "object_version":
				v := Text("other")
				r.Evidence.ImmutableVersion = &v
			case "missing_slot":
				r.Results.Provider.Observations = r.Results.Provider.Observations[1:]
			case "changed_slot":
				r.Results.Provider.Observations[0].Slot = "unknown"
			case "unconfigured_live":
				env.mode = "configured"
			case "new_key_after_commit":
				r.RequestKey = "another-request-key-1"
			case "changed_result_replay":
				r.Results.Provider.Observations[0].Status = "unsupported"
				r.Results.Provider.Observations[0].Reason = "unsupported_api"
			case "no_receipt_authority":
				env.alterAdmission = func(a *ResultAdmission) { a.ReadReceipt = false }
			case "unknown_commit":
				db.commitError = true
			case "late_commit":
				db.commitWait = 6 * time.Second
			}
			env.expected = detached(r)
			before := cloneMemory(m.rows)
			out, err := s.CommitResult(context.Background(), h, r)
			if name == "late_commit" {
				if !errors.Is(err, ErrCommittedExpired) || out.Receipt.ResultVersion != "1" {
					t.Fatal(out, err)
				}
				return
			}
			if name == "unknown_commit" {
				if !errors.Is(err, ErrCommitUnknown) || !reflect.DeepEqual(out, CommittedResult{}) {
					t.Fatal(out, err)
				}
				db.commitError = false
				env.noReport = true
				out, err = s.CommitResult(context.Background(), h, r)
				if err != nil || !out.Replayed {
					t.Fatal("committed unknown readback", out, err)
				}
				return
			}
			if err == nil || !reflect.DeepEqual(out, CommittedResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("bad binding/replay", out, err)
			}
		})
	}
}
