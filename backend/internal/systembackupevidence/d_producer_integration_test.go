package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type dIntegrationFixture struct {
	t                     *testing.T
	realDB                bool
	d                     *dIntegrationDB
	db                    *sql.DB
	until                 time.Time
	policy                pd.Hash
	fail                  string
	readReceipt           bool
	acceptPublishedFinish bool
	executionRecheckHook  func()
	command               pd.CommandRequest
	observation           pd.ObservationRequest
	probe                 pd.CallRequest
	history               pd.HistoricalBindingRecord
	pendingRequest        pd.PendingRequest
	claimRequest          pd.ClaimRequest
	finishRequest         pd.FinishRequest
	resultRequest         pd.ResultRequest
	handle                *pd.ExecutionHandle
	pending               *pd.Pending
	publication           *pd.Publication
	finalizer             *pd.Finalizer
	results               *pd.ResultsService
	claim                 *pd.PublicationClaim
	prepared              Prepared
	channel               ProducerEvidenceChannel
	ciphertext            []byte
	lifecycle             *pd.Lifecycle
}

func dIntegrationVector(t *testing.T, group, key string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "producer-authority-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The file also contains metadata; decode just the requested array.
	var root map[string]json.RawMessage
	if err = json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		ID, Definition string
		Value          json.RawMessage
	}
	if err = json.Unmarshal(root[group], &entries); err != nil {
		t.Fatal(err)
	}
	for _, v := range entries {
		if v.ID == key || v.Definition == key {
			return v.Value
		}
	}
	t.Fatalf("missing %s/%s", group, key)
	return nil
}
func (f *dIntegrationFixture) refs(h pd.Hash) pd.ReferenceApproval {
	return pd.ReferenceApproval{RequestHash: h, PolicyHash: f.policy, VersionHash: f.policy, DependencyExpiresAt: systemExecutionStamp(f.until)}
}
func (f *dIntegrationFixture) audit(ctx context.Context, tx pd.SQL, operation, stage string) error {
	if stage != "result" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); err != nil {
		return pd.ErrUnavailable
	}
	switch f.fail {
	case operation + "_audit":
		return pd.ErrUnavailable
	case operation + "_capacity":
		f.d.now = f.d.now.Add(6 * time.Second)
	case operation + "_chunks":
		f.d.chunks[0]["gcm_nonce"] = []byte("corrupted after service writes")
	}
	return nil
}
func newDIntegrationFixture(t *testing.T) *dIntegrationFixture {
	return newDIntegrationFixtureWithDB(t, nil)
}
func newDIntegrationFixtureWithDB(t *testing.T, database *sql.DB, advanceClock ...bool) *dIntegrationFixture {
	t.Helper()
	prepared, channel, record, binding, ciphertext := producerBindingFixtureWithCiphertext(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &dIntegrationFixture{t: t, until: now.Add(5 * time.Minute), policy: pd.Hash(strings.Repeat("c", 64)), readReceipt: true}
	f.prepared, f.channel, f.ciphertext = prepared, channel, ciphertext
	command, err := pd.DecodeCommand(dIntegrationVector(t, "commands", "acquire"))
	if err != nil {
		t.Fatal(err)
	}
	command.Scope.Installation = binding.OwnerID
	command.Next.EvidenceID = binding.EvidenceID
	command.Next.AuthorizationExpiresAt = systemExecutionStamp(f.until)
	ownerWriteWindow := 2 * time.Minute
	if len(advanceClock) > 1 && advanceClock[1] {
		// Isolated historical-recovery MySQL tests need a real database cutoff
		// without waiting two minutes. All records still share this original date.
		ownerWriteWindow = 12 * time.Second
	}
	command.Next.OwnerWriteExpiresAt = systemExecutionStamp(now.Add(ownerWriteWindow))
	lease := systemExecutionStamp(now.Add(2 * time.Minute))
	command.LeaseExpiresAt = &lease
	if err = pd.DecodeRecord(producerHistoricalVector(t), &f.history); err != nil {
		t.Fatal(err)
	}
	f.history.RetentionExpiresAt = systemExecutionStamp(now.Add(24 * time.Hour))
	f.d = &dIntegrationDB{systemPendingTestDB: &systemPendingTestDB{t: t, scope: command.Scope, now: now}, records: map[string][]map[string]driver.Value{}}
	if len(advanceClock) > 0 {
		f.d.advanceClock = advanceClock[0]
	}
	f.db = database
	f.realDB = database != nil
	if database == nil {
		f.db = sql.OpenDB(f.d)
		f.db.SetMaxOpenConns(1)
	}
	t.Cleanup(func() { f.db.Close() })
	// The remote harness has already verified and created this run-owned DB.
	// Bind before seeding any canonical record or constructing a service: the
	// contract vector's database identity cannot name a random MySQL test DB.
	command.Scope, err = dIntegrationDatabaseScope(context.Background(), f.db, command.Scope)
	if err != nil {
		t.Fatal("fixture database scope", err)
	}
	f.command = command
	f.d.scope = command.Scope
	var domain pd.DomainRecord
	if err = pd.DecodeRecord(dIntegrationVector(t, "records", "DomainRecord"), &domain); err != nil {
		t.Fatal(err)
	}
	domain.Scope = command.Scope
	domain.AdmissionExpiresAt = systemExecutionStamp(f.until)
	domain.CreatedAt = systemExecutionStamp(now)
	domain.UpdatedAt = domain.CreatedAt
	f.seed(&domain)
	lifecycle, err := pd.NewLifecycle(f.db, command.Scope, &dIntegrationCommand{f})
	if err != nil {
		t.Fatal(err)
	}
	f.lifecycle = lifecycle
	acquired, err := lifecycle.Execute(context.Background(), command, nil)
	if err != nil || acquired.Handle == nil {
		t.Fatal("acquire", err)
	}
	f.handle = acquired.Handle
	execution, err := pd.NewExecution(lifecycle, &dIntegrationExecution{f})
	if err != nil {
		t.Fatal(err)
	}
	budget := systemExecutionStamp(now.Add(time.Minute))
	f.probe = pd.CallRequest{Purpose: "probe", EvidenceID: binding.EvidenceID, RefIdentityHash: command.Target.IdentityHash, RefVersion: command.Target.RefVersion, PolicyHash: f.policy, BudgetUntil: budget}
	probe, err := execution.BeginCall(context.Background(), f.handle, f.probe, nil)
	if err != nil {
		t.Fatal("probe", err)
	}
	// A real MySQL probe captures database time after fixture initialization.
	// Bind the simulated evaluator observation to that committed snapshot.
	f.observation = pd.ObservationRequest{ExpectedRunVersion: "1", ObservedAt: probe.View().CapturedAt, ExpiresAt: budget, AttestationHash: pd.Hash(strings.Repeat("d", 64))}
	if _, err = execution.BindObservation(context.Background(), f.handle, probe, f.observation); err != nil {
		t.Fatal("observation", err)
	}
	var run pd.RunRecord
	f.load("system_backup_producer_runs", &run)
	h := &f.history
	h.Scope = command.Scope
	h.RunID = run.RunID
	h.GrantID = run.GrantID
	h.GrantGeneration = run.GrantGeneration
	h.DomainEpoch = domain.Epoch
	h.Admission = domain.Admission
	h.TargetHash = run.TargetHash
	h.InputHash = run.InputHash
	h.Evidence = binding
	h.RelativeKey = pd.RelativeKey(record.Ref.RelativeKey)
	h.OwnerWriteExpiresAt = run.OwnerWriteExpiresAt
	h.ObservedAt = *run.ObservedAt
	h.ObservationExpiresAt = *run.ObservationExpiresAt
	h.CreatedAt = h.ObservedAt
	f.pendingRequest = pd.PendingRequest{History: *h, ExpectedRunVersion: run.RowVersion, PolicyHash: f.policy, BudgetUntil: budget}
	pe, err := NewSystemPendingEnvironment(&dIntegrationPending{f: f}, prepared, channel, *h)
	if err != nil {
		t.Fatal("pending environment", err)
	}
	f.pending, err = pd.NewPending(execution, pe)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := NewSystemClaimEnvironment(&dIntegrationClaim{f: f}, prepared, channel, *h)
	if err != nil {
		t.Fatal(err)
	}
	f.publication, err = pd.NewPublication(execution, ce)
	if err != nil {
		t.Fatal(err)
	}
	fe, err := NewSystemFinishEnvironment(&dIntegrationFinish{f: f}, prepared, channel, *h)
	if err != nil {
		t.Fatal(err)
	}
	f.finalizer, err = pd.NewFinalizer(execution, fe)
	if err != nil {
		t.Fatal(err)
	}
	re, err := NewSystemResultEnvironment(&dIntegrationResult{f: f}, prepared, channel, *h)
	if err != nil {
		t.Fatal(err)
	}
	f.results, err = pd.NewResults(execution, re)
	if err != nil {
		t.Fatal(err)
	}
	// The shortened recovery fixture must not request a claim beyond the
	// original owner-write cutoff. Keep the production deadline guard intact.
	claimWindow := min(45*time.Second, ownerWriteWindow)
	f.claimRequest = pd.ClaimRequest{EvidenceID: binding.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "d-integration-claim-0001", ExpiresAt: systemExecutionStamp(now.Add(claimWindow)), PolicyHash: f.policy, RefsVersionHash: f.policy, BudgetUntil: budget}
	version := pd.Text("Exact.Version/1")
	f.finishRequest = pd.FinishRequest{State: "ready", ProofHash: pd.Hash(strings.Repeat("e", 64)), ObjectHash: binding.ObjectHash, ObjectBytes: binding.ObjectBytes, ImmutableVersion: &version, ObservedAt: h.CreatedAt, BudgetUntil: budget}
	if err = pd.DecodeRecord(dIntegrationVector(t, "positive", "unconfigured_artifact"), &f.resultRequest); err != nil {
		t.Fatal(err)
	}
	r := &f.resultRequest
	r.Scope = h.Scope
	r.GrantID = h.GrantID
	r.GrantGeneration = h.GrantGeneration
	r.RunID = h.RunID
	r.DomainEpoch = h.DomainEpoch
	r.Admission = h.Admission
	r.Target = command.Target
	r.InputHash = h.InputHash
	r.TargetGeneration = run.TargetGeneration
	r.Evidence = binding
	r.Evidence.ImmutableVersion = &version
	r.ObservedAt = h.ObservedAt
	r.ObservationExpiresAt = h.ObservationExpiresAt
	return f
}
func (f *dIntegrationFixture) step(stage string) error {
	ctx := context.Background()
	switch stage {
	case "pending":
		// Fixture construction/file loading may exceed the five-second capacity
		// observation window on a slow host. Model a fresh SQL clock before this
		// NEW admission, as the real database does; preserve all original owner,
		// claim and budget deadlines. Delays injected inside audit/guard remain
		// observable and must still fail the existing expiry tests.
		if !f.realDB {
			f.d.now = time.Now().UTC().Truncate(time.Microsecond)
		}
		out, err := f.pending.AdmitPending(ctx, f.handle, f.pendingRequest)
		if err == nil && out.RunVersion != "3" {
			f.t.Fatal("pending version", out)
		}
		return err
	case "claim":
		var err error
		f.claim, err = f.publication.ClaimPublication(ctx, f.handle, f.claimRequest)
		return err
	case "finish":
		out, err := f.finalizer.FinishPublication(ctx, f.claim, f.finishRequest)
		if err == nil && out.EvidenceVersion != "3" {
			f.t.Fatal("finish version", out)
		}
		return err
	case "result":
		_, err := f.results.CommitResult(ctx, f.handle, f.resultRequest)
		return err
	}
	f.t.Fatal(stage)
	return pd.ErrInvalid
}

func TestDProducerPendingAfterSlowLocalSetup(t *testing.T) {
	f := newDIntegrationFixture(t)
	budget, owner, claim, authority := f.pendingRequest.BudgetUntil, f.history.OwnerWriteExpiresAt, f.claimRequest.ExpiresAt, f.until
	time.Sleep(6 * time.Second)
	f.advance("pending")
	if f.pendingRequest.BudgetUntil != budget || f.history.OwnerWriteExpiresAt != owner || f.claimRequest.ExpiresAt != claim || !f.until.Equal(authority) {
		t.Fatal("setup clock sample extended an original execution deadline")
	}
}
func (f *dIntegrationFixture) advance(stages ...string) {
	f.t.Helper()
	for _, stage := range stages {
		if err := f.step(stage); err != nil {
			f.t.Fatal(stage, err)
		}
	}
}

func TestDProducerActualAAdaptersLifecycleToReceipt(t *testing.T) {
	f := newDIntegrationFixture(t)
	ctx := context.Background()
	f.advance("pending")
	writes := f.d.writes
	pending, err := f.pending.AdmitPending(ctx, f.handle, f.pendingRequest)
	if err != nil || !pending.Replayed || f.d.writes != writes {
		t.Fatal("pending replay", pending, err)
	}
	f.advance("claim")
	writes = f.d.writes
	claim, err := f.publication.ReadPublicationClaim(ctx, f.handle, f.claimRequest)
	if err != nil || claim == nil || f.d.writes != writes {
		t.Fatal("claim readback", err)
	}
	f.claim = claim
	f.advance("finish", "result")
	var run pd.RunRecord
	f.load("system_backup_producer_runs", &run)
	var target pd.TargetRecord
	f.d.load("system_backup_producer_targets", &target)
	var receipt pd.ReceiptRecord
	f.d.load("system_backup_producer_result_receipts", &receipt)
	if run.State != "committed" || run.RowVersion != "5" || target.ResultVersion != "1" || receipt.ResultVersion != "1" || !reflect.DeepEqual(receipt.Request, f.resultRequest) || len(f.d.records["system_backup_producer_evidence_refs"]) != 3 {
		t.Fatal("incomplete D result")
	}
	if f.d.row["storage_state"] != "ready" || f.d.row["row_version"] != int64(3) || f.d.row["claim_owner"] != nil || f.d.row["storage_immutable_version"] != "Exact.Version/1" || f.d.row["observed_health"] != "unknown" || len(f.d.chunks) != 1 {
		t.Fatal("incomplete A publication")
	}
	if err = f.d.check(&f.history); err != nil {
		t.Fatal("original history mutated", err)
	}
	// Expired execution cannot be used, but independently authorized exact
	// historical replay must not touch the now-unavailable A loader.
	f.d.now = f.d.now.Add(10 * time.Minute)
	f.until = f.d.now.Add(time.Minute)
	f.d.fail = "read_evidence"
	writes = f.d.writes
	before := cloneDIntegrationRows(f.d.records)
	aBefore := cloneSystemPendingRow(f.d.row)
	replay, err := f.results.CommitResult(ctx, f.handle, f.resultRequest)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Receipt, receipt) || f.d.writes != writes || !reflect.DeepEqual(before, f.d.records) || !reflect.DeepEqual(aBefore, f.d.row) {
		t.Fatal("historical replay", err)
	}
	f.readReceipt = false
	if out, err := f.results.CommitResult(ctx, f.handle, f.resultRequest); err == nil || !reflect.DeepEqual(out, pd.CommittedResult{}) {
		t.Fatal("unauthorized replay", err)
	}
}

func TestDProducerActualAAdaptersAtomicFailures(t *testing.T) {
	cases := []struct{ stage, failure, reject, dbFailure string }{
		{"pending", "", "", "chunk"}, {"pending", "pending_audit", "", ""}, {"pending", "pending_guard", "", ""},
		{"claim", "claim_guard", "", ""}, {"claim", "", "evidence_cas", ""},
		{"finish", "", "update:system_backup_producer_runs", ""}, {"finish", "finish_chunks", "", ""}, {"finish", "finish_guard", "", ""}, {"finish", "finish_capacity", "", ""},
		{"result", "", "insert:system_backup_producer_result_receipts", ""}, {"result", "result_guard", "", ""}, {"result", "result_chunks", "", ""}, {"result", "result_audit", "", ""}, {"result", "result_capacity", "", ""},
	}
	stages := []string{"pending", "claim", "finish", "result"}
	for _, tc := range cases {
		t.Run(tc.stage+"/"+tc.failure+tc.reject+tc.dbFailure, func(t *testing.T) {
			f := newDIntegrationFixture(t)
			for _, stage := range stages {
				if stage == tc.stage {
					break
				}
				f.advance(stage)
			}
			before := cloneDIntegrationRows(f.d.records)
			row := cloneSystemPendingRow(f.d.row)
			chunks := cloneSystemPendingChunks(f.d.chunks)
			marker := f.d.marker
			commits, rollbacks := f.d.commits, f.d.rollbacks
			f.fail, f.d.reject, f.d.fail = tc.failure, tc.reject, tc.dbFailure
			err := f.step(tc.stage)
			if err == nil || f.d.commits != commits || f.d.rollbacks != rollbacks+1 || !reflect.DeepEqual(before, f.d.records) || !reflect.DeepEqual(row, f.d.row) || !reflect.DeepEqual(chunks, f.d.chunks) || marker != f.d.marker {
				t.Fatal("A/D partial commit", err)
			}
			if tc.stage == "claim" && f.claim != nil {
				t.Fatal("failed claim minted authority")
			}
		})
	}
}

func TestDProducerActualAAdaptersAmbiguousResult(t *testing.T) {
	f := newDIntegrationFixture(t)
	f.advance("pending", "claim", "finish")
	f.d.fail = "commit_unknown"
	out, err := f.results.CommitResult(context.Background(), f.handle, f.resultRequest)
	if !errors.Is(err, pd.ErrCommitUnknown) || !reflect.DeepEqual(out, pd.CommittedResult{}) {
		t.Fatal("ambiguous commit leaked receipt", err)
	}
	// This driver's ambiguous outcome deliberately retains committed rows.
	// No automatic retry: a new independently authorized call reads the receipt.
	f.d.fail = "read_evidence"
	writes := f.d.writes
	out, err = f.results.CommitResult(context.Background(), f.handle, f.resultRequest)
	if err != nil || !out.Replayed || f.d.writes != writes || out.Receipt.ResultVersion != "1" {
		t.Fatal("ambiguous receipt recovery", err)
	}
}
