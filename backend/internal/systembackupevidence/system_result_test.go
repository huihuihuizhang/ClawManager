package systembackupevidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Only the A adapter and D transaction executor are under test here. Synthetic
// authority never authenticates a real D lifecycle/result command successfully.
type systemResultTestAuthority struct {
	fail    string
	sample  time.Time
	checks  int
	prepare func(pd.ResultBinding, Record)
}

func (a *systemResultTestAuthority) PrepareResultAuthority(_ context.Context, b pd.ResultBinding, r Record) (SystemResultAuthoritySession, *time.Time, error) {
	if a.fail == "prepare" {
		return nil, nil, ErrDenied
	}
	if a.prepare != nil {
		a.prepare(b, r)
	}
	return a, &a.sample, nil
}
func (*systemResultTestAuthority) LockInstallation(context.Context, pd.SQL, pd.ResultBinding) error {
	return nil
}
func (*systemResultTestAuthority) Authenticate(context.Context, pd.SQL, pd.ResultBinding, pd.DomainRecord) (pd.ResultAdmission, error) {
	return pd.ResultAdmission{}, ErrDenied
}
func (*systemResultTestAuthority) LockHost(context.Context, pd.SQL, pd.ResultBinding, pd.GrantRecord) error {
	return nil
}
func (*systemResultTestAuthority) LockProjectionReferences(context.Context, pd.SQL, pd.ResultBinding, pd.ResultFacts) (pd.ResultProjection, error) {
	return pd.ResultProjection{}, ErrDenied
}
func (*systemResultTestAuthority) Reserve(context.Context, pd.SQL, pd.ResultBinding, uint64) error {
	return nil
}
func (*systemResultTestAuthority) Audit(context.Context, pd.SQL, pd.ResultBinding, string) error {
	return nil
}
func (*systemResultTestAuthority) ApplyProjections(context.Context, pd.SQL, pd.ResultBinding, pd.ResultFacts) error {
	return ErrDenied
}
func (a *systemResultTestAuthority) Recheck(context.Context, pd.ReadSQL, pd.ResultBinding, pd.ResultFacts, time.Time) error {
	a.checks++
	if a.fail == "guard" {
		return ErrDenied
	}
	return nil
}

type systemResultTestFixture struct {
	*systemPublicationTestFixture
	env *SystemResultEnvironment
	a   *systemResultTestAuthority
	rb  pd.ResultBinding
}

func newSystemResultTestFixture(t *testing.T) *systemResultTestFixture {
	t.Helper()
	f := newSystemPublicationTestFixture(t)
	if _, err := f.claimRun(t, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.finishRun(t, "ready", nil); err != nil {
		t.Fatal(err)
	}
	a := &systemResultTestAuthority{sample: f.d.now}
	env, err := NewSystemResultEnvironment(a, f.prepared, f.channel, f.b.Request.History)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "producer-authority-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ID    string
			Value json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var r pd.ResultRequest
	for _, v := range vectors.Positive {
		if v.ID == "unconfigured_artifact" {
			if err := pd.DecodeRecord(v.Value, &r); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	h := f.b.Request.History
	r.Scope, r.GrantID, r.GrantGeneration, r.RunID, r.DomainEpoch, r.Admission = h.Scope, h.GrantID, h.GrantGeneration, h.RunID, h.DomainEpoch, h.Admission
	r.InputHash, r.ObservedAt, r.ObservationExpiresAt = h.InputHash, h.ObservedAt, h.ObservationExpiresAt
	r.Evidence = h.Evidence
	v := pd.Text("Exact.Version/1")
	r.Evidence.ImmutableVersion = &v
	r.ExpectedEvidenceVersion = "3"
	return &systemResultTestFixture{f, env, a, pd.ResultBinding{Subject: f.b.Subject, GrantVersion: f.b.GrantVersion, Request: r}}
}
func (f *systemResultTestFixture) facts(t *testing.T, replay bool) pd.ResultFacts {
	t.Helper()
	d, err := pd.ResultHashes(f.rb.Request)
	if err != nil {
		t.Fatal(err)
	}
	h := f.b.Request.History
	r := pd.ReceiptRecord{Scope: h.Scope, ReceiptKeyHash: d.Key, RequestHash: d.Request, Request: f.rb.Request, ResultVersion: "1", CommittedAt: systemExecutionStamp(f.d.now), RetentionExpiresAt: h.RetentionExpiresAt, ChargedBytes: "1"}
	facts := pd.ResultFacts{Receipt: &r, Replayed: replay, Admission: pd.ResultAdmission{ReadReceipt: true}}
	if !replay {
		facts.History = &h
	}
	return facts
}
func (f *systemResultTestFixture) runResult(t *testing.T, replay bool, mutate func(*pd.ResultFacts)) (pd.CommitReceipt, error) {
	t.Helper()
	ctx := context.Background()
	p, err := f.env.PrepareResult(ctx, f.rb)
	if err != nil {
		return pd.CommitReceipt{}, err
	}
	s := p.Session.(*systemResultSession)
	facts := f.facts(t, replay)
	hash, _ := pd.ResultBindingHash(f.rb)
	policy := systemPublicationTestPolicy{hash: hash, until: f.d.now.Add(time.Minute), guard: func(ctx context.Context, tx pd.ReadSQL, now time.Time) error {
		return s.Recheck(ctx, tx, f.rb, facts, now)
	}}
	if !replay {
		policy.sample = p.CapacityObservedAt
	}
	runner, err := pd.NewTransactions(f.db, f.rb.Request.Scope, policy)
	if err != nil {
		t.Fatal(err)
	}
	return runner.Run(ctx, func(ctx context.Context, tx *pd.Transaction) error {
		if !replay {
			evidence, err := s.LockEvidence(ctx, tx, f.rb, facts)
			if err != nil {
				return err
			}
			facts.Evidence = &evidence
			if _, err := tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); err != nil {
				return ErrUnavailable
			}
		}
		if mutate != nil {
			mutate(&facts)
		}
		return nil
	})
}

func TestSystemResultReadyAndReceiptReplay(t *testing.T) {
	f := newSystemResultTestFixture(t)
	row, chunks := cloneSystemPendingRow(f.d.row), cloneSystemPendingChunks(f.d.chunks)
	if out, err := f.runResult(t, false, nil); err != nil || !out.Committed() {
		t.Fatal(out, err)
	}
	if !reflect.DeepEqual(row, f.d.row) || !reflect.DeepEqual(chunks, f.d.chunks) || f.a.checks != 1 {
		t.Fatal("result changed evidence or omitted authority")
	}
	// Independent receipt authorization can return history without the evidence
	// still being present. No A query, write, or capacity sample is needed.
	f.d.row, f.d.chunks = nil, nil
	f.d.fail = "read_evidence"
	f.a.sample = f.d.now.Add(-time.Hour)
	writes, events := f.d.writes, len(f.d.events)
	if out, err := f.runResult(t, true, nil); err != nil || !out.Committed() {
		t.Fatal(out, err)
	}
	if f.d.writes != writes || f.a.checks != 2 {
		t.Fatal("receipt replay wrote or bypassed authority")
	}
	for _, event := range f.d.events[events:] {
		if strings.Contains(event, "evidence") || strings.Contains(event, "chunk") {
			t.Fatal("replay loaded evidence", event)
		}
	}
}

func TestSystemResultLockedEvidenceRejects(t *testing.T) {
	for _, name := range []string{"missing", "pending", "unknown", "failure", "claimed", "version", "object_version", "content", "chunk", "extra_chunk", "retention", "read_error"} {
		t.Run(name, func(t *testing.T) {
			f := newSystemResultTestFixture(t)
			switch name {
			case "missing":
				f.d.row = nil
			case "pending":
				f.d.row["storage_state"], f.d.row["storage_immutable_version"] = "pending", nil
			case "unknown":
				f.d.row["storage_state"], f.d.row["evidence_failure_code"], f.d.row["storage_immutable_version"] = "write_unknown", "provider_unavailable", nil
			case "failure":
				f.d.row["evidence_failure_code"] = "provider_unavailable"
			case "claimed":
				f.d.row["claim_owner"], f.d.row["claim_expires_at"] = "gc-owner", f.d.now.Add(time.Minute)
			case "version":
				f.d.row["row_version"] = int64(4)
			case "object_version":
				f.d.row["storage_immutable_version"] = "exact.Version/1"
			case "content":
				f.d.row["content_checksum"] = strings.Repeat("f", 64)
			case "chunk":
				f.d.chunks[0]["gcm_tag"] = []byte("wrong")
			case "extra_chunk":
				f.d.chunks = append(f.d.chunks, cloneSystemPendingRow(f.d.chunks[0]))
			case "retention":
				f.d.row["protected_until"] = f.d.now
			case "read_error":
				f.d.fail = "read_evidence"
			}
			marker := f.d.marker
			if out, err := f.runResult(t, false, nil); err == nil || out.Committed() {
				t.Fatal("accepted", name)
			}
			if f.d.marker != marker {
				t.Fatal("wrote before rejected evidence")
			}
		})
	}
}

func TestSystemResultFinalGuardRollback(t *testing.T) {
	for _, name := range []string{"health", "reconcile", "claim", "state", "version", "object_version", "content", "chunk", "retention", "history", "reported_fact", "receipt_hash", "receipt_request", "receipt_retention", "replayed", "revoked", "capacity", "read_error", "audit"} {
		t.Run(name, func(t *testing.T) {
			f := newSystemResultTestFixture(t)
			row, chunks, marker := cloneSystemPendingRow(f.d.row), cloneSystemPendingChunks(f.d.chunks), f.d.marker
			if name == "audit" {
				f.d.fail = "audit"
			}
			out, err := f.runResult(t, false, func(facts *pd.ResultFacts) {
				switch name {
				case "health":
					f.d.row["observed_health"] = "healthy"
				case "reconcile":
					f.d.row["next_reconcile_at"] = f.d.now
				case "claim":
					f.d.row["claim_owner"], f.d.row["claim_expires_at"] = "other", f.d.now.Add(time.Minute)
				case "state":
					f.d.row["storage_state"] = "write_unknown"
				case "version":
					f.d.row["row_version"] = int64(4)
				case "object_version":
					f.d.row["storage_immutable_version"] = "other"
				case "content":
					f.d.row["object_checksum"] = strings.Repeat("f", 64)
				case "chunk":
					f.d.chunks[0]["gcm_nonce"] = []byte("wrong")
				case "retention":
					f.d.row["expires_at"] = f.d.now
				case "history":
					facts.History.InputHash = pd.Hash(strings.Repeat("f", 64))
				case "reported_fact":
					facts.Evidence.RowVersion = "4"
				case "receipt_hash":
					facts.Receipt.RequestHash = pd.Hash(strings.Repeat("f", 64))
				case "receipt_request":
					facts.Receipt.Request.RequestKey = "other-request-0001"
				case "receipt_retention":
					facts.Receipt.RetentionExpiresAt = systemExecutionStamp(f.d.now.Add(48 * time.Hour))
				case "replayed":
					facts.Replayed = true
				case "revoked":
					f.a.fail = "guard"
				case "capacity":
					f.d.now = f.d.now.Add(6 * time.Second)
				case "read_error":
					f.d.fail = "read_evidence"
				}
			})
			if err == nil || out.Committed() {
				t.Fatal("accepted", name)
			}
			if strings.Contains(err.Error(), "synthetic private") {
				t.Fatal("leaked driver failure")
			}
			if !reflect.DeepEqual(row, f.d.row) || !reflect.DeepEqual(chunks, f.d.chunks) || marker != f.d.marker {
				t.Fatal("partial commit", name)
			}
		})
	}
}

func TestSystemResultRequestAndReplayBoundaries(t *testing.T) {
	for _, name := range []string{"scope", "manifest", "write_profile", "nil_version", "empty_version", "null_version", "unicode_version", "nil_context", "prepare"} {
		t.Run(name, func(t *testing.T) {
			f := newSystemResultTestFixture(t)
			ctx := context.Background()
			switch name {
			case "scope":
				f.rb.Request.Scope.Installation = "another_installation"
			case "manifest":
				f.rb.Request.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
			case "write_profile":
				f.rb.Request.Evidence.WriteRefVersion = "v9"
			case "nil_version":
				f.rb.Request.Evidence.ImmutableVersion = nil
			case "empty_version":
				*f.rb.Request.Evidence.ImmutableVersion = ""
			case "null_version":
				*f.rb.Request.Evidence.ImmutableVersion = "null"
			case "unicode_version":
				*f.rb.Request.Evidence.ImmutableVersion = "版本"
			case "nil_context":
				ctx = nil
			case "prepare":
				f.a.fail = "prepare"
			}
			if _, err := f.env.PrepareResult(ctx, f.rb); err == nil {
				t.Fatal("accepted", name)
			}
		})
	}
	for _, name := range []string{"no_permission", "revoked", "changed_request", "execution_facts", "receipt_missing"} {
		t.Run("replay_"+name, func(t *testing.T) {
			f := newSystemResultTestFixture(t)
			if out, err := f.runResult(t, true, func(facts *pd.ResultFacts) {
				switch name {
				case "no_permission":
					facts.Admission.ReadReceipt = false
				case "revoked":
					f.a.fail = "guard"
				case "changed_request":
					f.rb.Request.RequestKey = "changed-request-0001"
				case "execution_facts":
					h := f.b.Request.History
					facts.History = &h
				case "receipt_missing":
					facts.Receipt = nil
				}
			}); err == nil || out.Committed() {
				t.Fatal("accepted", name)
			}
		})
	}
}

func TestSystemResultCopiesAuthorityInputs(t *testing.T) {
	f := newSystemResultTestFixture(t)
	before := string(canonical(f.rb))
	f.a.prepare = func(b pd.ResultBinding, r Record) {
		*b.Request.Evidence.ImmutableVersion = "other"
		b.Request.Target.ResultSlots[0] = "other"
		b.Request.Results.Provider.Observations[0].Reason = "other"
		r.Manifest.Chunks[0].CipherHash = strings.Repeat("f", 64)
	}
	p, err := f.env.PrepareResult(context.Background(), f.rb)
	if err != nil {
		t.Fatal(err)
	}
	f.a.sample = f.a.sample.Add(time.Hour)
	if before != string(canonical(f.rb)) || p.CapacityObservedAt.Equal(f.a.sample) {
		t.Fatal("authority changed caller or sample")
	}
	f.a.prepare = nil
	f.a.sample = f.d.now
	if out, err := f.runResult(t, false, nil); err != nil || !out.Committed() {
		t.Fatal("authority changed original manifest", err)
	}
	if _, err := NewSystemResultEnvironment(nil, f.prepared, f.channel, f.b.Request.History); err == nil {
		t.Fatal("nil authority")
	}
	if _, err := NewSystemResultEnvironment(f.a, Prepared{}, f.channel, f.b.Request.History); err == nil {
		t.Fatal("zero preparation")
	}
}
