package systembackupevidence

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// D owns claim/result CAS and opaque handle issuance (covered in its package).
// These tests exercise A's concrete row/chunk reads and final checks through
// D's actual transaction executor, with controlled in-transaction state changes.
type systemClaimTestAuthority struct {
	fail   string
	sample time.Time
}

func (a *systemClaimTestAuthority) PrepareClaimAuthority(context.Context, pd.ClaimRequestBinding, bool, Record) (SystemClaimAuthoritySession, *time.Time, error) {
	if a.fail == "prepare" {
		return nil, nil, ErrDenied
	}
	return a, &a.sample, nil
}
func (a *systemClaimTestAuthority) LockInstallation(context.Context, pd.SQL, pd.ClaimRequestBinding) error {
	return nil
}
func (a *systemClaimTestAuthority) Authenticate(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.DomainRecord, bool) (pd.ClaimAdmission, error) {
	return pd.ClaimAdmission{}, ErrDenied
}
func (a *systemClaimTestAuthority) LockHost(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.GrantRecord) error {
	return nil
}
func (a *systemClaimTestAuthority) LockReferences(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.ClaimFacts) (pd.ReferenceApproval, error) {
	return pd.ReferenceApproval{}, ErrDenied
}
func (a *systemClaimTestAuthority) Reserve(context.Context, pd.SQL, pd.ClaimRequestBinding, uint64) error {
	return nil
}
func (a *systemClaimTestAuthority) Audit(context.Context, pd.SQL, pd.ClaimRequestBinding, string) error {
	return nil
}
func (a *systemClaimTestAuthority) Recheck(context.Context, pd.ReadSQL, pd.ClaimRequestBinding, pd.ClaimFacts, time.Time) error {
	if a.fail == "guard" {
		return ErrDenied
	}
	return nil
}

type systemFinishTestAuthority struct {
	fail   string
	sample time.Time
}

func (a *systemFinishTestAuthority) PrepareFinishAuthority(context.Context, pd.FinishBinding, Record) (SystemFinishAuthoritySession, *time.Time, error) {
	if a.fail == "prepare" {
		return nil, nil, ErrDenied
	}
	return a, &a.sample, nil
}
func (a *systemFinishTestAuthority) LockInstallation(context.Context, pd.SQL, pd.FinishBinding) error {
	return nil
}
func (a *systemFinishTestAuthority) Authenticate(context.Context, pd.SQL, pd.FinishBinding, pd.DomainRecord) (pd.FinishAdmission, error) {
	return pd.FinishAdmission{}, ErrDenied
}
func (a *systemFinishTestAuthority) LockHost(context.Context, pd.SQL, pd.FinishBinding, pd.GrantRecord) error {
	return nil
}
func (a *systemFinishTestAuthority) LockReferences(context.Context, pd.SQL, pd.FinishBinding, pd.FinishFacts) (pd.ReferenceApproval, error) {
	return pd.ReferenceApproval{}, ErrDenied
}
func (a *systemFinishTestAuthority) Reserve(context.Context, pd.SQL, pd.FinishBinding, uint64) error {
	return nil
}
func (a *systemFinishTestAuthority) Audit(context.Context, pd.SQL, pd.FinishBinding, string) error {
	return nil
}
func (a *systemFinishTestAuthority) Recheck(context.Context, pd.ReadSQL, pd.FinishBinding, pd.FinishFacts, time.Time) error {
	if a.fail == "guard" {
		return ErrDenied
	}
	return nil
}

type systemPublicationTestPolicy struct {
	hash   pd.Hash
	until  time.Time
	sample *time.Time
	guard  func(context.Context, pd.ReadSQL, time.Time) error
}

func (p systemPublicationTestPolicy) LockAndAuthorize(context.Context, pd.SQL, pd.Scope) (pd.GuardPlan, error) {
	return pd.GuardPlan{BindingHash: p.hash, Deadlines: []time.Time{p.until}, CapacityObservedAt: p.sample}, nil
}
func (p systemPublicationTestPolicy) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.Scope, _ pd.GuardPlan, now time.Time) error {
	return p.guard(ctx, tx, now)
}

type systemPublicationTestFixture struct {
	*systemPendingTestFixture
	claim  *SystemClaimEnvironment
	finish *SystemFinishEnvironment
	ca     *systemClaimTestAuthority
	fa     *systemFinishTestAuthority
	cb     pd.ClaimRequestBinding
}

func newSystemPublicationTestFixture(t *testing.T) *systemPublicationTestFixture {
	t.Helper()
	f := newSystemPendingTestFixture(t)
	// This transaction only seeds historical committed state for the next
	// operation. A known commit with expired execution permission still left
	// that state in SQL; it grants no permission to call a provider. Keep the
	// production five-second check and reject unknown/uncommitted outcomes.
	seed, e := f.run(t, false, nil)
	if !seed.Committed() || e != nil && e != pd.ErrCommittedExpired {
		t.Fatal(e)
	}
	ca := &systemClaimTestAuthority{sample: f.d.now}
	fa := &systemFinishTestAuthority{sample: f.d.now}
	c, e := NewSystemClaimEnvironment(ca, f.prepared, f.channel, f.b.Request.History)
	if e != nil {
		t.Fatal(e)
	}
	finish, e := NewSystemFinishEnvironment(fa, f.prepared, f.channel, f.b.Request.History)
	if e != nil {
		t.Fatal(e)
	}
	b := pd.ClaimRequestBinding{Scope: f.b.Scope, Subject: f.b.Subject, GrantID: f.b.GrantID, GrantGeneration: f.b.GrantGeneration, GrantVersion: f.b.GrantVersion, RunID: f.b.RunID, Request: pd.ClaimRequest{EvidenceID: f.b.Request.History.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "claim-nonce-12345678", ExpiresAt: systemExecutionStamp(f.d.now.Add(30 * time.Second)), PolicyHash: f.b.Request.PolicyHash, RefsVersionHash: pd.Hash(strings.Repeat("c", 64)), BudgetUntil: f.b.Request.BudgetUntil}}
	return &systemPublicationTestFixture{f, c, finish, ca, fa, b}
}
func (f *systemPublicationTestFixture) claimRun(t *testing.T, readback bool, mutate func(*pd.ClaimFacts)) (pd.CommitReceipt, error) {
	t.Helper()
	ctx := context.Background()
	p, e := f.claim.PrepareClaim(ctx, f.cb, readback)
	if e != nil {
		return pd.CommitReceipt{}, e
	}
	s := p.Session.(*systemClaimSession)
	facts := pd.ClaimFacts{History: f.b.Request.History, Readback: readback}
	h, _ := pd.ClaimRequestHash(f.cb)
	expiry, _ := f.cb.Request.ExpiresAt.Time()
	policy := systemPublicationTestPolicy{hash: h, until: expiry, sample: p.CapacityObservedAt, guard: func(ctx context.Context, tx pd.ReadSQL, now time.Time) error {
		return s.Recheck(ctx, tx, f.cb, facts, now)
	}}
	r, e := pd.NewTransactions(f.db, f.b.Scope, policy)
	if e != nil {
		t.Fatal(e)
	}
	return r.Run(ctx, func(ctx context.Context, tx *pd.Transaction) error {
		v, e := s.LockEvidence(ctx, tx, f.cb, facts)
		if e != nil {
			return e
		}
		facts.Evidence = v
		if !readback {
			owner, until := pd.ID(h), f.cb.Request.ExpiresAt
			facts.Evidence.Evidence.ClaimOwner = &owner
			facts.Evidence.Evidence.ClaimExpiresAt = &until
			facts.Evidence.Evidence.RowVersion = "2"
			f.d.onAudit = func() {
				f.d.row["claim_owner"] = string(h)
				f.d.row["claim_expires_at"] = expiry
				f.d.row["row_version"] = int64(2)
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); e != nil {
				return ErrUnavailable
			}
			f.d.onAudit = nil
		}
		if mutate != nil {
			mutate(&facts)
		}
		return nil
	})
}
func (f *systemPublicationTestFixture) finishBinding(state string) pd.FinishBinding {
	h, _ := pd.ClaimRequestHash(f.cb)
	original := f.b.Request.History.Evidence
	b := pd.FinishBinding{Scope: f.cb.Scope, Subject: f.cb.Subject, GrantID: f.cb.GrantID, GrantGeneration: f.cb.GrantGeneration, GrantVersion: f.cb.GrantVersion, RunID: f.cb.RunID, Claim: pd.ClaimBinding{EvidenceID: f.cb.Request.EvidenceID, EvidenceVersion: "2", ManifestHash: original.ManifestHash, Owner: pd.ID(h), ExpiresAt: f.cb.Request.ExpiresAt, PolicyHash: f.cb.Request.PolicyHash, RefsVersionHash: f.cb.Request.RefsVersionHash}, Request: pd.FinishRequest{State: state, ProofHash: pd.Hash(strings.Repeat("d", 64)), ObjectHash: original.ObjectHash, ObjectBytes: original.ObjectBytes, ObservedAt: systemExecutionStamp(f.d.now), BudgetUntil: f.cb.Request.BudgetUntil}}
	if state == "ready" {
		v := pd.Text("Exact.Version/1")
		b.Request.ImmutableVersion = &v
	}
	return b
}
func (f *systemPublicationTestFixture) finishRun(t *testing.T, state string, mutate func(*pd.FinishFacts)) (pd.CommitReceipt, error) {
	t.Helper()
	ctx := context.Background()
	b := f.finishBinding(state)
	p, e := f.finish.PrepareFinish(ctx, b)
	if e != nil {
		return pd.CommitReceipt{}, e
	}
	s := p.Session.(*systemFinishSession)
	facts := pd.FinishFacts{History: f.b.Request.History}
	h, _ := pd.FinishBindingHash(b)
	expiry, _ := b.Claim.ExpiresAt.Time()
	policy := systemPublicationTestPolicy{hash: h, until: expiry, sample: p.CapacityObservedAt, guard: func(ctx context.Context, tx pd.ReadSQL, now time.Time) error {
		return s.Recheck(ctx, tx, b, facts, now)
	}}
	r, e := pd.NewTransactions(f.db, f.b.Scope, policy)
	if e != nil {
		t.Fatal(e)
	}
	return r.Run(ctx, func(ctx context.Context, tx *pd.Transaction) error {
		v, e := s.LockEvidence(ctx, tx, b, facts)
		if e != nil {
			return e
		}
		facts.Evidence = v
		facts.Evidence.ClaimEvidence.Evidence.State = state
		facts.Evidence.ClaimEvidence.Evidence.RowVersion = "3"
		facts.Evidence.ClaimEvidence.Evidence.ClaimOwner = nil
		facts.Evidence.ClaimEvidence.Evidence.ClaimExpiresAt = nil
		facts.Evidence.Failure = "provider_unavailable"
		if state == "ready" {
			facts.Evidence.Failure = "none"
			facts.Evidence.ImmutableVersion = b.Request.ImmutableVersion
		}
		f.d.onAudit = func() {
			f.d.row["storage_state"] = state
			f.d.row["evidence_failure_code"] = facts.Evidence.Failure
			f.d.row["row_version"] = int64(3)
			f.d.row["claim_owner"] = nil
			f.d.row["claim_expires_at"] = nil
			if state == "ready" {
				f.d.row["storage_immutable_version"] = string(*b.Request.ImmutableVersion)
			}
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); e != nil {
			return ErrUnavailable
		}
		f.d.onAudit = nil
		if mutate != nil {
			mutate(&facts)
		}
		return nil
	})
}

func TestSystemPublicationClaimReadbackAndFinish(t *testing.T) {
	for _, state := range []string{"ready", "write_unknown"} {
		t.Run(state, func(t *testing.T) {
			f := newSystemPublicationTestFixture(t)
			chunks := cloneSystemPendingChunks(f.d.chunks)
			if r, e := f.claimRun(t, false, nil); e != nil || !r.Committed() {
				t.Fatal("claim final check failed", e)
			}
			writes := f.d.writes
			row := cloneSystemPendingRow(f.d.row)
			if r, e := f.claimRun(t, true, nil); e != nil || !r.Committed() || f.d.writes != writes || !reflect.DeepEqual(row, f.d.row) {
				t.Fatal("readback changed original", e)
			}
			if r, e := f.finishRun(t, state, nil); e != nil || !r.Committed() {
				t.Fatal("finish final check failed", e)
			}
			if f.d.row["storage_state"] != state || f.d.row["claim_owner"] != nil || f.d.row["row_version"] != int64(3) || f.d.row["observed_health"] != "unknown" || !reflect.DeepEqual(chunks, f.d.chunks) {
				t.Fatal("unexpected metadata update")
			}
			if state == "ready" {
				if f.d.row["storage_immutable_version"] != "Exact.Version/1" {
					t.Fatal("version changed")
				}
				if r, e := f.systemPendingTestFixture.run(t, true, nil); e == nil || r.Committed() {
					t.Fatal("ready evidence accepted by pending loader")
				}
			} else if f.d.row["storage_immutable_version"] != nil {
				t.Fatal("unknown evidence acquired a version")
			}
		})
	}
}

func TestSystemPublicationClaimFinalGuard(t *testing.T) {
	for _, mode := range []string{"owner", "expiry", "version", "health", "content", "chunk", "history", "reported_fact", "revoked", "capacity", "read_error", "readback_mode"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPublicationTestFixture(t)
			before := cloneSystemPendingRow(f.d.row)
			chunks := cloneSystemPendingChunks(f.d.chunks)
			mutated := false
			r, e := f.claimRun(t, false, func(facts *pd.ClaimFacts) {
				mutated = true
				switch mode {
				case "owner":
					f.d.row["claim_owner"] = "other"
				case "expiry":
					f.d.row["claim_expires_at"] = f.d.now.Add(time.Hour)
				case "version":
					f.d.row["row_version"] = int64(4)
				case "health":
					f.d.row["observed_health"] = "healthy"
				case "content":
					f.d.row["content_checksum"] = strings.Repeat("f", 64)
				case "chunk":
					f.d.chunks[0]["gcm_tag"] = []byte("different")
				case "history":
					facts.History.InputHash = pd.Hash(strings.Repeat("f", 64))
				case "reported_fact":
					facts.Evidence.Evidence.State = "ready"
				case "revoked":
					f.ca.fail = "guard"
				case "capacity":
					f.d.now = f.d.now.Add(6 * time.Second)
				case "read_error":
					f.d.fail = "read_chunks"
				case "readback_mode":
					facts.Readback = true
				}
			})
			if !mutated || e == nil || r.Committed() || !reflect.DeepEqual(before, f.d.row) || !reflect.DeepEqual(chunks, f.d.chunks) {
				t.Fatal("claim guard allowed drift or partial commit", e)
			}
		})
	}
}

func TestSystemPublicationFinishFinalGuard(t *testing.T) {
	for _, mode := range []string{"wrong_version", "missing_version", "claim_not_cleared", "row_version", "health", "next_reconcile", "content", "chunk", "retention", "reported_fact", "revoked", "capacity", "read_error", "wrong_failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPublicationTestFixture(t)
			if _, e := f.claimRun(t, false, nil); e != nil {
				t.Fatal(e)
			}
			before := cloneSystemPendingRow(f.d.row)
			chunks := cloneSystemPendingChunks(f.d.chunks)
			r, e := f.finishRun(t, "ready", func(facts *pd.FinishFacts) {
				switch mode {
				case "wrong_version":
					f.d.row["storage_immutable_version"] = "exact.version/1"
				case "missing_version":
					f.d.row["storage_immutable_version"] = nil
				case "claim_not_cleared":
					f.d.row["claim_owner"] = before["claim_owner"]
					f.d.row["claim_expires_at"] = before["claim_expires_at"]
				case "row_version":
					f.d.row["row_version"] = int64(4)
				case "health":
					f.d.row["observed_health"] = "healthy"
				case "next_reconcile":
					f.d.row["next_reconcile_at"] = f.d.now.Add(time.Minute)
				case "content":
					f.d.row["object_checksum"] = strings.Repeat("f", 64)
				case "chunk":
					f.d.chunks[0]["gcm_nonce"] = []byte("changed")
				case "retention":
					f.d.row["protected_until"] = f.d.now
				case "reported_fact":
					facts.Evidence.Failure = "provider_unavailable"
				case "revoked":
					f.fa.fail = "guard"
				case "capacity":
					f.d.now = f.d.now.Add(6 * time.Second)
				case "read_error":
					f.d.fail = "read_evidence"
				case "wrong_failure":
					f.d.row["evidence_failure_code"] = "provider_unavailable"
				}
			})
			if e == nil || r.Committed() || !reflect.DeepEqual(before, f.d.row) || !reflect.DeepEqual(chunks, f.d.chunks) {
				t.Fatal("finish guard allowed drift or partial commit", e)
			}
		})
	}
}

func TestSystemPublicationConstructorAndReadBoundaries(t *testing.T) {
	f := newSystemPublicationTestFixture(t)
	h := f.b.Request.History
	if _, e := NewSystemClaimEnvironment(nil, f.prepared, f.channel, h); e == nil {
		t.Fatal("nil claim authority")
	}
	if _, e := NewSystemFinishEnvironment(nil, f.prepared, f.channel, h); e == nil {
		t.Fatal("nil finish authority")
	}
	if _, e := NewSystemClaimEnvironment(f.ca, Prepared{}, f.channel, h); e == nil {
		t.Fatal("forged preparation")
	}
	if _, e := NewSystemFinishEnvironment(f.fa, Prepared{}, f.channel, h); e == nil {
		t.Fatal("forged preparation")
	}
	for _, mode := range []string{"scope", "evidence", "invalid_version", "prepare_denied", "nil_context"} {
		t.Run(mode, func(t *testing.T) {
			g := newSystemPublicationTestFixture(t)
			b := g.cb
			ctx := context.Background()
			switch mode {
			case "scope":
				b.Scope.Database = "other"
			case "evidence":
				b.Request.EvidenceID = "sev_aaaaaaaa-2222-4333-8444-555555555555"
			case "invalid_version":
				b.Request.ExpectedEvidenceVersion = "9223372036854775807"
			case "prepare_denied":
				g.ca.fail = "prepare"
			case "nil_context":
				ctx = nil
			}
			if _, e := g.claim.PrepareClaim(ctx, b, false); e == nil {
				t.Fatal("invalid claim admitted")
			}
		})
	}
	if _, e := f.claimRun(t, true, nil); e == nil {
		t.Fatal("readback manufactured uncommitted claim")
	}
	if _, e := f.claimRun(t, false, nil); e != nil {
		t.Fatal(e)
	}
	f.cb.Request.Nonce = "other_nonce"
	if _, e := f.claimRun(t, true, nil); e == nil {
		t.Fatal("changed request read back claim")
	}
}
