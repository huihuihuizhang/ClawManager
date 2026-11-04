package systembackupevidence

import (
	"context"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Real TLS/SigV4 HEAD + original STS protocol fixture and mocked D snapshots.
// These are not assertions of real MinIO/D/MySQL native integration.
func nativePublicationVerifierFixture(t *testing.T, mode string) (*systemPublishFixture, *NativeSystemPublicationVerifier, SystemPublicationProofRequest) {
	t.Helper()
	f := newSystemPublishFixture(t, mode)
	store, e := NewS3Store(f.x.c.STS.Store, f.x.s, downloadNoAbsence{})
	if e != nil {
		t.Fatal(e)
	}
	v := &NativeSystemPublicationVerifier{sts: f.x.s, store: store}
	v.origin = v
	t.Cleanup(v.Close)
	s := f.x.s
	r := s.original.record
	q := SystemPublicationProofRequest{Scope: s.original.scope, RunID: s.original.runID, Claim: *s.views[0].Binding.Claim, PolicyHash: s.policy, ProviderProfileHash: s.c.ProviderProfileHash, ManifestHash: string(s.c.History.Evidence.ManifestHash), Ref: r.Ref, Expected: ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}, Observed: ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize, Version: "Exact-Version-1"}, Observation: "match", Challenge: strings.Repeat("a", 64), Deadline: s.until}
	return f, v, q
}

func TestNativeSystemPublicationVerifierRequiresIndependentNativeRead(t *testing.T) {
	for _, mode := range []string{"existing", "mismatch", "unknown", "revoke_stat"} {
		t.Run(mode, func(t *testing.T) {
			f, v, q := nativePublicationVerifierFixture(t, mode)
			ctx, cancel := context.WithDeadline(context.Background(), q.Deadline)
			defer cancel()
			p, e := v.VerifySystemPublication(ctx, q)
			heads, puts := f.counts()
			if heads != 1 || puts != 0 {
				t.Fatal("independent verifier must perform one native HEAD and no PUT", heads, puts)
			}
			if mode == "existing" {
				if e != nil || p.State != "ready" || p.Object != q.Observed || !digestPattern.MatchString(p.ProofHash) || p.ExpiresAt.After(q.Deadline) {
					t.Fatal("genuine readback rejected", e)
				}
			} else if e == nil {
				t.Fatal("failed/drifted/revoked read minted proof")
			}
			if _, e := v.VerifySystemPublication(ctx, q); e == nil {
				t.Fatal("reused readback attempt")
			}
		})
	}
}

func TestNativeSystemPublicationVerifierRejectsCallerProofInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*SystemPublicationProofRequest)
	}{
		{"wrong_claim", func(q *SystemPublicationProofRequest) { q.Claim.Owner = "wrong-owner" }},
		{"wrong_installation", func(q *SystemPublicationProofRequest) { q.Scope.Installation = "installation_other" }},
		{"wrong_ref", func(q *SystemPublicationProofRequest) { q.Ref.RelativeKey += "-other" }},
		{"wrong_manifest", func(q *SystemPublicationProofRequest) { q.ManifestHash = strings.Repeat("e", 64) }},
		{"wrong_profile", func(q *SystemPublicationProofRequest) { q.ProviderProfileHash = strings.Repeat("e", 64) }},
		{"extended_deadline", func(q *SystemPublicationProofRequest) { q.Deadline = q.Deadline.Add(time.Second) }},
		{"caller_ready_unavailable", func(q *SystemPublicationProofRequest) { q.Observation = "unavailable" }},
		{"wrong_immutable_version", func(q *SystemPublicationProofRequest) { q.Observed.Version = "other-version" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v, q := nativePublicationVerifierFixture(t, "existing")
			tc.change(&q)
			if _, e := v.VerifySystemPublication(context.Background(), q); e == nil {
				t.Fatal("caller input used as native proof")
			}
		})
	}
	if _, e := NewVerifiedSystemPublisher(context.Background(), nil, nil, nil, Prepared{}, SystemSTSPolicy{}, nil, nil, nil); e == nil {
		t.Fatal("missing genuine original sources accepted")
	}
}

func TestNativeSystemPublicationFinishBindsOnlyOriginalRetainedProof(t *testing.T) {
	f, v, q := nativePublicationVerifierFixture(t, "existing")
	ctx, cancel := context.WithDeadline(context.Background(), q.Deadline)
	defer cancel()
	p, e := v.VerifySystemPublication(ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	original := v.sts.views[0].Binding
	version := pd.Text(p.Object.Version)
	b := pd.FinishBinding{Scope: q.Scope, Subject: original.Subject, GrantID: original.GrantID, GrantGeneration: original.GrantGeneration, GrantVersion: original.GrantVersion, RunID: q.RunID, Claim: q.Claim, Request: pd.FinishRequest{State: p.State, ProofHash: pd.Hash(p.ProofHash), ObjectHash: pd.Hash(p.Object.SHA256), ObjectBytes: pd.Counter(systemPendingCounter(p.Object.Size)), ImmutableVersion: &version, ObservedAt: systemPublicationTimestamp(p.ObservedAt), BudgetUntil: systemPublicationTimestamp(p.ExpiresAt)}}
	r := v.sts.original.copyRecord()
	a := &nativePublicationFinishAuthority{verifier: v, original: &systemFinishTestAuthority{sample: time.Now()}}
	bad := b
	bad.Request.ProofHash = pd.Hash(strings.Repeat("f", 64))
	if _, _, e := a.PrepareFinishAuthority(ctx, bad, r); e == nil {
		t.Fatal("self hash accepted")
	}
	other, stop := context.WithCancel(ctx)
	defer stop()
	if _, _, e := a.PrepareFinishAuthority(other, b, r); e == nil {
		t.Fatal("other context accepted")
	}
	wrong := r
	wrong.Manifest.ObjectHash = strings.Repeat("f", 64)
	if _, _, e := a.PrepareFinishAuthority(ctx, b, wrong); e == nil {
		t.Fatal("other original manifest accepted")
	}
	s, _, e := a.PrepareFinishAuthority(ctx, b, r)
	if e != nil || s == nil {
		t.Fatal("retained native proof rejected", e)
	}
	if _, _, e := a.PrepareFinishAuthority(ctx, b, r); e == nil {
		t.Fatal("proof bound twice")
	}
	if e := s.LockInstallation(ctx, nil, b); e == nil {
		t.Fatal("non-original transaction accepted")
	}
	f.x.calls.revoked.Store(true) // Current authority still belongs to D, not this proof.
	v.Close()
	if v.matchesFinish(ctx, b, r, time.Now()) {
		t.Fatal("closed verifier remained current")
	}
}
