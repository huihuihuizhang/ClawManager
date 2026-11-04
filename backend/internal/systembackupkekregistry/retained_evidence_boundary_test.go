package systembackupkekregistry

import (
	"bytes"
	"context"
	"testing"
)

func retainedEvidenceBoundaryBinding() Binding {
	b := bindingReadFixture()
	b.Key.Provider = RetainedEvidenceProvider
	b.GenerateRef = TypedReference{}
	b.UnwrapRef = TypedReference{}
	b.Retention = &RetainedEvidenceSource{Purpose: RetainedEvidencePurpose, Source: b.Provider.CASource, KeyContextSHA256: b.Provider.ScopeHash}
	return b
}

func TestRetentionOnlyBindingPreservesLegacyWireAndRejectsPurposeConfusion(t *testing.T) {
	legacy := bindingReadFixture()
	raw, _, e := hashJSON(legacy)
	if e != nil || bytes.Contains(raw, []byte("Retention")) {
		t.Fatal("changed legacy executable binding wire")
	}
	b := retainedEvidenceBoundaryBinding()
	if !validRetainedEvidenceBinding(b) {
		t.Fatal("retention binding shape")
	}
	if _, e := semanticCoreHash(b); e != nil {
		t.Fatal("retention-only metadata cannot be read in coverage", e)
	}
	copy := cloneBinding(b)
	copy.Retention.KeyContextSHA256 = "changed"
	if copy.Retention.KeyContextSHA256 == b.Retention.KeyContextSHA256 {
		t.Fatal("retained source alias")
	}
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{
		{"generate_ref", func(b *Binding) { b.GenerateRef = legacy.GenerateRef }},
		{"unwrap_ref", func(b *Binding) { b.UnwrapRef = legacy.UnwrapRef }},
		{"backup_provider_alias", func(b *Binding) { b.Key.Provider = legacy.Key.Provider }},
		{"wrong_context", func(b *Binding) { b.Retention.KeyContextSHA256 = "changed" }},
		{"unknown_purpose", func(b *Binding) { b.Retention.Purpose = "capture" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := cloneBinding(b)
			tc.change(&bad)
			if _, e := semanticCoreHash(bad); e == nil {
				t.Fatal("retention/execution confusion accepted")
			}
		})
	}
	for _, purpose := range []RevocationPurpose{GenerateRevocation, UnwrapRevocation} {
		bound := &Bound{epoch: 1, original: Snapshot{Epoch: 1, Bindings: []BindingFacts{{Binding: b}}}}
		if bound.RequireUnrevoked(b.ConfigRef, purpose) == nil {
			t.Fatal("retained key granted execution", purpose)
		}
	}
}

type retainedNoSQL struct{ SQLWriteView }
type retainedReferenceAttempt struct {
	PreparedReferenceChange
	r Reference
}

func (p retainedReferenceAttempt) Reference() Reference { return p.r }
func (retainedReferenceAttempt) ExpectedEpoch() uint64  { return 1 }

type retainedAdmissionAttempt struct {
	PreparedAdmission
	b Binding
}

func (p retainedAdmissionAttempt) Binding() Binding { return p.b }
func (retainedAdmissionAttempt) OriginalMapping() PreparedMappingSource {
	return retainedMappingAttempt{}
}

type retainedMappingAttempt struct{ PreparedMappingSource }

func TestRetentionOnlyCannotEnterExecutableAdmissionOrPlannedUnknownPath(t *testing.T) {
	binding := retainedEvidenceBoundaryBinding()
	b := &Bound{tx: retainedNoSQL{}, epoch: 1, original: Snapshot{Epoch: 1, Bindings: []BindingFacts{{Binding: binding}}}}
	if b.StageAdmission(context.Background(), "original-operation", 1, retainedAdmissionAttempt{b: binding}) == nil {
		t.Fatal("retained key promoted to executable admission")
	}
	for _, state := range []ReferenceState{ReferencePlanned, ReferenceUnknown} {
		p := retainedReferenceAttempt{r: Reference{Key: binding.Key, State: state}}
		if state == ReferencePlanned {
			if b.RetainPlanned(context.Background(), p) == nil {
				t.Fatal("planned key use accepted")
			}
		} else if b.MarkUnknown(context.Background(), p) == nil {
			t.Fatal("unknown provider use accepted")
		}
	}
}
