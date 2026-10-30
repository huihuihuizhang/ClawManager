package systembackupkekadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	c "clawreef/internal/systembackupkekcandidate"
	r "clawreef/internal/systembackupkekregistry"
	w "clawreef/internal/systembackupwire"
)

type candidateCoverageFixture struct{}

func (candidateCoverageFixture) Sources() []r.CoverageSource { return nil }
func (candidateCoverageFixture) References() []r.Reference   { return nil }
func (candidateCoverageFixture) ExpectedEpoch() uint64       { return 0 }
func (candidateCoverageFixture) ValidUntil() time.Time       { return time.Time{} }
func (candidateCoverageFixture) Recheck(context.Context, r.SQLReadView, r.LockedSnapshot, time.Time) error {
	return ErrCandidate
}

func candidateFixture(t *testing.T) (r.AdmissionInput, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "systembackupkekcandidate", "testdata", "mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.DecodeMapping(raw)
	if err != nil {
		t.Fatal(err)
	}
	v := m.Input()
	ref := func(x c.KMSReference) r.TypedReference {
		b, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		return r.TypedReference{RawJSON: b, SHA256: hex.EncodeToString(h[:])}
	}
	source := func(x c.SourceRecord) r.SourceRecord {
		return r.SourceRecord{SourceID: x.SourceID, RecordID: x.RecordID, RecordVersion: x.RecordVersion, ContentSHA256: x.ContentSHA256}
	}
	now := time.Now().UTC()
	b := r.Binding{InstallationID: v.InstallationID, ConfigRef: r.ReferencePin{IdentityHash: v.ConfigRef.IdentityHash, Version: v.ConfigRef.Version},
		Key:         w.KeyBinding{Provider: v.KeyBinding.Provider, IdentityHash: v.KeyBinding.IdentityHash, RegistryVersion: v.KeyBinding.RegistryVersion, ProviderKeyID: v.KeyBinding.ProviderKeyID, ProviderVersion: v.KeyBinding.ProviderVersion},
		Provider:    r.ProviderBinding{Endpoint: v.Provider.Endpoint, KeyName: v.Provider.KeyName, ProviderIdentityHash: v.Provider.ProviderIdentityHash, ScopeHash: v.Provider.ScopeHash, CAPEMSHA256: v.Provider.CAPEMSHA256, CASource: source(v.Provider.CASource)},
		GenerateRef: ref(v.GenerateRef), UnwrapRef: ref(v.UnwrapRef)}
	adopt := source(v.Provider.CASource)
	coverage := []r.CoverageSource{}
	for _, partition := range []r.Partition{r.RetainedArtifacts, r.InflightAndUnknownWrites, r.HoldsAndCatalog, r.RestoreAndPrune} {
		coverage = append(coverage, r.CoverageSource{Partition: partition, SourceID: "original-source", SnapshotRevision: "source-r1", FenceRevision: "fence-r1", AdoptionSource: adopt})
	}
	return r.AdmissionInput{Candidate: b, Observation: r.AdmissionObservation{InstallationID: v.InstallationID, ConfigSHA256: v.ConfigSHA256, SourceRevision: v.SourceRevision, MappingSource: adopt, GenerateCapabilitySource: adopt, UnwrapCapabilitySource: adopt, NotBefore: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)},
		Snapshot: r.Snapshot{Database: r.DatabaseIdentity{ServerUUID: "synthetic-server", Database: "synthetic-db"}, InstallationID: v.InstallationID, Epoch: 7, ObservedAt: now, Coverage: coverage, Bindings: []r.BindingFacts{}, References: []r.Reference{}}, Coverage: candidateCoverageFixture{}}, now
}

func TestCandidateRejectsChangedPurposeVersionAndIncompleteHistory(t *testing.T) {
	base, now := candidateFixture(t)
	if err := CheckUnadmittedInput(base, now); err != nil {
		t.Fatalf("structurally valid candidate: %v", err)
	}
	cases := map[string]func(*r.AdmissionInput){
		"cross-installation": func(v *r.AdmissionInput) { v.Observation.InstallationID = "other" },
		"mutable-version": func(v *r.AdmissionInput) {
			v.Candidate.ConfigRef.Version = "latest"
			v.Candidate.Key.RegistryVersion = "latest"
		},
		"invalid-provider-version": func(v *r.AdmissionInput) { v.Candidate.Key.ProviderVersion = "latest" },
		"provider-redirect-path":   func(v *r.AdmissionInput) { v.Candidate.Provider.Endpoint = "https://provider.invalid/other" },
		"provider-empty-query":     func(v *r.AdmissionInput) { v.Candidate.Provider.Endpoint = "https://provider.invalid?" },
		"provider-empty-fragment":  func(v *r.AdmissionInput) { v.Candidate.Provider.Endpoint = "https://provider.invalid#" },
		"wrong-purpose":            func(v *r.AdmissionInput) { v.Candidate.GenerateRef = v.Candidate.UnwrapRef },
		"changed-ref-bytes": func(v *r.AdmissionInput) {
			v.Candidate.GenerateRef.RawJSON = append([]byte(nil), v.Candidate.GenerateRef.RawJSON...)
			v.Candidate.GenerateRef.RawJSON[0] = '['
		},
		"expired": func(v *r.AdmissionInput) { v.Observation.ValidUntil = now },
		"missing-coverage": func(v *r.AdmissionInput) {
			v.Snapshot.Coverage = append([]r.CoverageSource(nil), v.Snapshot.Coverage[:3]...)
		},
		"duplicate-coverage": func(v *r.AdmissionInput) {
			v.Snapshot.Coverage = append([]r.CoverageSource(nil), v.Snapshot.Coverage...)
			v.Snapshot.Coverage[3] = v.Snapshot.Coverage[0]
		},
		"unmapped-retained-key": func(v *r.AdmissionInput) {
			v.Snapshot.References = []r.Reference{{Partition: r.RetainedArtifacts, SourceRecordID: "r", SourceRecordVersion: "v1", BackupPublicID: "sbk_one", AttemptNo: "1", EnvelopeID: "e", Key: v.Candidate.Key, BindingSHA256: v.Candidate.ConfigRef.IdentityHash, MappingSource: v.Observation.MappingSource, ExpectedRequestSource: v.Observation.MappingSource, LifecycleSource: v.Observation.MappingSource}}
		},
		"malformed-historical-mapping": func(v *r.AdmissionInput) {
			old := v.Candidate
			old.ConfigRef.Version, old.Key.RegistryVersion = "old-v1", "old-v1"
			old.Provider.Endpoint = "http://untrusted.invalid"
			v.Snapshot.Bindings = []r.BindingFacts{{Binding: old, BindingSHA256: keyBindingHash(old), RowVersion: 1}}
		},
		"historical-provider-empty-query": func(v *r.AdmissionInput) {
			old := v.Candidate
			old.ConfigRef.Version, old.Key.RegistryVersion = "old-v1", "old-v1"
			old.Provider.Endpoint = "https://provider.invalid?"
			v.Snapshot.Bindings = []r.BindingFacts{{Binding: old, BindingSHA256: keyBindingHash(old), RowVersion: 1}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := base
			change(&v)
			if err := CheckUnadmittedInput(v, now); !errors.Is(err, ErrCandidate) {
				t.Fatalf("invalid candidate accepted: %v", err)
			}
		})
	}
}
