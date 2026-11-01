package systembackupoffline

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	wire "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var partitions = []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune}
var fixedVersion = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func exactVersion(v string) bool {
	return fixedVersion.MatchString(v) && v != "latest" && v != "current" && v != "default"
}
func validSource(s reg.SourceRecord) bool {
	return s.SourceID != "" && s.RecordID != "" && exactVersion(s.RecordVersion) && digestPattern.MatchString(s.ContentSHA256)
}
func keyHash(k wire.KeyBinding) string {
	raw, err := json.Marshal(map[string]string{"provider": k.Provider, "identity_hash": k.IdentityHash, "registry_version": k.RegistryVersion, "provider_key_id": k.ProviderKeyID, "provider_version": k.ProviderVersion})
	if err != nil {
		return ""
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		return ""
	}
	return Digest(raw)
}
func refID(r reg.Reference) string {
	raw, _ := json.Marshal([]string{string(r.Partition), r.SourceRecordID, r.SourceRecordVersion})
	return string(raw)
}

func reviewCoverage(t Trust, material *CoverageMaterial, now time.Time) []Check {
	status := "rejected"
	if material == nil && t.CoverageInventorySHA256 == "" {
		status = "unverified"
	}
	failure := func() []Check {
		out := []Check{}
		for _, p := range partitions {
			out = append(out, Check{Slot: "coverage:" + string(p), Status: status})
		}
		return out
	}
	if material == nil || !digestPattern.MatchString(t.CoverageInventorySHA256) || Digest(material.Expected) != t.CoverageInventorySHA256 {
		return failure()
	}
	var expected reg.Snapshot
	if Decode(material.Expected, &expected) != nil {
		return failure()
	}
	observed := material.Observed
	if t.InstallationID == "" || expected.InstallationID != t.InstallationID || observed.InstallationID != t.InstallationID ||
		expected.Database.ServerUUID == "" || expected.Database.Database == "" || observed.Database != expected.Database || observed.Epoch != expected.Epoch ||
		expected.ObservedAt.IsZero() || observed.ObservedAt.IsZero() || expected.ObservedAt.After(now) || observed.ObservedAt.After(now) ||
		expected.Coverage == nil || observed.Coverage == nil || expected.Bindings == nil || observed.Bindings == nil || expected.References == nil || observed.References == nil {
		return failure()
	}
	want, got := map[reg.Partition]reg.CoverageSource{}, map[reg.Partition]reg.CoverageSource{}
	known := map[reg.Partition]bool{}
	for _, p := range partitions {
		known[p] = true
	}
	for _, pair := range []struct {
		rows []reg.CoverageSource
		dest map[reg.Partition]reg.CoverageSource
	}{{expected.Coverage, want}, {observed.Coverage, got}} {
		for _, c := range pair.rows {
			if !known[c.Partition] || pair.dest[c.Partition].SourceID != "" || c.SourceID == "" || !exactVersion(c.SnapshotRevision) || !exactVersion(c.FenceRevision) || !validSource(c.AdoptionSource) {
				return failure()
			}
			pair.dest[c.Partition] = c
		}
	}
	bindings := map[reg.ReferencePin]reg.BindingFacts{}
	// Compare every exact binding; equal cardinality cannot replace membership.
	for _, f := range expected.Bindings {
		pin := f.Binding.ConfigRef
		if _, exists := bindings[pin]; exists {
			return failure()
		}
		if f.Binding.InstallationID != t.InstallationID || !digestPattern.MatchString(pin.IdentityHash) || !exactVersion(pin.Version) ||
			f.Binding.Key.IdentityHash != pin.IdentityHash || f.Binding.Key.RegistryVersion != pin.Version || f.Binding.Key.Provider != "external-kms" ||
			f.BindingSHA256 != keyHash(f.Binding.Key) || f.RowVersion == 0 {
			return failure()
		}
		bindings[pin] = f
	}
	observedBindings := map[reg.ReferencePin]bool{}
	for _, f := range observed.Bindings {
		pin := f.Binding.ConfigRef
		previous, ok := bindings[pin]
		if !ok || observedBindings[pin] || !reflect.DeepEqual(previous, f) {
			return failure()
		}
		observedBindings[pin] = true
	}
	for pin := range bindings {
		if !observedBindings[pin] {
			return failure()
		}
	}
	actual, required := map[string]reg.Reference{}, map[string]bool{}
	for _, r := range observed.References {
		id := refID(r)
		if _, duplicate := actual[id]; duplicate || !known[r.Partition] {
			return failure()
		}
		actual[id] = r
	}
	result := []Check{}
	for _, p := range partitions {
		s := "checked_offline"
		a, aok := want[p]
		b, bok := got[p]
		if !aok || !bok {
			s = "unverified"
		} else if a != b {
			s = "rejected"
		}
		result = append(result, Check{Slot: "coverage:" + string(p), Status: s})
	}
	for i, r := range expected.References {
		id := refID(r)
		if required[id] || !known[r.Partition] {
			return failure()
		}
		required[id] = true
		s := "checked_offline"
		f, bound := bindings[reg.ReferencePin{IdentityHash: r.Key.IdentityHash, Version: r.Key.RegistryVersion}]
		a, exists := actual[id]
		if !exists || !reflect.DeepEqual(a, r) || !bound || f.Binding.Key != r.Key || f.BindingSHA256 != r.BindingSHA256 ||
			r.SourceRecordID == "" || !exactVersion(r.SourceRecordVersion) || r.BackupPublicID == "" || r.AttemptNo == "" || r.EnvelopeID == "" ||
			!validSource(r.MappingSource) || !validSource(r.ExpectedRequestSource) || !validSource(r.LifecycleSource) ||
			(r.State != reg.ReferencePlanned && r.State != reg.ReferenceUnknown && r.State != reg.ReferenceRetained && r.State != reg.ReferenceReleased) ||
			(f.UnwrapRevoked != nil && r.State != reg.ReferenceReleased) {
			s = "rejected"
		}
		result = append(result, Check{Slot: "coverage_reference:" + string(r.Partition) + ":" + strconv.Itoa(i), Status: s})
	}
	for id := range actual {
		if !required[id] {
			return failure()
		}
	}
	return result
}
