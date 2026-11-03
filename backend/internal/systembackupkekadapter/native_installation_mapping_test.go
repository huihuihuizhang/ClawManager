package systembackupkekadapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

// DATA-only signature compatibility; this does not call Observe or supply a
// real provider/coverage/installation authority. Production cannot initialize
// the private observation fields that this package-local fixture exercises.
func observedInstallationMappingData(t *testing.T) (*ObservedVaultPermissions, reg.SourceRecord, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	owner, _, _ := ownerRecordFixture(t)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := owner.Binding
	p := &ObservedVaultPermissions{owner: &VaultPermissionObserver{cfg: VaultPermissionObserverConfig{Binding: binding}}, observed: time.Now().UTC(), generate: ProviderCapabilityFacts{Binding: binding, Operation: kms.Generate}, unwrap: ProviderCapabilityFacts{Binding: binding, Operation: kms.Unwrap}}
	return p, reg.SourceRecord{SourceID: "original-installation-owner-DATA", RecordID: "original-mapping-DATA", RecordVersion: "v1"}, public, key
}

func TestObservedInstallationMappingUsesExistingOriginalImporterContract(t *testing.T) {
	observed, source, public, key := observedInstallationMappingData(t)
	signed, err := observed.SignInstallationMapping(source, "original-r1", time.Now().Add(time.Hour), key)
	if err != nil {
		t.Fatal("existing signed mapping contract", err)
	}
	record, err := decodeOwnerRecord(signed.Record, signed.Signature, public)
	if err != nil || record.GenerateRevoked || record.UnwrapRevoked || record.Source.SourceID != source.SourceID || record.Source.RecordID != source.RecordID || !record.NotBefore.Equal(observed.observed) || record.Binding.InstallationID != observed.owner.cfg.Binding.InstallationID {
		t.Fatal("original importer rejected exact signed source", err)
	}
	var raw OriginalRecord
	if json.Unmarshal(signed.Record, &raw) != nil || raw.Source.ContentSHA256 == "" {
		t.Fatal("missing exact source hash")
	}
	if ed25519.Verify(public, append([]byte(ProviderCapabilityDomain), signed.Record...), signed.Signature) {
		t.Fatal("mapping signature became a provider capability")
	}
}

func TestObservedInstallationMappingRejectsUnobservedStaleAndForeignInputs(t *testing.T) {
	for _, name := range []string{"nil", "missing-owner", "stale", "future", "wrong-purpose", "foreign-binding", "expired", "long-horizon", "bad-private-key", "missing-source", "latest-version"} {
		t.Run(name, func(t *testing.T) {
			observed, source, _, key := observedInstallationMappingData(t)
			until := time.Now().Add(time.Hour)
			switch name {
			case "nil":
				observed = nil
			case "missing-owner":
				observed.owner = nil
			case "stale":
				observed.observed = time.Now().Add(-2 * time.Minute)
			case "future":
				observed.observed = time.Now().Add(time.Minute)
			case "wrong-purpose":
				observed.unwrap.Operation = kms.Generate
			case "foreign-binding":
				observed.unwrap.Binding.InstallationID = "foreign"
			case "expired":
				until = time.Now().Add(-time.Microsecond)
			case "long-horizon":
				until = time.Now().Add(25 * time.Hour)
			case "bad-private-key":
				key[len(key)-1] ^= 1
			case "missing-source":
				source.SourceID = ""
			case "latest-version":
				source.RecordVersion = "latest"
			}
			if _, err := observed.SignInstallationMapping(source, "original-r1", until, key); err == nil {
				t.Fatal("unobserved/foreign owner mapping signed")
			}
		})
	}
}
