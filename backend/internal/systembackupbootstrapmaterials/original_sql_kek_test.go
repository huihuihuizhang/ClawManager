package systembackupbootstrapmaterials

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func originalKEKSourceFixture(t *testing.T) OriginalSQLBootstrapKEKSource {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	ref := func(id string) reg.SourceRecord {
		return reg.SourceRecord{SourceID: "original-owner", RecordID: id, RecordVersion: "v1", ContentSHA256: strings.Repeat("a", 64)}
	}
	cfg := kek.SQLBootstrapKEKConfig{Database: reg.DatabaseIdentity{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "original_source"}, InstallationID: "installation_original", Mapping: reg.ReferencePin{IdentityHash: strings.Repeat("b", 64), Version: "v1"}, MappingIssuer: public, Generate: kek.ProviderCapabilityPin{Source: ref("generate-original"), Issuer: public}, Unwrap: kek.ProviderCapabilityPin{Source: ref("unwrap-original"), Issuer: public}, Adoption: kek.CoverageOwnerPin{Source: ref("sev_adoption_original"), Issuer: public}}
	for _, partition := range []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune} {
		for _, kind := range []string{"original_sql_census", "immutable_external_snapshot", "original_writer_fence", "historical_backfill"} {
			cfg.Witnesses = append(cfg.Witnesses, kek.CoverageWitnessPin{CoverageOwnerPin: kek.CoverageOwnerPin{Source: ref("sev_" + string(partition) + "_" + kind), Issuer: public}, Partition: partition, Kind: kind, ScopeSHA256: strings.Repeat("c", 64)})
		}
	}
	return OriginalSQLBootstrapKEKSource{SchemaVersion: OriginalSQLBootstrapKEKSourceVersion, Preparation: cfg}
}

func TestOriginalSQLKEKLinkKeepsAllThirtyResourceOwnersMissing(t *testing.T) {
	source := originalKEKSourceFixture(t)
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "original-owner-pins.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	base := sec.BootstrapOwnerAdapters{}
	linked, err := LinkOriginalSQLBootstrapKEK(base, file, pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := linked.KEK.(*kek.SQLBootstrapKEKPreparation); !ok || !reflect.DeepEqual(sec.MissingBootstrapOwnerAdapters(linked), sec.MissingBootstrapOwnerAdapters(base)) {
		t.Fatal("deferred source manufactured a resource validator")
	}
	if _, err := LinkOriginalSQLBootstrapKEK(linked, file, pin); err == nil {
		t.Fatal("overwrote an existing original preparation")
	}
	if _, err := LinkOriginalSQLBootstrapKEK(base, file, strings.Repeat("f", 64)); err == nil {
		t.Fatal("self-selected/unpinned original source")
	}
	// A complete finite sixteen-pin declaration is NOT actual coverage/adoption
	// proof. Runtime Prepare still reads/validates every real original source.
	for _, mutate := range []func(*OriginalSQLBootstrapKEKSource){func(s *OriginalSQLBootstrapKEKSource) { s.Preparation.Witnesses = s.Preparation.Witnesses[:15] }, func(s *OriginalSQLBootstrapKEKSource) { s.Preparation.Unwrap = s.Preparation.Generate }} {
		bad := originalKEKSourceFixture(t)
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		raw, _ = jsoncanonicalizer.Transform(raw)
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("controlled source")
		}
		digest := sha256.Sum256(raw)
		if _, err := LinkOriginalSQLBootstrapKEK(base, file, hex.EncodeToString(digest[:])); err == nil {
			t.Fatal("lost independent purpose or coverage source")
		}
	}
}
