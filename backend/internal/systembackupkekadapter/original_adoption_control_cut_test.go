package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Explicit control-transport fixtures. ONLY SQL witnesses below come from the
// actual private SQL census producer. Physical/snapshot/backfill witness values
// are signed test doubles; none is a genuine physical proof or PreparedCoverage.
func originalControlBatchFixture(t *testing.T, observed *UnadmittedSQLCoverageCensus) (OriginalAdoptionControlPins, OriginalAdoptionControlRecords) {
	return originalControlReferencesFixture(t, observed, []reg.Reference{}, 1, false)
}

// Test-only signed physical/backfill doubles; no production proof constructor.
func originalControlReferencesFixture(t *testing.T, observed *UnadmittedSQLCoverageCensus, refs []reg.Reference, epoch uint64, revoked bool) (OriginalAdoptionControlPins, OriginalAdoptionControlRecords) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	facts := observed.Facts()
	until := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	pins := OriginalAdoptionControlPins{}
	records := OriginalAdoptionControlRecords{}
	parts := []CoveragePartitionAdoption{}
	keys := map[string]ed25519.PrivateKey{}
	for _, kind := range append(append([]string{}, coverageWitnessKinds...), "adoption") {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[kind] = key
	}
	for _, partition := range []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune} {
		count, digest, e := originalCoverageReferences(refs, partition)
		if e != nil {
			t.Fatal(e)
		}
		part := CoveragePartitionAdoption{Partition: partition, SourceID: "fixture-source-" + string(partition), SnapshotRevision: "fixture-snapshot-v1", FenceRevision: "fixture-fence-v1", ReferenceCount: count, ReferencesSHA256: digest}
		for _, kind := range coverageWitnessKinds {
			source := reg.SourceRecord{SourceID: "fixture-original-" + kind, RecordID: "sev_fixture_" + string(partition) + "_" + kind, RecordVersion: "v1"}
			var signed SignedCoverageOwnerRecord
			var pin CoverageWitnessPin
			if kind == "original_sql_census" {
				signed, pin, e = observed.SignOriginalSQLWitness(ctx, partition, source, "v1", part.SnapshotRevision, part.FenceRevision, until, keys[kind])
				if e != nil {
					t.Fatal(e)
				}
			} else {
				w := CoverageWitnessFacts{Database: facts.Database, InstallationID: facts.InstallationID, Partition: partition, Kind: kind, ScopeSHA256: coverageFactsHash("TEST-DOUBLE-scope-" + kind + string(partition)), ObservationSHA256: coverageFactsHash("TEST-DOUBLE-not-native-" + kind), SnapshotRevision: part.SnapshotRevision, FenceRevision: part.FenceRevision}
				source.ContentSHA256 = coverageFactsHash(w)
				r := CoverageWitnessRecord{Facts: w, Source: source, Revision: "v1", NotBefore: facts.ObservedAt, Until: until, Revoked: revoked && kind == "historical_backfill"}
				raw, e := json.Marshal(r)
				if e != nil {
					t.Fatal(e)
				}
				signed = SignedCoverageOwnerRecord{Record: raw, Signature: ed25519.Sign(keys[kind], append([]byte(OriginalCoverageWitnessDomain), raw...))}
				pin = CoverageWitnessPin{CoverageOwnerPin: CoverageOwnerPin{Source: source, Issuer: keys[kind].Public().(ed25519.PublicKey)}, Partition: partition, Kind: kind, ScopeSHA256: w.ScopeSHA256}
			}
			pins.Witnesses = append(pins.Witnesses, pin)
			records[pin.Source.RecordID] = signed
			switch kind {
			case "original_sql_census":
				part.SQLCensus = pin.Source
			case "immutable_external_snapshot":
				part.ImmutableExternalSnapshot = pin.Source
			case "original_writer_fence":
				part.WriterFence = pin.Source
			case "historical_backfill":
				part.HistoricalBackfill = pin.Source
			}
		}
		parts = append(parts, part)
	}
	adoption := CoverageAdoptionFacts{Database: facts.Database, InstallationID: facts.InstallationID, AdoptedEpoch: epoch, Partitions: parts}
	source := reg.SourceRecord{SourceID: "fixture-original-adopter", RecordID: "sev_fixture_adoption", RecordVersion: "v1", ContentSHA256: coverageFactsHash(adoption)}
	r := CoverageAdoptionRecord{Facts: adoption, Source: source, Revision: "v1", NotBefore: facts.ObservedAt, Until: until}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	pins.Adoption = CoverageOwnerPin{Source: source, Issuer: keys["adoption"].Public().(ed25519.PublicKey)}
	records[source.RecordID] = SignedCoverageOwnerRecord{Record: raw, Signature: ed25519.Sign(keys["adoption"], append([]byte(OriginalCoverageDomain), raw...))}
	return pins, records
}

func TestOriginalControlCutCannotBeDetachedSerializedOrConvertedToCoverage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := (*SQLCoverageCensus)(nil).PrepareOriginalAdoptionControlCut(ctx, nil, nil, OriginalAdoptionControlPins{}, time.Now().Add(time.Second)); e == nil {
		t.Fatal("detached cut accepted")
	}
	p := &OriginalAdoptionControlCut{}
	if p.Stage(ctx, nil) == nil || p.Recheck(ctx) == nil {
		t.Fatal("detached transaction accepted")
	}
	if _, e := p.MarshalJSON(); e == nil {
		t.Fatal("transaction became JSON approval")
	}
	if _, ok := any(p).(reg.PreparedCoverage); ok {
		t.Fatal("SQL cut became complete coverage")
	}
	if p.Abort() == nil || p.Abort() == nil {
		t.Fatal("failed rollback became confirmed on retry")
	}
}

func TestOriginalControlRowJournalDistinguishesNullEmptyAndEveryColumn(t *testing.T) {
	columns := []string{"id", "inline_payload", "extra_original_metadata"}
	base := []sql.RawBytes{[]byte("1"), []byte("exact signed envelope"), nil}
	a := originalControlRowSHA(columns, base)
	base[2] = []byte{}
	if originalControlRowSHA(columns, base) == a {
		t.Fatal("NULL/empty collision in private journal")
	}
	base[2] = nil
	base[1] = []byte("different signed envelope")
	if originalControlRowSHA(columns, base) == a {
		t.Fatal("payload change ignored")
	}
	if originalControlRowSHA([]string{"id", "inline_payload", "unknown_column"}, base) == a {
		t.Fatal("column identity ignored")
	}
	if strings.TrimSpace(a) == "" {
		t.Fatal("missing exact row digest")
	}
}
