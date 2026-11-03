package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Signature DATA only. This fixture supplies neither physical source proofs,
// an original maintenance authority, SQL evidence rows nor PreparedCoverage.
func coverageWitnessData(t *testing.T) (CoverageWitnessRecord, CoverageWitnessPin, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := CoverageWitnessRecord{Facts: CoverageWitnessFacts{Database: reg.DatabaseIdentity{ServerUUID: "DATA-server", Database: "DATA_database"}, InstallationID: "installation_DATA", Partition: reg.RetainedArtifacts, Kind: "original_sql_census", ScopeSHA256: strings.Repeat("a", 64), ObservationSHA256: strings.Repeat("b", 64), SnapshotRevision: "snapshot-original-7", FenceRevision: "fence-original-7"}, Source: reg.SourceRecord{SourceID: "original-SQL-source-DATA", RecordID: "sev_original_source_DATA", RecordVersion: "v7"}, Revision: "v7", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	record.Source.ContentSHA256 = coverageFactsHash(record.Facts)
	pin := CoverageWitnessPin{CoverageOwnerPin: CoverageOwnerPin{Source: record.Source, Issuer: public}, Partition: record.Facts.Partition, Kind: record.Facts.Kind, ScopeSHA256: record.Facts.ScopeSHA256}
	return record, pin, key, now
}

func signCoverageData(t *testing.T, record any, key ed25519.PrivateKey, domain string, until time.Time) capabilityEvidence {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(SignedCoverageOwnerRecord{Record: raw, Signature: ed25519.Sign(key, append([]byte(domain), raw...))})
	if err != nil {
		t.Fatal(err)
	}
	return capabilityEvidence{raw: envelope, until: until}
}

func TestOriginalCoverageWitnessAuthenticatesIndependentOriginalFacts(t *testing.T) {
	record, pin, key, now := coverageWitnessData(t)
	good := signCoverageData(t, record, key, OriginalCoverageWitnessDomain, record.Until)
	if _, err := authenticateCoverageWitness(good, pin, now); err != nil {
		t.Fatal("DATA signature contract", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*CoverageWitnessRecord)
	}{
		{"revoked", func(r *CoverageWitnessRecord) { r.Revoked = true }},
		{"future", func(r *CoverageWitnessRecord) { r.NotBefore = now.Add(time.Microsecond) }},
		{"expired", func(r *CoverageWitnessRecord) { r.Until = now }},
		{"foreign-source", func(r *CoverageWitnessRecord) { r.Source.SourceID = "foreign" }},
		{"foreign-partition", func(r *CoverageWitnessRecord) { r.Facts.Partition = reg.RestoreAndPrune }},
		{"foreign-kind", func(r *CoverageWitnessRecord) { r.Facts.Kind = "immutable_external_snapshot" }},
		{"foreign-scope", func(r *CoverageWitnessRecord) { r.Facts.ScopeSHA256 = strings.Repeat("c", 64) }},
		{"missing-observation", func(r *CoverageWitnessRecord) { r.Facts.ObservationSHA256 = "" }},
		{"latest-snapshot", func(r *CoverageWitnessRecord) { r.Facts.SnapshotRevision = "latest" }},
		{"latest-fence", func(r *CoverageWitnessRecord) { r.Facts.FenceRevision = "current" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := record
			tc.change(&changed)
			e := signCoverageData(t, changed, key, OriginalCoverageWitnessDomain, record.Until)
			if _, err := authenticateCoverageWitness(e, pin, now); err == nil {
				t.Fatal("changed original owner facts admitted")
			}
		})
	}
	wrong := pin
	wrong.Issuer = make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := authenticateCoverageWitness(good, wrong, now); err == nil {
		t.Fatal("caller-selected issuer accepted")
	}
	wrongDomain := signCoverageData(t, record, key, OriginalCoverageDomain, record.Until)
	if _, err := authenticateCoverageWitness(wrongDomain, pin, now); err == nil {
		t.Fatal("adoption signature substituted for SQL source witness")
	}
	good.until = now
	if _, err := authenticateCoverageWitness(good, pin, now); err == nil {
		t.Fatal("expired original evidence row accepted")
	}
}

func TestOriginalCoverageReferenceSetKeepsUnknownReleasedAndEveryMember(t *testing.T) {
	refs := []reg.Reference{{Partition: reg.RetainedArtifacts, State: reg.ReferenceUnknown, SourceRecordID: "original-unknown", SourceRecordVersion: "v1"}, {Partition: reg.RetainedArtifacts, State: reg.ReferenceReleased, SourceRecordID: "original-released", SourceRecordVersion: "v2"}, {Partition: reg.InflightAndUnknownWrites, State: reg.ReferenceUnknown, SourceRecordID: "original-inflight", SourceRecordVersion: "v3"}}
	count, digest, err := originalCoverageReferences(refs, reg.RetainedArtifacts)
	if err != nil || count != 2 || !authorityHash.MatchString(digest) {
		t.Fatal("unknown/released historical membership omitted")
	}
	reordered := []reg.Reference{refs[2], refs[1], refs[0]}
	n, hash, err := originalCoverageReferences(reordered, reg.RetainedArtifacts)
	if err != nil || n != count || hash != digest {
		t.Fatal("same complete set order changed observation")
	}
	changed := append([]reg.Reference(nil), refs...)
	changed[1].State = reg.ReferenceRetained
	if _, hash, err := originalCoverageReferences(changed, reg.RetainedArtifacts); err != nil || hash == digest {
		t.Fatal("historical lifecycle change not observed")
	}
	duplicate := append(append([]reg.Reference(nil), refs...), refs[0])
	if _, _, err := originalCoverageReferences(duplicate, reg.RetainedArtifacts); err == nil {
		t.Fatal("duplicate historical source identity accepted")
	}
	if _, _, err := originalCoverageReferences(nil, reg.RetainedArtifacts); err == nil {
		t.Fatal("unobserved nil source became an empty scan")
	}
}

func TestOriginalCoverageCannotBeManufacturedFromEmptyInputs(t *testing.T) {
	if _, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{}); err == nil {
		t.Fatal("missing original owners manufactured preparation")
	}
	if _, err := NewSQLBootstrapKEKPreparation(SQLBootstrapKEKConfig{}); err == nil {
		t.Fatal("missing original bootstrap sources manufactured factory")
	}
	if _, err := NewSQLBootstrapAdmissionSource(SQLBootstrapSourceConfig{}); err == nil {
		t.Fatal("missing original source manufactured admission")
	}
	if _, err := (*SQLCoverageOwnerPreparation)(nil).Prepare(context.Background(), reg.Snapshot{}); err == nil {
		t.Fatal("nil original coverage manufactured proof")
	}
	if _, _, err := (*UnadmittedSQLCoverageCensus)(nil).SignOriginalSQLWitness(context.Background(), reg.RetainedArtifacts, reg.SourceRecord{}, "v1", "v1", "v1", time.Now().Add(time.Minute), nil); err == nil {
		t.Fatal("missing real census manufactured signed SQL observation")
	}
	if err := (*SQLPreparedOriginalCoverage)(nil).LockOriginalEvidence(context.Background(), nil); err == nil {
		t.Fatal("missing evidence lock accepted")
	}
}
