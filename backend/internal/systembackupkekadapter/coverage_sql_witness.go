package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

type OriginalSQLPartitionCensus struct {
	Database       reg.DatabaseIdentity
	InstallationID string
	Partition      reg.Partition
	ObservedAt     time.Time
	Tables         []SQLCoverageTable
}

// SignOriginalSQLWitness signs ONLY a real complete original SQL census
// obtained by SQLCoverageCensus.Observe. It cannot sign an external immutable
// snapshot, writer fence, historical backfill or adoption. Those are separate
// mandatory original-owner sources; live S3 LIST has no immutable signing API.
// Snapshot/fence revision strings are original protocol associations, never a
// claim that a lock was acquired by this read-only observation.
func (p *UnadmittedSQLCoverageCensus) SignOriginalSQLWitness(ctx context.Context, partition reg.Partition, source reg.SourceRecord, revision, snapshotRevision, fenceRevision string, until time.Time, issuer ed25519.PrivateKey) (SignedCoverageOwnerRecord, CoverageWitnessPin, error) {
	fail := func() (SignedCoverageOwnerRecord, CoverageWitnessPin, error) {
		return SignedCoverageOwnerRecord{}, CoverageWitnessPin{}, sec.ErrRegistrationUnavailable
	}
	if p == nil || p.owner == nil || nilSource(ctx) || ctx.Err() != nil || !coveragePartition(partition) || p.facts.Database != p.owner.database || p.facts.InstallationID != p.owner.installation || p.facts.ObservedAt.IsZero() || time.Since(p.facts.ObservedAt) < 0 || time.Since(p.facts.ObservedAt) > time.Minute || !authorityExact(revision) || !authorityExact(snapshotRevision) || !authorityExact(fenceRevision) || source.SourceID == "" || source.RecordID == "" || !authorityExact(source.RecordVersion) || len(issuer) != ed25519.PrivateKeySize || !until.After(time.Now()) || until.After(p.facts.ObservedAt.Add(24*time.Hour)) {
		return fail()
	}
	canonical := ed25519.NewKeyFromSeed(issuer[:ed25519.SeedSize])
	defer clear(canonical)
	if !equalPrivateKey(canonical, issuer) {
		return fail()
	}
	sources, _ := sqlCensusSources()
	seen := map[string]bool{}
	facts := OriginalSQLPartitionCensus{Database: p.facts.Database, InstallationID: p.facts.InstallationID, Partition: partition, ObservedAt: p.facts.ObservedAt, Tables: []SQLCoverageTable{}}
	for _, table := range p.facts.Tables {
		if sources[table.Table] != table.Partition || seen[table.Table] || !authorityHash.MatchString(table.SchemaSHA256) || !authorityHash.MatchString(table.RowsSHA256) {
			return fail()
		}
		seen[table.Table] = true
		if table.Partition == partition {
			facts.Tables = append(facts.Tables, table)
		}
	}
	for table := range sources {
		if !seen[table] {
			return fail()
		}
	}
	if len(facts.Tables) == 0 {
		return fail()
	}
	scope := struct {
		Database       reg.DatabaseIdentity
		InstallationID string
		Partition      reg.Partition
	}{facts.Database, facts.InstallationID, partition}
	witness := CoverageWitnessFacts{Database: facts.Database, InstallationID: facts.InstallationID, Partition: partition, Kind: "original_sql_census", ScopeSHA256: coverageFactsHash(scope), ObservationSHA256: coverageFactsHash(facts), SnapshotRevision: snapshotRevision, FenceRevision: fenceRevision}
	source.ContentSHA256 = coverageFactsHash(witness)
	record := CoverageWitnessRecord{Facts: witness, Source: source, Revision: revision, NotBefore: p.facts.ObservedAt, Until: until}
	raw, err := json.Marshal(record)
	if err != nil {
		return fail()
	}
	signed := SignedCoverageOwnerRecord{Record: raw, Signature: ed25519.Sign(issuer, append([]byte(OriginalCoverageWitnessDomain), raw...))}
	return signed, CoverageWitnessPin{CoverageOwnerPin: CoverageOwnerPin{Source: source, Issuer: append(ed25519.PublicKey(nil), issuer.Public().(ed25519.PublicKey)...)}, Partition: partition, Kind: witness.Kind, ScopeSHA256: witness.ScopeSHA256}, nil
}

func equalPrivateKey(a, b ed25519.PrivateKey) bool {
	if len(a) != len(b) {
		return false
	}
	var changed byte
	for i := range a {
		changed |= a[i] ^ b[i]
	}
	return changed == 0
}
