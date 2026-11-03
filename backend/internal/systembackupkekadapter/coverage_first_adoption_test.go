package systembackupkekadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Signature/association fixtures only: no physical proof, live DB or adoption.
func firstAdoptionAuthenticationFixture(t *testing.T) (SQLCoverageOwnerConfig, *OriginalAdoptionControlCut, reg.Snapshot, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	db := reg.DatabaseIdentity{ServerUUID: "fixture-server", Database: "fixture_database"}
	scanner := &SQLCoverageCensus{database: db, installation: "fixture-installation"}
	facts := SQLCoverageCensusFacts{Database: db, InstallationID: scanner.installation, ObservedAt: now.Add(-time.Second)}
	sources, _ := sqlCensusSources()
	for table, partition := range sources {
		facts.Tables = append(facts.Tables, SQLCoverageTable{Table: table, Partition: partition, SchemaSHA256: strings.Repeat("a", 64), RowsSHA256: strings.Repeat("b", 64)})
	}
	sort.Slice(facts.Tables, func(i, j int) bool { return facts.Tables[i].Table < facts.Tables[j].Table })
	observed := &UnadmittedSQLCoverageCensus{owner: scanner, facts: facts}
	pins, records := originalControlBatchFixture(t, observed)
	cut := &OriginalAdoptionControlCut{original: &OriginalSQLCoverageTransaction{owner: scanner}, observed: facts, pins: pins, until: now.Add(time.Minute)}
	rows, err := cut.authenticateBatch(records, now)
	if err != nil {
		t.Fatal(err)
	}
	cut.rows = rows
	cfg := SQLCoverageOwnerConfig{Database: db, InstallationID: scanner.installation, Adoption: pins.Adoption, Witnesses: pins.Witnesses}
	snapshot := reg.Snapshot{Database: db, InstallationID: scanner.installation, ObservedAt: now, Bindings: []reg.BindingFacts{}, References: []reg.Reference{}}
	return cfg, cut, snapshot, now
}

func TestFirstAdoptionAuthenticationRequiresAllSeventeenRecords(t *testing.T) {
	cfg, cut, snapshot, now := firstAdoptionAuthenticationFixture(t)
	if _, err := authenticateFirstAdoptionSnapshot(cfg, cut, snapshot, now); err != nil {
		t.Fatal(err)
	}
	for id, row := range cut.rows {
		delete(cut.rows, id)
		if _, err := authenticateFirstAdoptionSnapshot(cfg, cut, snapshot, now); err == nil {
			t.Fatal("missing record accepted", id)
		}
		cut.rows[id] = row
		old := row.expires
		row.expires = now
		if _, err := authenticateFirstAdoptionSnapshot(cfg, cut, snapshot, now); err == nil {
			t.Fatal("expired record accepted", id)
		}
		row.expires = old
		original := row.envelope
		var signed SignedCoverageOwnerRecord
		if json.Unmarshal(original, &signed) != nil {
			t.Fatal("fixture envelope")
		}
		signed.Signature[0] ^= 1
		row.envelope, _ = json.Marshal(signed)
		if _, err := authenticateFirstAdoptionSnapshot(cfg, cut, snapshot, now); err == nil {
			t.Fatal("changed signature accepted", id)
		}
		row.envelope = original
	}
}

func TestFirstAdoptionAuthenticationBindsOriginalRegistryFacts(t *testing.T) {
	cfg, cut, snapshot, now := firstAdoptionAuthenticationFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*reg.Snapshot)
	}{
		{"installation", func(s *reg.Snapshot) { s.InstallationID = "foreign" }},
		{"database", func(s *reg.Snapshot) { s.Database.ServerUUID = "foreign" }},
		{"epoch", func(s *reg.Snapshot) { s.Epoch = 1 }},
		{"overflow", func(s *reg.Snapshot) { s.Epoch = ^uint64(0) }},
		{"future", func(s *reg.Snapshot) { s.ObservedAt = now.Add(time.Second) }},
		{"no-bindings", func(s *reg.Snapshot) { s.Bindings = nil }},
		{"unknown-references", func(s *reg.Snapshot) { s.References = nil }},
		{"extra-unknown-reference", func(s *reg.Snapshot) {
			s.References = []reg.Reference{{Partition: reg.RetainedArtifacts, SourceRecordID: "unclassified", SourceRecordVersion: "v1", State: reg.ReferenceUnknown}}
		}},
		{"already-adopted", func(s *reg.Snapshot) { s.Coverage = []reg.CoverageSource{{Partition: reg.RetainedArtifacts}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := snapshot
			tc.change(&changed)
			if _, err := authenticateFirstAdoptionSnapshot(cfg, cut, changed, now); err == nil {
				t.Fatal("mismatched registry facts accepted")
			}
		})
	}
	if !sameFirstAdoptionPins(cfg, cut.pins) {
		t.Fatal("original pins rejected")
	}
	pins := cut.pins
	pins.Witnesses = append([]CoverageWitnessPin(nil), pins.Witnesses...)
	pins.Witnesses[0].Source.SourceID = "caller-selected"
	if sameFirstAdoptionPins(cfg, pins) {
		t.Fatal("caller-selected source accepted")
	}
}

func TestFirstAdoptionAuthenticationCannotAuthorizeOrCrossTransactions(t *testing.T) {
	if _, err := (*SQLCoverageOwnerPreparation)(nil).AuthenticateFirstAdoption(context.Background(), nil, reg.LockedSnapshot{}); err == nil {
		t.Fatal("nil owner accepted")
	}
	cfg, cut, snapshot, now := firstAdoptionAuthenticationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cut.ctx = ctx
	cut.origin = cut
	cut.staged = true
	cut.original.tx = &sql.Tx{}
	cut.locked = &LockedSQLCoverageCensus{}
	p := &AuthenticatedFirstAdoption{owner: &SQLCoverageOwnerPreparation{cfg: cfg}, cut: cut, snapshot: snapshot, until: now.Add(time.Minute)}
	p.origin = p
	if _, ok := any(p).(reg.PreparedCoverage); ok {
		t.Fatal("signature-only authentication became adoption authority")
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("opaque handle serialized")
	}
	if len(p.RecordSources()) != 17 {
		t.Fatal("incomplete source correspondence")
	}
	if p.Recheck(ctx, &sql.Tx{}, reg.LockedSnapshot{}, now) == nil || !cut.failed || !p.failed {
		t.Fatal("foreign transaction accepted or failure not terminal")
	}
	if p.Recheck(ctx, cut.original.tx, reg.LockedSnapshot{}, now) == nil {
		t.Fatal("poisoned handle reused")
	}
}
