package systembackupresources

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fixtureProof struct{ err error }

func (p fixtureProof) VerifyCapture(context.Context, CaptureSnapshotEvidence, CaptureSnapshotEvidence) error {
	return p.err
}

func TestResourcesBackupFixedFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/resources-backup-verify-draft.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Proof  string                  `json:"proof"`
		Source CaptureSnapshotEvidence `json:"source"`
		Dump   CaptureSnapshotEvidence `json:"dump"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Proof != "synthetic-test-only" {
		t.Fatal("fixture must not claim a real capture proof")
	}
	checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), fixture.Source, fixture.Dump, fixtureProof{})
	if err != nil || len(checks) != 12 {
		t.Fatalf("fixed fixture: checks=%v err=%v", checks, err)
	}
	for _, check := range checks {
		if check.Status != "passed" {
			t.Fatalf("fixed fixture mismatch: %+v", check)
		}
	}
}

func verifierEvidence() CaptureSnapshotEvidence {
	rows := make([]TableCount, 0, len(resourceTables))
	for table := range resourceTables {
		rows = append(rows, TableCount{Table: table, Rows: 1})
	}
	// Match the frozen allowlist's deterministic order.
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].Table < rows[i].Table {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}
	cutoff := int64(7)
	return CaptureSnapshotEvidence{
		CheckpointHash: strings.Repeat("a", 64), CaptureContextHash: strings.Repeat("b", 64),
		EvidenceRef: "sev_fixture", Snapshot: SourceSnapshot{Tables: rows, AuditMaxID: &cutoff},
	}
}

func TestVerifyBackupSnapshotFixture(t *testing.T) {
	source := verifierEvidence()
	dump := verifierEvidence()
	checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, fixtureProof{})
	if err != nil || len(checks) != len(resourceTables)+3 {
		t.Fatalf("checks=%v err=%v", checks, err)
	}
	for _, check := range checks {
		if check.Status != "passed" || check.FailureCategory != "none" || check.EvidenceRef == nil {
			t.Fatalf("unexpected check: %+v", check)
		}
	}
	dump.Snapshot.Tables[3].Rows = 9
	dump.Snapshot.AuditMaxID = nil // invalid evidence fails before comparison.
	if checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, fixtureProof{}); err == nil || checks != nil {
		t.Fatalf("invalid cutoff accepted: %v %v", checks, err)
	}
	dump = verifierEvidence()
	dump.Snapshot.Tables[3].Rows = 9
	dump.Snapshot.AuditMaxID = new(int64)
	*dump.Snapshot.AuditMaxID = 8
	checks, err = VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, fixtureProof{})
	if err != nil || checks[5].Status != "failed" || checks[len(checks)-1].Status != "failed" {
		t.Fatalf("mismatches missed: %v %v", checks, err)
	}
}

func TestVerifyBackupSnapshotFailsClosed(t *testing.T) {
	source := verifierEvidence()
	dump := verifierEvidence()
	for _, tc := range []struct {
		name  string
		proof CaptureProofVerifier
		alter func(*CaptureSnapshotEvidence)
	}{
		{"missing proof", nil, func(*CaptureSnapshotEvidence) {}},
		{"rejected proof", fixtureProof{errors.New("certificate invalid")}, func(*CaptureSnapshotEvidence) {}},
		{"invalid evidence id", fixtureProof{}, func(e *CaptureSnapshotEvidence) { e.EvidenceRef = "secret" }},
		{"missing table", fixtureProof{}, func(e *CaptureSnapshotEvidence) { e.Snapshot.Tables = e.Snapshot.Tables[:8] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := dump
			tc.alter(&bad)
			checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, bad, tc.proof)
			if err == nil || checks != nil {
				t.Fatalf("accepted incomplete proof: %v %v", checks, err)
			}
		})
	}
}
