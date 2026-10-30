package worker

import (
	"testing"

	legacy "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/staging"
)

func TestLegacyTeamDatabaseFormatOnlyAdmittedForIsolatedRestore(t *testing.T) {
	r := databaseRequestFixture(t).Request
	r.Database.InputFormat = legacy.LegacyTeamSQLFormat
	if validDatabaseRequest(r) {
		t.Fatal("legacy import enabled source capture")
	}
	r.Operation = "restore-database"
	r.Database.Name = "cm_drill_legacy"
	r.PolicyVersion = "reviewed-test-policy"
	r.Database.EvidenceName = "normalized.enc"
	r.Database.EvidenceBinding = staging.Binding{Path: "isolated-evidence"}
	if !validDatabaseRequest(r) {
		t.Fatal("explicit legacy restore rejected")
	}
	r.Operation = "verify-database"
	r.Database.EvidenceName = ""
	r.Database.EvidenceBinding = staging.Binding{}
	if validDatabaseRequest(r) {
		t.Fatal("original archive used instead of normalized verification receipt")
	}
	r.Operation = "restore-database"
	r.Database.Name = "production"
	r.Database.EvidenceName = "normalized.enc"
	r.Database.EvidenceBinding = staging.Binding{Path: "isolated-evidence"}
	if validDatabaseRequest(r) {
		t.Fatal("source target admitted")
	}
}
