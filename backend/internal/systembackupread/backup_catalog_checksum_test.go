package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

func TestBackupDetailCatalogChecksumUsesPersistedRegistration(t *testing.T) {
	for _, registered := range []bool{false, true} {
		name := "unregistered"
		if registered {
			name = "registered"
		}
		t.Run(name, func(t *testing.T) {
			f := newUnstartedDetailFixture(BackupTask)
			registrationID := "scr_00000000-0000-4000-8000-000000000004"
			registrationSHA := strings.Repeat("e", 64)
			if registered {
				now := f.rows[0][20].(time.Time)
				finished := now.Add(time.Minute)
				f.rows[0][11], f.values["status"] = "succeeded", "succeeded"
				f.rows[0][14] = false
				f.times = []driver.Value{int64(1), nil, nil, now, finished}
				for column, value := range map[string]driver.Value{
					"artifact_state": "committed", "artifact_usable": true, "artifact_unusable_reason": "none",
					"artifact_committed_at": finished, "consistency": "strong",
					"manifest_checksum": strings.Repeat("a", 64), "index_checksum": strings.Repeat("b", 64),
					"marker_checksum": strings.Repeat("c", 64), "acceptance_checksum": strings.Repeat("d", 64),
					"artifact_registration_id": registrationID, "artifact_registration_hash": registrationSHA,
					"acceptance_eligible": true, "eligibility_reason_codes": "eligible",
					"eligibility_decision_hash": strings.Repeat("f", 64), "eligibility_decided_at": finished,
				} {
					f.values[column] = value
				}
			}
			got, err := verificationDetailReader(t, f, nil).ReadBackupDetail(context.Background(), f.rows[0][1].(string))
			if err != nil {
				t.Fatal(err)
			}
			if registered {
				if got.Checksums.Catalog == nil || *got.Checksums.Catalog != registrationSHA ||
					got.ArtifactRegistrationHash == nil || *got.ArtifactRegistrationHash != registrationSHA ||
					got.ArtifactRegistrationID == nil || *got.ArtifactRegistrationID != registrationID ||
					got.Checksums.Acceptance == nil || *got.Checksums.Acceptance != strings.Repeat("d", 64) ||
					got.Task.Status != "succeeded" || !got.ArtifactUsable || !got.AcceptanceEligible {
					t.Fatal("persisted catalog registration or distinct artifact checksums changed", got)
				}
			} else if got.Checksums.Catalog != nil || got.ArtifactRegistrationHash != nil || got.ArtifactRegistrationID != nil {
				t.Fatal("missing registration acquired a catalog checksum", got)
			}
			if got.AcceptanceReady || f.rechecks != 1 || f.commits != 1 || f.rollbacks != 0 ||
				f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatal("catalog projection changed current readiness or authorized snapshot boundaries", got, f.options)
			}
		})
	}
}
