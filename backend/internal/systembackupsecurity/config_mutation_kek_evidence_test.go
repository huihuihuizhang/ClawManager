package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Exercise actual database/sql transaction/row/chunk lock mechanics with the
// existing finite SQL model. The synthetic original source intentionally
// refuses after its lock-stage callback; it is never a KEK admission fixture.
func TestConfigMutationKEKLocksOriginalAndResponseUnionBeforeFence(t *testing.T) {
	for _, mode := range []string{"complete-union", "missing-capability-source", "foreign-source-id", "broken-chunk-order"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentCandidateFixture(t)
			observed := []string{}
			db := sql.OpenDB(bootstrapEvidenceConnector{f.sql, &observed})
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			responseID := "sev_00_actual_response"
			for i, id := range []string{responseID, "sev_a_original", "sev_b_generate", "sev_y_unwrap", "sev_z_original"} {
				f.sql.rows["system_backup_v2_evidence"] = append(f.sql.rows["system_backup_v2_evidence"], map[string]driver.Value{"id": int64(401 + i), "public_id": id})
			}
			original := &bootstrapEvidenceAdmission{ids: []string{"sev_z_original", "sev_a_original", "sev_z_original", string(f.sql.evidence.Evidence.EvidenceID)}, observation: reg.AdmissionObservation{GenerateCapabilitySource: reg.SourceRecord{RecordID: "sev_b_generate"}, UnwrapCapabilitySource: reg.SourceRecord{RecordID: "sev_y_unwrap"}}}
			wanted := []string{responseID, "sev_a_original", "sev_b_generate", "sev_y_unwrap", "sev_z_original", string(f.sql.evidence.Evidence.EvidenceID)}
			sort.Strings(wanted)
			switch mode {
			case "missing-capability-source":
				original.observation.GenerateCapabilitySource.RecordID = ""
			case "foreign-source-id":
				original.ids[0] = "../foreign"
			case "broken-chunk-order":
				f.sql.rows["system_backup_v2_evidence_chunks"][0]["chunk_index"] = int64(1)
			}
			calls := 0
			original.lock = func(actual context.Context, view reg.SQLReadView) error {
				calls++
				if actual != ctx || view != tx || !reflect.DeepEqual(observed, wanted) {
					t.Fatal("source callback ran before complete same-transaction sorted union", observed, wanted)
				}
				for _, query := range f.sql.queries {
					if strings.Contains(query, "system_backup_v2_kek_") {
						t.Fatal("KEK fence/registry before original evidence", query)
					}
				}
				return ErrRegistrationUnavailable
			}
			if lockConfigMutationKEKOriginalEvidence(ctx, tx, original, responseID) == nil || f.sql.commits != 0 {
				t.Fatal("synthetic source became actual mutation authority")
			}
			if (mode == "complete-union") != (calls == 1) {
				t.Fatal("original union stage reached incorrectly", mode, calls, observed)
			}
			if (mode == "missing-capability-source" || mode == "foreign-source-id") && len(observed) != 0 {
				t.Fatal("invalid source reached native locks")
			}
		})
	}
}
