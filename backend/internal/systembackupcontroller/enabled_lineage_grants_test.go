package systembackupcontroller

import (
	"reflect"
	"strings"
	"testing"
)

func TestOriginalEnabledLineagePrivilegesReachExactConsumerProfiles(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		for _, permits := range []bool{false, true} {
			for _, publication := range []bool{false, true} {
				matrix := controlEvidenceTableGrants(runtime, permits, publication)
				for _, table := range []string{"system_backup_v2_installation_state", "system_backup_v2_configs", "system_backup_v2_operations", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_kek_admissions", "system_backup_v2_kek_bindings"} {
					found := false
					for _, verb := range matrix[table] {
						found = found || verb == "SELECT"
					}
					if !found {
						t.Fatal("same-view lineage SELECT omitted", runtime, permits, publication, table)
					}
				}
				if !reflect.DeepEqual(matrix["system_backup_v2_kek_admissions"], []string{"SELECT"}) {
					t.Fatal("lineage admission gained mutation privileges")
				}
				if !publication && !reflect.DeepEqual(matrix["system_backup_v2_evidence_chunks"], []string{"SELECT"}) {
					t.Fatal("formal lineage chunk read gained mutation privileges")
				}
				grants, err := ControlEvidenceGrantSQL("capture", "reader", "127.0.0.1", false, runtime, permits, publication)
				if err != nil {
					t.Fatal(err)
				}
				for i := range grants {
					grants[i] = strings.TrimSuffix(grants[i], ";")
				}
				if err = validateControllerGrants("capture", grants, matrix); err != nil {
					t.Fatal("generated exact role rejected", err)
				}
				for _, table := range []string{"system_backup_v2_kek_admissions", "system_backup_v2_evidence_chunks"} {
					missing := []string{}
					for _, statement := range grants {
						if !strings.Contains(statement, ".`"+table+"` TO") {
							missing = append(missing, statement)
						}
					}
					if validateControllerGrants("capture", missing, matrix) == nil {
						t.Fatal("missing lineage SELECT accepted", table)
					}
				}
				for _, verb := range []string{"INSERT", "UPDATE", "DELETE"} {
					extra := append(append([]string(nil), grants...), "GRANT "+verb+" ON `capture`.`system_backup_v2_kek_admissions` TO 'reader'@'127.0.0.1'")
					if validateControllerGrants("capture", extra, matrix) == nil {
						t.Fatal("extra admission DML accepted", verb)
					}
				}
			}
		}
	}
	if _, ok := controllerTableGrants["system_backup_v2_kek_admissions"]; ok {
		t.Fatal("historical14 profile changed")
	}
	if _, ok := publicCaptureTableGrants["system_backup_v2_kek_admissions"]; ok {
		t.Fatal("standalone capture profile changed")
	}
}
