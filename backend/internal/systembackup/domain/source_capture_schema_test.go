package domain

import (
	"strings"
	"testing"
)

func TestBusinessCaptureSchemaIndependentPolicyAndCompleteShape(t *testing.T) {
	snapshot := Snapshot{Version: Version}
	for _, name := range BusinessCaptureTables() {
		snapshot.Tables = append(snapshot.Tables, Table{Name: name, Engine: "InnoDB", Columns: []Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}, Rows: []Row{}})
	}
	actual, err := BusinessCaptureSchemaForTables(snapshot.Tables)
	if err != nil || VerifyBusinessCapturedSnapshot(snapshot, actual) != nil {
		t.Fatal("valid complete schema fixture", err)
	}
	for _, mode := range []string{"policy", "schema", "missing-core", "unknown-table"} {
		t.Run(mode, func(t *testing.T) {
			expected := actual
			expected.Tables = append([]string{}, actual.Tables...)
			switch mode {
			case "policy":
				expected.PolicySHA256 = strings.Repeat("0", 64)
			case "schema":
				expected.SchemaSHA256 = strings.Repeat("0", 64)
			case "missing-core":
				for n, name := range expected.Tables {
					if name == "users" {
						expected.Tables = append(expected.Tables[:n], expected.Tables[n+1:]...)
						break
					}
				}
			case "unknown-table":
				expected.Tables = append(expected.Tables, "zz_unknown_business")
			}
			if VerifyBusinessCapturedSnapshot(snapshot, expected) == nil {
				t.Fatal("independent scope accepted changed policy/schema/table set")
			}
		})
	}
}
