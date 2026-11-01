package systembackup

import (
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/team"
)

func TestRoutingSharedOwnerPolicyPreservesLegacyContract(t *testing.T) {
	for _, nullable := range []string{"YES", "NO"} {
		source := team.Row{"routing_mode": team.Value("laya"), "base_url": team.Value("https://original.invalid"), "encrypted_api_key": team.Value("original-ciphertext"), "timeout_ms": team.Value("5000")}
		original := team.Clone(source)
		table := SQLTable{Name: "routing_classifier_settings", Columns: []SQLColumn{{Name: "routing_mode", Nullable: "NO"}, {Name: "base_url", Nullable: nullable}, {Name: "encrypted_api_key", Nullable: nullable}, {Name: "timeout_ms", Nullable: "NO"}}}
		change, err := NormalizeDataRow(table, source, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
		if err != nil || change.Reason != "restore_disabled" || !change.Quarantined || !reflect.DeepEqual(change.Before, original) || !reflect.DeepEqual(source, original) || string(change.After["routing_mode"].Data) != "rules" {
			t.Fatal("legacy owner contract changed", err)
		}
		for _, name := range []string{"base_url", "encrypted_api_key"} {
			cell := change.After[name]
			if cell.IsNull != (nullable == "YES") || len(cell.Data) != 0 {
				t.Fatal("legacy nullability changed", nullable, name)
			}
		}
		change.After["timeout_ms"].Data[0] = '9'
		if !reflect.DeepEqual(change.Before, original) || !reflect.DeepEqual(source, original) {
			t.Fatal("target aliases source/Before")
		}
		change.Before["encrypted_api_key"].Data[0] = 'X'
		if !reflect.DeepEqual(source, original) {
			t.Fatal("Before aliases source")
		}
	}
}
