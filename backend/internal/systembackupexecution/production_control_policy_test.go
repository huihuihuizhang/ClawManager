package systembackupexecution

import (
	"encoding/json"
	"testing"
)

func TestProductionControlApprovalMatchesExactCensusAndOriginalClassification(t *testing.T) {
	raw := []byte(`{"objects":[{"object_type":"table","name":"gateway_runtime_tasks","category":"system_backup","data_classification":"secret","backup_strategy":"metadata_only","restore_strategy":"reference_only"},{"object_type":"table","name":"system_backup_gate","category":"system_backup","data_classification":"internal","backup_strategy":"metadata_only","restore_strategy":"reference_only"}]}`)
	names := []string{"gateway_runtime_tasks", "system_backup_gate"}
	if err := validateOriginalControlPolicy(raw, names, names); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing", "unknown", "wrong-classification", "business-name", "captured-control", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			var document map[string]any
			json.Unmarshal(raw, &document)
			objects := document["objects"].([]any)
			selected := append([]string{}, names...)
			switch fault {
			case "missing":
				selected = selected[1:]
			case "unknown":
				selected = append(selected, "system_backup_v2_unreviewed")
			case "wrong-classification":
				objects[0].(map[string]any)["data_classification"] = "internal"
			case "business-name":
				objects[0].(map[string]any)["name"] = "users"
			case "captured-control":
				objects[0].(map[string]any)["backup_strategy"] = "mysql_dump"
			case "duplicate":
				document["objects"] = append(objects, objects[0])
			}
			changed, _ := json.Marshal(document)
			if err := validateOriginalControlPolicy(changed, selected, names); err == nil {
				t.Fatal("altered frozen control scope/classification accepted", fault)
			}
		})
	}
}
