package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestHistoricalCapturePinsDoNotSubstituteCurrentRestoreActions(t *testing.T) {
	if BusinessCapturePolicySHA256() != capturePolicySkillHistoryV1 {
		t.Fatal("current capture contract changed; review historical pin support")
	}
	old := rules()
	rule := old["skill_package_materialize_jobs"]
	rule.RestoreAction = "drop"
	old["skill_package_materialize_jobs"] = rule
	raw, _ := json.Marshal(struct {
		Rules  any
		Census string
	}{old, SchemaCensusPolicySHA256()})
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != capturePolicyBaselineV1 {
		t.Fatal("baseline capture contract changed")
	}
	snapshot := Snapshot{Version: Version}
	for _, name := range BusinessCaptureTables() {
		snapshot.Tables = append(snapshot.Tables, Table{Name: name, Engine: "InnoDB", Columns: []Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}, Rows: []Row{{"id": Text("1")}}})
	}
	original, err := BusinessCaptureSchemaForTables(snapshot.Tables)
	if err != nil {
		t.Fatal(err)
	}
	original.PolicySHA256 = capturePolicyBaselineV1
	before := copyTables(snapshot.Tables)
	if VerifyBusinessCapturedSnapshot(snapshot, original) == nil {
		t.Fatal("current capture verifier silently accepted historical policy")
	}
	if MatchHistoricalBusinessCaptureSchema(snapshot, original) != nil || !reflect.DeepEqual(before, snapshot.Tables) {
		t.Fatal("historical byte contract changed")
	}
	for _, pin := range []string{strings.Repeat("0", 64), "", "latest"} {
		bad := original
		bad.PolicySHA256 = pin
		if MatchHistoricalBusinessCaptureSchema(snapshot, bad) == nil {
			t.Fatal("unreviewed policy accepted")
		}
	}
	for i := range snapshot.Tables {
		if snapshot.Tables[i].Name == "gateway_keys" {
			// Plausible metadata must not be manufactured for an old archive whose
			// original schema digest omitted that metadata.
			snapshot.Tables[i].UniqueKeys = []UniqueKey{{Name: "historical_missing_unique", Columns: []string{"id"}}}
		}
	}
	if MatchHistoricalBusinessCaptureSchema(snapshot, original) == nil {
		t.Fatal("synthetic unique metadata rewrote original archive")
	}
	current, err := BusinessCaptureSchemaForTables(snapshot.Tables)
	if err != nil || MatchHistoricalBusinessCaptureSchema(snapshot, current) != nil {
		t.Fatal("current exact metadata rejected", err)
	}
	for i := range snapshot.Tables {
		snapshot.Tables[i].UniqueKeys = nil
	}
	if MatchHistoricalBusinessCaptureSchema(snapshot, current) == nil {
		t.Fatal("lost current metadata accepted as historical omission")
	}
}
