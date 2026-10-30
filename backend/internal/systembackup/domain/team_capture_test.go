package domain

import (
	"encoding/json"
	"os"
	"testing"

	"clawreef/internal/systembackup/team"
)

func TestTeamCoverageRequiresValidOriginalSQLSnapshot(t *testing.T) {
	// Repository schema metadata with zero C rows is sufficient to reproduce
	// accepting an unknown snapshot codec before any real target is involved.
	raw, err := os.ReadFile("../team/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var shapes []struct {
		Name       string
		Columns    []struct{ Name, Type, Nullable, Extra string }
		PrimaryKey []string `json:"primary_key"`
	}
	if err := json.Unmarshal(raw, &shapes); err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Version: Version, Tables: []Table{table("users", Row{"id": Text("4")}), table("instances", Row{"id": Text("7"), "user_id": Text("4")}), table("user_quotas", Row{"id": Text("8"), "user_id": Text("4")})}}
	for _, shape := range shapes {
		tbl := Table{Name: shape.Name, Engine: "InnoDB", PrimaryKey: shape.PrimaryKey}
		for _, c := range shape.Columns {
			tbl.Columns = append(tbl.Columns, Column{Name: c.Name, Type: c.Type, Nullable: c.Nullable == "YES", Extra: c.Extra})
		}
		s.Tables = append(s.Tables, tbl)
	}
	inv := team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256()}
	if err := VerifyTeamCapture(s, inv); err != nil {
		t.Fatal("valid empty C scope", err)
	}
	s.Version = "unknown-source-codec"
	if err := VerifyTeamCapture(s, inv); err == nil {
		t.Fatal("C coverage blessed an invalid original SQL snapshot")
	}
}
