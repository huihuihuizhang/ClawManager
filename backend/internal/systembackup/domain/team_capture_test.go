package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/team"
)

func currentTeamCaptureFixture(t *testing.T) (Snapshot, team.Inventory) {
	t.Helper()
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
	return s, inv
}

func TestTeamCoverageRequiresValidOriginalSQLSnapshot(t *testing.T) {
	s, inv := currentTeamCaptureFixture(t)
	if err := VerifyTeamCapture(s, inv); err != nil {
		t.Fatal("valid empty C scope", err)
	}
	s.Version = "unknown-source-codec"
	if err := VerifyTeamCapture(s, inv); err == nil {
		t.Fatal("C coverage blessed an invalid original SQL snapshot")
	}
}

func TestTeamWorkspaceSpecDoesNotPublishPlainSQLFingerprint(t *testing.T) {
	s, inv := currentTeamCaptureFixture(t)
	inv.Teams = []team.SourceTeam{{ID: 20, UserID: 4, ResourceScope: "cm", Status: "running", SharedMountID: "team_20", RedisScopeID: "redis_a"}}
	inv.Mounts = []team.SharedMount{{ID: "team_20", TeamID: 20, Namespace: "source", PVC: "source-pvc", UID: "fixture-pvc-uid", Root: "/team"}}
	inv.Redis = []team.RedisScope{{ID: "redis_a", ServerID: strings.Repeat("a", 40), TeamIDs: []int{20}}}
	for n := range s.Tables {
		if s.Tables[n].Name == "teams" {
			row := Row{}
			for _, column := range s.Tables[n].Columns {
				row[column.Name] = Text("0")
				if column.Nullable {
					row[column.Name] = Cell{Null: true}
				}
			}
			for name, value := range map[string]string{"id": "20", "user_id": "4", "resource_scope": "cm", "status": "running", "shared_pvc_name": "source-pvc", "shared_pvc_namespace": "source", "shared_mount_path": "/team"} {
				row[name] = Text(value)
			}
			s.Tables[n].Rows = []Row{row}
		}
	}
	spec, err := NewTeamWorkspaceSpec(s, inv, 20, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	plainDigest, _ := Digest(s)
	if bytes.Contains(raw, []byte(plainDigest)) {
		t.Fatal("public worker configuration exposes a dictionary-testable plaintext SQL fingerprint")
	}
}
