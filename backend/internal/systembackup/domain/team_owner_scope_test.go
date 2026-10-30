package domain

import (
	"context"
	"testing"
)

func TestOwnerTeamProvisionHistoryIsCapturedAndCannotReplay(t *testing.T) {
	if _, ok := rules()["owner_team_provision_steps"]; !ok {
		t.Fatal("public SQL capture silently omits owner Team provisioning history")
	}
	source, _, policy := teamFixture()
	steps := table("owner_team_provision_steps", Row{"team_id": Text("20"), "step_key": Text("member"), "operation_id": Text("source-operation"), "status": Text("started"), "updated_at": Text("2026-10-30 00:00:00")})
	steps.PrimaryKey = []string{"team_id", "step_key"}
	locks := table("owner_team_admission_locks", Row{"team_id": Text("20")})
	locks.PrimaryKey = []string{"team_id"}
	source.Tables = append(source.Tables, steps, locks)
	before, _ := Digest(source)
	plan, err := Normalize(context.Background(), source, source.Tables, policy)
	if err != nil {
		t.Fatal(err)
	}
	row := find(plan.Data, "owner_team_provision_steps").Rows[0]
	if row["status"].String() != "failed" || row["operation_id"].String() == "source-operation" || row["step_key"].String() != "member" || len(find(plan.Data, "owner_team_admission_locks").Rows) != 0 {
		t.Fatal("provisioning history lost or live authority copied")
	}
	after, _ := Digest(source)
	if before != after {
		t.Fatal("archive changed")
	}
	steps.Rows[0]["team_id"] = Text("999")
	if _, err = Normalize(context.Background(), source, source.Tables, policy); err == nil {
		t.Fatal("orphan provisioning step accepted")
	}
}
