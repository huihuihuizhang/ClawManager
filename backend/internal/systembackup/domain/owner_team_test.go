package domain

import (
	"context"
	"testing"
)

func TestCurrentOwnerTeamDefinitionsSurviveIsolatedRestore(t *testing.T) {
	s, target, policy := teamFixture()
	for i := range s.Tables {
		var fields Row
		switch s.Tables[i].Name {
		case "teams":
			fields = Row{"resource_scope": Text("northbound"), "owner": Text("portal@example.test"), "display_name": Text("owner team")}
		case "team_members":
			fields = Row{"icon_key": Text("code"), "runtime_intent": Text("waiting")}
		case "team_work_items":
			s.Tables[i].Rows[0]["status"] = Text("awaiting_review")
		}
		for name, value := range fields {
			if !hasColumn(s.Tables[i], name) {
				s.Tables[i].Columns = append(s.Tables[i].Columns, Column{Name: name, Type: "text", Nullable: true})
			}
			s.Tables[i].Rows[0][name] = value
		}
	}
	target = append([]Table(nil), s.Tables...)
	template := table("custom_team_templates", Row{"id": Text("30"), "user_id": Text("4"), "resource_scope": Text("northbound"), "owner": Text("portal@example.test"), "name": Text("template"), "last_operation_id": Text("old-operation")})
	audit := table("team_workspace_file_audits", Row{"id": Text("31"), "team_id": Text("20"), "user_id": Text("4"), "relative_path": Text("results/report.md")})
	s.Tables = append(s.Tables, template, audit)
	target = append(target, template, audit)
	before, _ := Digest(s)
	plan, err := Normalize(context.Background(), s, target, policy)
	if err != nil {
		t.Fatal(err)
	}
	team := find(plan.Data, "teams").Rows[0]
	if team["resource_scope"].String() != "northbound" || team["owner"].String() != "portal@example.test" || team["display_name"].String() != "owner team" {
		t.Fatal("owner isolation or team definition lost")
	}
	if find(plan.Data, "team_members").Rows[0]["icon_key"].String() != "code" || !find(plan.Data, "team_members").Rows[0]["runtime_intent"].Null {
		t.Fatal("member definition lost or execution retained")
	}
	if find(plan.Data, "team_work_items").Rows[0]["status"].String() != "failed" {
		t.Fatal("review work can replay")
	}
	if !find(plan.Data, "custom_team_templates").Rows[0]["last_operation_id"].Null || find(plan.Data, "custom_team_templates").Rows[0]["owner"].String() != "portal@example.test" {
		t.Fatal("template owner lost or original operation can replay")
	}
	if find(plan.Data, "team_workspace_file_audits").Rows[0]["relative_path"].String() != "results/report.md" {
		t.Fatal("file history lost")
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source data changed")
	}
}

func TestLegacyTeamReceivesOnlyExplicitCMResourceScope(t *testing.T) {
	source, target, policy := teamFixture()
	for i := range target {
		if target[i].Name == "teams" {
			target[i].Columns = append(append([]Column(nil), target[i].Columns...), Column{Name: "resource_scope", Type: "varchar(16)", Default: ptr("cm")})
		}
	}
	plan, err := Normalize(context.Background(), source, target, policy)
	if err != nil {
		t.Fatal(err)
	}
	row := find(plan.Data, "teams").Rows[0]
	if row["resource_scope"].String() != "cm" {
		t.Fatal("legacy Team lost its original CM category")
	}
	if _, exists := row["owner"]; exists {
		t.Fatal("legacy Team received an invented owner")
	}
}

func ptr(value string) *string { return &value }
