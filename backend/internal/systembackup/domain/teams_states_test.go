package domain

import (
	"bytes"
	"context"
	"testing"
)

func TestTeamArtifactReferencesCannotBeSilentlyRedactedByConfigPolicy(t *testing.T) {
	s, schema, p := teamFixture()
	for n := range s.Tables {
		if s.Tables[n].Name == "team_work_items" {
			s.Tables[n].Columns = append(s.Tables[n].Columns, Column{Name: "artifact_refs_json", Type: "text", Nullable: true})
			s.Tables[n].Rows[0]["artifact_refs_json"] = Text("[ \"/team/results/报告.bin\" ]")
		}
	}
	schema = s.Tables
	p.Configs = JSONRegistry{"team_work_items.artifact_refs_json": {{Path: []string{"*"}, Action: "stub"}}}
	plan, err := Normalize(context.Background(), s, schema, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(find(plan.Data, "team_work_items").Rows[0]["artifact_refs_json"].Bytes, find(s, "team_work_items").Rows[0]["artifact_refs_json"].Bytes) {
		t.Fatal("artifact locations were rewritten as credentials, losing task products")
	}
}

func TestPublicTeamRestoreRejectsUnknownMemberAndWorkflowState(t *testing.T) {
	for _, field := range []string{"member", "workflow"} {
		t.Run(field, func(t *testing.T) {
			s, schema, p := teamFixture()
			if field == "member" {
				find(s, "team_members").Rows[0]["status"] = Text("unregistered-state")
			} else {
				find(s, "team_tasks").Rows[0]["workflow_state"] = Text("unregistered-state")
			}
			if _, err := Normalize(context.Background(), s, schema, p); err == nil {
				t.Fatal("unknown Team state was guessed into an apparently safe result")
			}
		})
	}
}

func TestIndependentTeamVerificationRejectsExecutableExpectedPlan(t *testing.T) {
	for _, mode := range []string{"valid", "team", "member", "work", "workflow", "credentials", "outbox", "locks", "owner-operation", "template-operation", "source-volume"} {
		t.Run(mode, func(t *testing.T) {
			s, schema, p := teamFixture()
			plan, err := Normalize(context.Background(), s, schema, p)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "team":
				find(plan.Data, "teams").Rows[0]["status"] = Text("running")
			case "member":
				find(plan.Data, "team_members").Rows[0]["current_task_id"] = Text("22")
			case "work":
				find(plan.Data, "team_work_items").Rows[0]["status"] = Text("awaiting_review")
			case "workflow":
				find(plan.Data, "team_tasks").Rows[0]["workflow_state"] = Text("executing")
			case "credentials":
				find(plan.Data, "teams").Rows[0]["redis_url_secret_name"] = Text("source")
			case "outbox":
				plan.Data.Tables = append(plan.Data.Tables, table("team_event_outbox", Row{"id": Text("25")}))
			case "locks":
				plan.Data.Tables = append(plan.Data.Tables, table("owner_team_admission_locks", Row{"team_id": Text("20")}))
			case "owner-operation":
				plan.Data.Tables = append(plan.Data.Tables, table("owner_team_provision_steps", Row{"team_id": Text("20"), "status": Text("done"), "operation_id": Text("live-operation")}))
			case "template-operation":
				plan.Data.Tables = append(plan.Data.Tables, table("custom_team_templates", Row{"id": Text("30"), "last_operation_id": Text("live-operation")}))
			case "source-volume":
				find(plan.Data, "teams").Rows[0]["shared_pvc_namespace"] = Text("production")
			}
			if err := VerifyTeamQuarantine(plan.Data); (err == nil) != (mode == "valid") {
				t.Fatalf("quarantine verification: %v", err)
			}
			if mode != "valid" {
				// This is the public verifier, not an uncalled policy helper. No
				// target or credentials can make an executable expected plan valid.
				if err := VerifyDrill(context.Background(), nil, DrillTarget{}, plan); err == nil {
					t.Fatal("public verifier bypassed C quarantine")
				}
			}
		})
	}
}
