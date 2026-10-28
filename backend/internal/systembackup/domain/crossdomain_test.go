package domain

import (
	"context"
	"testing"
)

func teamFixture() (Snapshot, []Table, Policy) {
	s, target, p := fixture()
	extra := []Table{
		table("teams", Row{"id": Text("20"), "user_id": Text("4"), "status": Text("running"), "shared_pvc_name": Text("source-volume"), "shared_pvc_namespace": Text("production"), "shared_mount_path": Text("/shared"), "storage_class": Text("source-class"), "redis_url_secret_name": Text("source-redis"), "redis_events_last_id": Text("10-1")}),
		table("team_members", Row{"id": Text("21"), "team_id": Text("20"), "instance_id": Text("7"), "user_id": Text("4"), "status": Text("busy"), "availability": Text("busy"), "current_task_id": Text("22")}),
		table("team_tasks", Row{"id": Text("22"), "team_id": Text("20"), "target_member_id": Text("21"), "status": Text("running"), "workflow_state": Text("active"), "redis_stream_id": Text("10-2")}),
		table("team_work_items", Row{"id": Text("23"), "team_id": Text("20"), "root_task_id": Text("22"), "owner_member_id": Text("21"), "status": Text("waiting")}),
		table("team_workflow_phases", Row{"id": Text("24"), "team_id": Text("20"), "root_task_id": Text("22"), "status": Text("active")}),
		table("team_event_outbox", Row{"id": Text("25"), "team_id": Text("20"), "status": Text("pending")}),
		table("risk_rules", Row{"id": Text("30"), "is_enabled": Text("1"), "pattern": Text("synthetic-pattern")}),
		table("system_image_settings", Row{"id": Text("31"), "is_enabled": Text("1"), "image": Text("fixture@sha256:abc")}),
		table("egress_private_exceptions", Row{"id": Text("32"), "enabled": Text("1"), "cidr": Text("192.0.2.0/24")}),
		table("security_scan_jobs", Row{"id": Text("33"), "status": Text("running")}),
		table("model_invocations", Row{"id": Text("34"), "user_id": Text("4"), "instance_id": Text("7"), "status": Text("pending"), "gateway_id": Text("source-gateway"), "runtime_pod_id": Text("source-pod")}),
	}
	s.Tables = append(s.Tables, extra...)
	target = append(target, extra...)
	p.TeamPlacements = map[string]Placement{"20": {PVC: "restored-shared", Namespace: "cm-drill-team", MountPath: "/shared", StorageClass: "isolated"}}
	return s, target, p
}

func TestCrossDomainRestoreKeepsDefinitionsAndDisablesExecution(t *testing.T) {
	s, target, p := teamFixture()
	before, _ := Digest(s)
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]string{"teams": "failed", "team_members": "offline", "team_tasks": "failed", "team_work_items": "failed", "team_workflow_phases": "cancelled", "security_scan_jobs": "failed", "model_invocations": "failed"} {
		if find(plan.Data, name).Rows[0]["status"].String() != expected {
			t.Fatalf("%s can execute", name)
		}
	}
	team := find(plan.Data, "teams").Rows[0]
	if team["shared_pvc_name"].String() != "restored-shared" || team["shared_pvc_namespace"].String() != "cm-drill-team" || !team["redis_url_secret_name"].Null {
		t.Fatal("source bindings retained")
	}
	if len(find(plan.Data, "team_event_outbox").Rows) != 0 {
		t.Fatal("outbox replay")
	}
	if find(plan.Data, "risk_rules").Rows[0]["pattern"].String() != "synthetic-pattern" || find(plan.Data, "risk_rules").Rows[0]["is_enabled"].String() != "0" || find(plan.Data, "egress_private_exceptions").Rows[0]["enabled"].String() != "0" {
		t.Fatal("definition lost or execution enabled")
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source mutated")
	}
}

func TestTeamRestoreRequiresKnownStatesLinksVolumesAndJSONPolicy(t *testing.T) {
	for _, scenario := range []string{"missing-volume", "source-namespace", "orphan-task", "unknown-status", "unknown-column", "missing-json-policy"} {
		t.Run(scenario, func(t *testing.T) {
			s, target, p := teamFixture()
			switch scenario {
			case "missing-volume":
				p.TeamPlacements = nil
			case "source-namespace":
				p.TeamPlacements["20"] = Placement{PVC: "source", Namespace: "production", MountPath: "/shared"}
			case "orphan-task":
				find(s, "team_tasks").Rows[0]["target_member_id"] = Text("999")
			case "unknown-status":
				find(s, "team_tasks").Rows[0]["status"] = Text("new-executor-state")
			case "unknown-column", "missing-json-policy":
				name := "future_executor"
				if scenario == "missing-json-policy" {
					name = "payload_json"
				}
				for n := range s.Tables {
					if s.Tables[n].Name == "team_tasks" {
						s.Tables[n].Columns = append(s.Tables[n].Columns, Column{Name: name, Type: "text", Nullable: true})
						s.Tables[n].Rows[0][name] = Text(`{"token":"synthetic"}`)
					}
				}
				for n := range target {
					if target[n].Name == "team_tasks" {
						target[n] = find(s, "team_tasks")
					}
				}
			}
			if _, e := Normalize(context.Background(), s, target, p); e == nil {
				t.Fatal("unsafe restore accepted")
			}
		})
	}
}
