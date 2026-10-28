package domain

import "strings"

// Explicit inventory from migrations 014/017/018/032/035/036/037/042/046.
// Do not derive an allowlist from reflection: new model fields need review.
var teamColumns = map[string]string{
	"teams":                      "id user_id resource_scope owner display_name name description status communication_mode redis_url_secret_name redis_url_secret_key team_token_secret_name team_token_secret_key redis_events_last_id shared_pvc_name shared_pvc_namespace shared_mount_path storage_class created_at updated_at",
	"team_members":               "id team_id instance_id user_id member_key display_name icon_key role runtime_type instance_mode description status current_task_id progress last_seen_at availability runtime_status runtime_task_id runtime_intent blocked_reason last_summary created_at updated_at",
	"team_tasks":                 "id team_id target_member_id created_by message_id status workflow_state plan_version ledger_version current_phase_id accepted_completion_id payload_json result_json error_message redis_stream_id created_at dispatched_at started_at finished_at updated_at",
	"team_events":                "id event_id completion_id sequence_no team_id member_id task_id message_id event_type payload_json redis_stream_id occurred_at created_at",
	"team_work_items":            "id team_id root_task_id work_id assignment_id canonical_work_id phase_id revision required_for_root superseded_by review_required validated_revision review_target_assignment_id review_target_revision owner_member_id title status depends_on_json result_json artifact_refs_json created_at started_at finished_at updated_at",
	"team_workflow_phases":       "id team_id root_task_id phase_id plan_version sequence_no status required_for_root decision_required depends_on_json next_phase_id completion_policy created_at completed_at updated_at",
	"team_event_outbox":          "id team_id source_event_id destination message_id payload_json status attempts available_at last_error delivered_at created_at updated_at",
	"team_workspace_file_audits": "id team_id user_id action relative_path bytes created_at",
	"custom_team_templates":      "id user_id resource_scope owner last_operation_id name intent requested_member_count resolved_member_count spec_json revision last_trace_id created_at updated_at",
}

func normalizeTeam(table string, r Row, p Policy) error {
	switch table {
	case "teams":
		// Only creating/running teams are selected by the actual team scheduler.
		switch r["status"].String() {
		case "failed", "deleted":
		case "creating", "running", "deleting":
			set(r, "status", Text("failed"))
		default:
			return ErrNormalization
		}
		clearFields(r, "redis_url_secret_name redis_url_secret_key team_token_secret_name team_token_secret_key")
		set(r, "redis_events_last_id", Text("0-0"))
		if v := r["shared_pvc_name"]; !v.Null && v.String() != "" {
			placement, ok := p.TeamPlacements[r["id"].String()]
			if !ok || placement.PVC == "" || !strings.HasPrefix(placement.Namespace, "cm-drill-") || !safeRoot(placement.MountPath) {
				return ErrNormalization
			}
			set(r, "shared_pvc_name", Text(placement.PVC))
			set(r, "shared_pvc_namespace", Text(placement.Namespace))
			set(r, "shared_mount_path", Text(placement.MountPath))
			set(r, "storage_class", Text(placement.StorageClass))
		}
	case "team_members":
		if r["status"].String() != "deleted" {
			set(r, "status", Text("offline"))
		}
		set(r, "availability", Text("offline"))
		clearFields(r, "current_task_id last_seen_at runtime_status runtime_task_id runtime_intent blocked_reason")
	case "team_work_items":
		switch r["status"].String() {
		case "succeeded", "failed", "cancelled", "skipped", "superseded", "stale":
		case "pending", "dispatched", "running", "waiting", "blocked", "awaiting_review", "planned":
			set(r, "status", Text("failed"))
		default:
			return ErrNormalization
		}
	case "custom_team_templates":
		clearFields(r, "last_operation_id")
	case "team_tasks":
		switch r["status"].String() {
		case "succeeded", "failed", "stale":
		case "pending", "dispatched", "running", "waiting":
			set(r, "status", Text("failed"))
		default:
			return ErrNormalization
		}
		if table == "team_tasks" {
			if r["workflow_state"].String() != "completed" {
				set(r, "workflow_state", Text("failed"))
			}
			clearFields(r, "redis_stream_id current_phase_id")
		}
	case "team_workflow_phases":
		switch r["status"].String() {
		case "completed", "cancelled", "superseded":
		case "planned", "active", "awaiting_results", "awaiting_leader_decision":
			set(r, "status", Text("cancelled"))
		default:
			return ErrNormalization
		}
	case "team_events":
		clearFields(r, "redis_stream_id")
	case "team_event_outbox":
		// Outbox is encrypted history only; it is dropped before this normalizer.
		return ErrNormalization
	}
	return nil
}
