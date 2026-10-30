package domain

import (
	"slices"
	"strings"
)

// VerifyTeamQuarantine independently checks the restored C projection. An
// encrypted "expected" receipt is evidence of bytes, never permission to start
// consumers, owner retries or old task execution. The normal SQL verifier still
// reads every target row and omitted/control table with its SELECT-only grant.
func VerifyTeamQuarantine(snapshot Snapshot) error {
	for _, table := range snapshot.Tables {
		if _, owned := teamColumns[table.Name]; !owned {
			continue
		}
		for _, r := range table.Rows {
			var terminal, cleared []string
			switch table.Name {
			case "teams":
				terminal = []string{"failed", "deleted"}
				cleared = strings.Fields("redis_url_secret_name redis_url_secret_key team_token_secret_name team_token_secret_key")
				if v, ok := r["redis_events_last_id"]; ok && v.String() != "0-0" {
					return ErrNormalization
				}
				if v := r["shared_pvc_name"]; !v.Null && v.String() != "" {
					if !strings.HasPrefix(r["shared_pvc_namespace"].String(), "cm-drill-") || !safeRoot(r["shared_mount_path"].String()) {
						return ErrIsolation
					}
				}
			case "team_members":
				terminal = []string{"offline", "deleted"}
				cleared = strings.Fields("current_task_id last_seen_at runtime_status runtime_task_id runtime_intent blocked_reason")
				if v, ok := r["availability"]; ok && v.String() != "offline" {
					return ErrNormalization
				}
			case "team_tasks":
				terminal = []string{"succeeded", "failed", "stale"}
				cleared = strings.Fields("redis_stream_id current_phase_id")
				if v, ok := r["workflow_state"]; ok && (v.Null || !slices.Contains([]string{"completed", "failed"}, v.String())) {
					return ErrNormalization
				}
			case "team_work_items":
				terminal = []string{"succeeded", "failed", "cancelled", "skipped", "superseded", "stale"}
			case "team_workflow_phases":
				terminal = []string{"completed", "cancelled", "superseded"}
			case "owner_team_provision_steps":
				terminal = []string{"done", "failed"}
				if r["operation_id"].String() != "drill-disabled" {
					return ErrNormalization
				}
			case "custom_team_templates":
				cleared = []string{"last_operation_id"}
			case "team_events":
				cleared = []string{"redis_stream_id"}
			case "team_event_outbox", "owner_team_admission_locks":
				return ErrNormalization
			}
			if len(terminal) != 0 && !slices.Contains(terminal, r["status"].String()) {
				return ErrNormalization
			}
			for _, name := range cleared {
				if v, ok := r[name]; ok && !v.Null {
					return ErrNormalization
				}
			}
		}
	}
	return nil
}
