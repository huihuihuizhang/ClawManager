package domain

import (
	"context"
	"strings"

	"clawreef/internal/systembackup/scope"
)

// Dependency tables are captured in the SAME transaction as users/instances.
// Known local schemas have explicit normalizers. Other owners may provide an
// exact schema adapter; nonempty unadapted tables block restore, never vanish.
func dependencyRules() []scope.TableRule {
	var out []scope.TableRule
	for _, d := range scope.CrossDomainDependencies() {
		for _, name := range d.Tables {
			action := "preserve"
			if name == "instance_gateway_token_aliases" || name == "skill_package_materialize_jobs" || name == "team_event_outbox" {
				action = "drop"
			}
			out = append(out, scope.TableRule{Name: name, Domain: d.Domain, RestoreAction: action, Reason: "Portable users/instances dependency; preserve encrypted source rows and normalize with the owning schema."})
		}
	}
	for _, name := range []string{"skill_hub_tags", "skill_hub_tag_assignments", "skill_scan_results"} {
		out = append(out, scope.TableRule{Name: name, Domain: "skill_hub", RestoreAction: "preserve", Reason: "Skill metadata dependency."})
	}
	return out
}

type TableAdapter struct {
	SchemaSHA256 string
	// Every column must occur exactly once. Actions: preserve, null, stub, or
	// fixed:<terminal value>. Definitions/JSON still use the config registry.
	Columns map[string]string
}

func (a TableAdapter) validate(t Table) error {
	if SchemaDigest(t) != a.SchemaSHA256 || len(a.Columns) != len(t.Columns) {
		return ErrSchema
	}
	for _, c := range t.Columns {
		action, ok := a.Columns[c.Name]
		if !ok || (action != "preserve" && action != "null" && action != "stub" && !strings.HasPrefix(action, "fixed:")) {
			return ErrSchema
		}
	}
	return nil
}
func applyAdapter(ctx context.Context, r Row, a TableAdapter) error {
	for name, action := range a.Columns {
		switch {
		case action == "preserve":
		case action == "null":
			r[name] = Cell{Null: true}
		case action == "stub":
			v, e := (JSONRegistry{"s": {{Action: "stub"}}}).NormalizeJSON(ctx, "s", Text(`"credential"`))
			if e != nil {
				return e
			}
			// NormalizeJSON returns a JSON string; use its unquoted ASCII value.
			r[name] = Text(strings.Trim(v.String(), `"`))
		case strings.HasPrefix(action, "fixed:"):
			r[name] = Text(strings.TrimPrefix(action, "fixed:"))
		default:
			return ErrNormalization
		}
	}
	return nil
}

var dependencyColumns = map[string]string{
	"llm_models":                "id display_name description provider_type protocol_type base_url provider_model_name provider_models_json reasoning_enabled api_key api_key_secret_ref is_secure is_active input_price output_price currency created_at updated_at",
	"chat_sessions":             "id session_id user_id instance_id title last_trace_id started_at last_activity_at",
	"chat_messages":             "id trace_id session_id request_id user_id instance_id invocation_id role content sequence_no created_at",
	"skills":                    "id user_id skill_key name description current_version_id source_type status visibility published_at published_by risk_level last_scanned_at last_scan_result_id created_at updated_at",
	"skill_versions":            "id skill_id blob_id version_no manifest_json source_type created_at updated_at",
	"skill_blobs":               "id content_hash archive_hash object_key file_name media_type size_bytes scan_status risk_level last_scanned_at last_scan_result_id created_at updated_at",
	"instance_skills":           "id instance_id skill_id skill_version_id source_type install_path workspace_dir observed_hash status last_seen_at removed_at created_at updated_at",
	"skill_hub_tags":            "id tag_key name description sort_order admin_only created_at updated_at",
	"skill_hub_tag_assignments": "id skill_id tag_id created_at",
	"skill_scan_results":        "id blob_id engine risk_level status summary findings_json scanned_at created_at",
}

// validateForeignKeys prevents an apparently successful partial restore with
// omitted model/skill/session dependencies, even when the DB has no FK enabled.
func validateDependencyLinks(s Snapshot) error {
	index := map[string]map[string]map[string]bool{}
	byID := map[string]map[string]Row{}
	for _, t := range s.Tables {
		byID[t.Name] = map[string]Row{}
		for _, r := range t.Rows {
			if id, ok := r["id"]; ok && !id.Null {
				byID[t.Name][id.String()] = r
			}
		}
		index[t.Name] = map[string]map[string]bool{}
		for _, c := range t.Columns {
			values := map[string]bool{}
			for _, r := range t.Rows {
				if !r[c.Name].Null {
					values[r[c.Name].String()] = true
				}
			}
			index[t.Name][c.Name] = values
		}
	}
	for _, t := range s.Tables {
		for _, fk := range t.ForeignKeys {
			for _, r := range t.Rows {
				v := r[fk.Column]
				if !v.Null && !index[fk.Table][fk.Reference][v.String()] {
					return ErrData
				}
			}
		}
	}
	// Logical keys absent from older database schemas.
	for _, t := range s.Tables {
		for _, r := range t.Rows {
			var refs map[string][2]string
			switch t.Name {
			case "chat_messages":
				refs = map[string][2]string{"session_id": {"chat_sessions", "session_id"}}
			case "openclaw_config_bundle_skills":
				refs = map[string][2]string{"skill_id": {"skills", "id"}}
			case "skills":
				refs = map[string][2]string{"current_version_id": {"skill_versions", "id"}}
			case "skill_versions":
				refs = map[string][2]string{"skill_id": {"skills", "id"}, "blob_id": {"skill_blobs", "id"}}
			case "instance_skills":
				refs = map[string][2]string{"skill_id": {"skills", "id"}, "skill_version_id": {"skill_versions", "id"}}
			case "team_members":
				refs = map[string][2]string{"team_id": {"teams", "id"}}
			case "team_tasks":
				refs = map[string][2]string{"team_id": {"teams", "id"}, "target_member_id": {"team_members", "id"}}
			case "team_events":
				refs = map[string][2]string{"team_id": {"teams", "id"}, "member_id": {"team_members", "id"}, "task_id": {"team_tasks", "id"}}
			case "team_work_items":
				refs = map[string][2]string{"team_id": {"teams", "id"}, "root_task_id": {"team_tasks", "id"}, "owner_member_id": {"team_members", "id"}}
			case "team_workflow_phases":
				refs = map[string][2]string{"team_id": {"teams", "id"}, "root_task_id": {"team_tasks", "id"}}
			}
			for col, to := range refs {
				if v, ok := r[col]; ok && !v.Null && !index[to[0]][to[1]][v.String()] {
					return ErrData
				}
				if team, ok := r["team_id"]; ok && to[1] == "id" {
					v, has := r[col]
					if has && !v.Null {
						if other, hasTeam := byID[to[0]][v.String()]["team_id"]; hasTeam && other.String() != team.String() {
							return ErrData
						}
					}
				}
			}
			if t.Name == "team_members" {
				if owner, exists := byID["teams"][r["team_id"].String()]["user_id"]; exists && owner.String() != r["user_id"].String() {
					return ErrData
				}
				if instance, exists := r["instance_id"]; exists && !instance.Null {
					if byID["instances"][instance.String()]["user_id"].String() != r["user_id"].String() {
						return ErrData
					}
				}
			}
		}
	}
	return nil
}
