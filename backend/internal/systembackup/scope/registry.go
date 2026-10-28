// Package scope inventories the users and instances domains without reading
// credentials or changing a source/target environment. Its plans are inputs to
// collectors, not capture certificates or the frozen system-backup wire contract.
package scope

import "fmt"

type Domain string

const (
	Users     Domain = "users"
	Instances Domain = "instances"
)

// TableRule separates preserving business data from replaying source execution
// state. Sensitive columns must be captured through the encrypted data plane;
// the registry contains column names only, never their values.
type TableRule struct {
	Name             string   `json:"name"`
	Domain           Domain   `json:"domain"`
	RestoreAction    string   `json:"restore_action"`
	DependsOn        []string `json:"depends_on,omitempty"`
	SensitiveColumns []string `json:"sensitive_columns,omitempty"`
	Reason           string   `json:"reason"`
}

// TableRegistry includes the upgrade tables added after the v12 human plan.
// A normalizer must implement these rules before a restore is considered safe.
func TableRegistry() []TableRule {
	return []TableRule{
		{"users", Users, "preserve", nil, []string{"password_hash"}, "Preserve account identity, role, auth provider and password hash through encrypted backup, not the API JSON DTO."},
		{"user_quotas", Users, "preserve", []string{"users"}, nil, "Preserve source resource limits and user ownership."},
		{"enterprise_auth_settings", Users, "disable", []string{"users"}, []string{"ldap_bind_password_ciphertext"}, "Retain settings and encrypted secret dependency; disable external authentication in a drill."},
		{"instances", Instances, "reset", []string{"users", "openclaw_injection_snapshots"}, []string{"access_token", "agent_bootstrap_token", "environment_overrides_json"}, "Preserve specification and ownership; stop instances, clear access tokens and map target resource identities."},
		{"persistent_volumes", Instances, "reset", []string{"instances"}, nil, "Provision target storage; never adopt a source PVC by name alone."},
		{"backups", Instances, "reference_only", []string{"instances"}, []string{"backup_path"}, "Historical instance backup metadata is not proof that its original artifact is portable."},
		{"backup_schedules", Instances, "disable", []string{"instances"}, nil, "Preserve schedule definitions with execution disabled."},
		{"instance_usage", Instances, "preserve", []string{"instances"}, nil, "Retain usage history."},
		{"instance_agents", Instances, "reset", []string{"instances"}, []string{"session_token", "host_info_json"}, "Discard source sessions and require fresh target registration."},
		{"instance_runtime_status", Instances, "reset", []string{"instances"}, []string{"summary_json", "system_info_json", "health_json"}, "Source PID, endpoint and health are not target runtime state."},
		{"instance_desired_state", Instances, "reset", []string{"instances", "instance_config_revisions"}, nil, "Set desired power to stopped and clear queued runtime actions."},
		{"instance_browser_workers", Instances, "disable", []string{"instances"}, []string{"last_error"}, "Preserve browser settings; disable the component, reset generations and clear source diagnostics. Never replay ready/provisioning state."},
		{"instance_commands", Instances, "disable", []string{"instances"}, []string{"payload_json", "result_json"}, "Retain command history without replaying unfinished commands."},
		{"instance_config_revisions", Instances, "preserve", []string{"instances", "openclaw_injection_snapshots", "openclaw_config_bundles"}, []string{"content_json"}, "Retain versioned configuration; secret-bearing content still requires the normalization registry."},
		{"instance_runtime_bindings", Instances, "drop", []string{"instances", "runtime_pods"}, nil, "Do not restore live gateway bindings to source pools or ports."},
		{"instance_external_access", Instances, "disable", []string{"instances"}, []string{"public_token_hash", "short_code_hash", "api_key_hash", "password_value"}, "Disable source share links and clear their authentication material."},
		{"runtime_pods", Instances, "reference_only", nil, []string{"agent_endpoint", "capabilities_json"}, "Source pool UID, endpoints and placement are diagnostic references, not target workloads."},
		{"runtime_rollouts", Instances, "reference_only", []string{"users"}, []string{"preflight_json", "source_images_json"}, "Do not replay source image rollouts."},
		{"runtime_upgrade_items", Instances, "reference_only", []string{"runtime_rollouts", "instances"}, []string{"snapshot_ref", "preflight_json", "postflight_json"}, "Upgrade execution evidence cannot resume in a different installation."},
		{"runtime_upgrade_audits", Instances, "reference_only", []string{"runtime_rollouts", "users"}, []string{"detail_json"}, "Retain redacted historical evidence separately from active target upgrade records."},
		{"workspace_file_audits", Instances, "preserve", []string{"instances", "users"}, []string{"relative_path"}, "Retain file audit history under the correct user and instance."},
		{"openclaw_config_resources", Instances, "preserve", []string{"users"}, []string{"content_json"}, "These shared bootstrap resources are also consumed by non-OpenClaw runtimes."},
		{"openclaw_config_bundles", Instances, "preserve", []string{"users"}, nil, "Preserve reusable bootstrap bundles."},
		{"openclaw_config_bundle_items", Instances, "preserve", []string{"openclaw_config_bundles", "openclaw_config_resources"}, nil, "Preserve bundle-to-resource membership."},
		{"openclaw_config_bundle_skills", Instances, "preserve", []string{"openclaw_config_bundles", "skills"}, nil, "Preserve bundle skill references in coordination with the Skill Hub owner."},
		{"openclaw_injection_snapshots", Instances, "reset", []string{"users", "instances", "openclaw_config_bundles"}, []string{"resolved_resources_json", "rendered_manifest_json", "rendered_env_json"}, "Retain configuration history; never activate source Secret names or replay source injections."},
		{"instance_lifecycle_batches", Instances, "reference_only", nil, nil, "Retain source lifecycle execution evidence outside active target tables."},
		{"instance_lifecycle_batch_items", Instances, "reference_only", nil, nil, "Never replay source batch work."},
		{"instance_lifecycle_batch_attempts", Instances, "reference_only", nil, nil, "Never resume source attempts."},
		{"instance_lifecycle_manual_guards", Instances, "drop", nil, nil, "Source guards are not target coordination locks."},
		{"instance_lifecycle_scheduler", Instances, "drop", nil, nil, "Do not import source scheduler cursors."},
		{"runtime_rollout_instances", Instances, "reference_only", nil, nil, "Never resume source rollout items."},
		{"runtime_rollout_checkpoints", Instances, "reference_only", []string{"runtime_rollouts"}, []string{"state_json"}, "Archive source rollout checkpoints as evidence; never resume source rollout execution."},
		{"instance_workspace_write_intents", Instances, "drop", []string{"instances"}, nil, "Outstanding source remote writes are coordination state; never replay them or block target workspace access."},
		{"workbuddy_browser_grants", Instances, "drop", nil, nil, "Do not replay browser authorization grants."},
		{"workbuddy_instance_recoveries", Instances, "reference_only", nil, nil, "Do not execute source recovery attempts."},
		{"workbuddy_linux_identities", Instances, "preserve", []string{"instances"}, nil, "Preserve Linux identity and workspace ownership; target schema adapter must explicitly support its columns."},
		{"workbuddy_linux_identity_allocator", Instances, "reference_only", nil, nil, "Default reference-only; the pinned workbuddy-linux-uid.v1 adapter explicitly restores the validated high-water mark and all historical reservations. Never run allocation during restore."},
		{"workbuddy_pod_terminations", Instances, "reference_only", nil, nil, "Do not repeat source pod termination requests."},
	}
}

type Dependency struct {
	Domain Domain   `json:"domain"`
	Tables []string `json:"tables"`
	Reason string   `json:"reason"`
}

// CrossDomainDependencies is deliberately explicit: the two domain collectors
// alone cannot claim that model credentials, skill bindings or Team tasks have
// been migrated. The shared coordinator must satisfy these dependencies.
func CrossDomainDependencies() []Dependency {
	return []Dependency{
		{"ai_gateway", []string{"llm_models", "model_invocations", "audit_events", "cost_records", "risk_rules", "risk_hits", "instance_gateway_token_aliases", "chat_sessions", "chat_messages"}, "Model/provider configuration, platform chat history and gateway credentials require the AI Gateway collector and Secret resolver."},
		{"skill_hub", []string{"skills", "skill_versions", "instance_skills", "skill_blobs", "skill_package_materialize_jobs"}, "Workspace skill files do not replace Skill Hub metadata, bindings and package objects."},
		{"teams", []string{"teams", "team_members", "team_tasks", "team_events", "team_work_items", "team_event_outbox", "team_workflow_phases", "custom_team_templates"}, "Team-owned task definitions and replayable work must be preserved and normalized by their owner."},
		{"resources", []string{"system_image_settings", "egress_private_exceptions", "security_scan_configs", "security_scan_jobs", "security_scan_job_items", "security_scan_reports", "audit_logs"}, "Resource definitions and audit history are archived; execution and egress remain disabled in the drill."},
	}
}

func ValidateRegistry(rules []TableRule, dependencies []Dependency) error {
	known := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.Name == "" || known[rule.Name] {
			return fmt.Errorf("empty or duplicate scope table")
		}
		if rule.Domain != Users && rule.Domain != Instances {
			return fmt.Errorf("unassigned scope table: %s", rule.Name)
		}
		switch rule.RestoreAction {
		case "preserve", "reset", "disable", "drop", "reference_only":
		default:
			return fmt.Errorf("unassigned restore action: %s", rule.Name)
		}
		if rule.Reason == "" {
			return fmt.Errorf("missing restore rationale: %s", rule.Name)
		}
		known[rule.Name] = true
	}
	for _, dependency := range dependencies {
		for _, table := range dependency.Tables {
			known[table] = true
		}
	}
	for _, rule := range rules {
		for _, table := range rule.DependsOn {
			if !known[table] {
				return fmt.Errorf("unassigned dependency: %s -> %s", rule.Name, table)
			}
		}
	}
	return nil
}
