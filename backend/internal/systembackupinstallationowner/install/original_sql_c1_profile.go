package install

import (
	appdb "clawreef/internal/db"
	"reflect"
	"sort"
	"strings"
)

// This is the fixed ORIGINAL 97-row site's ledger, not guessed new count.
// A v3 operation requires the exact union with THIS binary's real embedded
// migration catalog, including formal137. No migration record is ever written.
const originalSQLC1HistoricalLedger = `001_init_schema.sql
002_add_webtop_instance_type.sql
003_add_system_image_settings.sql
004_fix_seeded_admin_password.sql
005_update_openclaw_default_image.sql
006_add_openclaw_config_center.sql
007_add_instance_agent_control_plane.sql
008_add_skill_management.sql
009_cpu_cores_decimal.sql
010_add_instance_environment_overrides.sql
011_add_hermes_instance_type.sql
012_update_agents_runtime_default_images.sql
013_normalize_agents_runtime_image_names.sql
014_add_team_mvp.sql
015_add_team_member_description.sql
016_release_deleted_team_names.sql
017_add_team_member_runtime_state.sql
018_add_team_member_runtime_type.sql
019_add_instance_runtime_type.sql
020_add_system_image_runtime_type.sql
021_add_openclaw_shell_runtime_image.sql
022_add_openclaw_config_bundle_skills.sql
023_add_runtime_pool_v2.sql
023_add_skill_hub.sql
023_normalize_runtime_config_mounts.sql
024_add_gateway_runtime_type.sql
025_add_instance_mode.sql
027_add_instance_external_access.sql
028_add_ai_gateway_runtime_attribution.sql
029_add_short_external_access_links.sql
030_add_external_access_password_value.sql
031_add_hermes_lite_runtime_image.sql
032_add_team_member_instance_mode.sql
033_system_image_gateway_runtime_type.sql
034_update_lite_default_images.sql
035_harden_team_event_protocol.sql
036_add_team_event_outbox.sql
037_add_team_workflow_ledger.sql
038_add_instance_gateway_token_aliases.sql
039_add_skill_package_materialize.sql
040_fix_injected_skill_provenance.sql
041_add_session_usage_indexes.sql
042_add_skill_summary_status.sql
042_add_team_review_contract.sql
043_add_external_access_workspace_scope.sql
043_drop_skill_summary_status.sql
044_add_egress_private_exceptions.sql
044_add_workbuddy_instance_type.sql
045_add_llm_model_reasoning_control.sql
045_add_northbound_api.sql
045_add_opencode_instance_type.sql
045_update_workbuddy_windows_runtime.sql
046_add_custom_team_templates.sql
046_add_enterprise_auth_identity.sql
046_add_instance_pvc_name.sql
046_add_opencode_lite_runtime.sql
047_add_deepseek_harness_runtime.sql
047_add_instance_owner.sql
047_add_instance_runtime_variant.sql
048_add_workbuddy_instance_type.sql
048_fix_instance_type_enum.sql
049_add_ldap_login_alias.sql
049_add_opencode_instance_type.sql
050_add_enterprise_auth_settings.sql
050_update_workbuddy_windows_runtime.sql
051_add_codex_and_claude_code_instance_types.sql
052_add_instance_pvc_name.sql
053_add_instance_runtime_variant.sql
054_add_system_image_runtime_variant.sql
055_reconcile_instance_type_enum.sql
056_add_llm_provider_models.sql
057_add_northbound_admin_settings.sql
058_add_openclaw_runtime_upgrade_safety.sql
058_enable_deepseek_harness_pro.sql
059_pin_openclaw_2026_8_1_images.sql
060_allow_terminal_runtime_upgrade_instance_deletion.sql
061_persist_runtime_upgrade_source_identity.sql
062_follow_openclaw_latest_images.sql
063_add_security_scan_tables.sql
063_unique_usernames.sql
064_reconcile_system_image_settings_schema.sql
065_add_system_backup_control_metadata_core.sql
066_add_system_backup_config_and_operations.sql
067_add_system_backup_task_execution_core.sql
068_add_system_backup_coordination_observability.sql
069_add_system_backup_promotion_authority.sql
070_add_system_backup_prune_authority.sql
071_add_system_backup_external_action_authority.sql
072_add_system_backup_check_authority.sql
073_add_system_backup_staging_resources.sql
074_add_system_maintenance_participants.sql
075_add_system_backup_strong_auth_nonces.sql
076_add_system_backup_job_observations.sql
077_add_system_restore_drill_resources.sql
078_reconcile_local_username_key.sql
079_add_a_owned_chat_and_risk_tables.sql
080_add_system_backup_registration_runtime.sql`

func originalSQLC1ExpectedLedger() ([]string, error) {
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, n := range strings.Split(originalSQLC1HistoricalLedger, "\n") {
		if n == "" || set[n] {
			return nil, errOriginalSQLAccounts
		}
		set[n] = true
	}
	has137 := false
	for _, n := range catalog.Filenames {
		set[n] = true
		if n == "137_backup_producer_authority.sql" {
			has137 = true
		}
	}
	if !has137 {
		return nil, errOriginalSQLAccounts
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
func originalSQLC1LedgerMatches(actual []string) bool {
	expected, err := originalSQLC1ExpectedLedger()
	return err == nil && reflect.DeepEqual(actual, expected)
}

var originalSQLC1Tables = []string{
	"system_backup_producer_domains", "system_backup_producer_grants", "system_backup_producer_runs", "system_backup_producer_targets",
	"system_backup_producer_command_receipts", "system_backup_producer_evidence_bindings", "system_backup_producer_evidence_refs", "system_backup_producer_result_receipts",
}

func originalSQLC1RoleDelta(role string, present map[string]bool, base []originalSQLPrivilege) ([]originalSQLPrivilege, error) {
	// All six roles share one frozen v3 operation, but only the actual installer
	// and bootstrap-consuming business service gain C1 rights. Runtime remains
	// the independently reviewed public48 profile; source receives none.
	for _, table := range originalSQLC1Tables {
		if !present[table] {
			return nil, errOriginalSQLAccounts
		}
	}
	result := append([]originalSQLPrivilege(nil), base...)
	add := func(table string, verbs ...string) {
		for _, verb := range verbs {
			p := originalSQLPriv(table, verb)
			found := false
			for _, old := range result {
				found = found || old == p
			}
			if !found {
				result = append(result, p)
			}
		}
	}
	if role == "installer" {
		for _, table := range originalSQLC1Tables {
			add(table, "SELECT", "INSERT", "UPDATE")
		}
		add("system_backup_v2_evidence", "SELECT", "INSERT", "UPDATE")
		// Pending inserts chunks; no protocol path updates/deletes chunk rows.
		add("system_backup_v2_evidence_chunks", "SELECT", "INSERT")
		add("system_backup_v2_metadata_reservations", "SELECT", "INSERT", "UPDATE")
		add("audit_logs", "INSERT")
	} else if role == "business" {
		for _, table := range originalSQLC1Tables {
			if table != "system_backup_producer_command_receipts" {
				add(table, "SELECT")
			}
		}
		// BootstrapConsumption changes only the domain to closed. It reads, but
		// never edits the receipt/history/reference objects it consumes.
		add("system_backup_producer_domains", "UPDATE")
		// Config bootstrap writes two audit rows and snapshots their full rows.
		// No UPDATE, DELETE, grant option or users password read is needed.
		add("audit_logs", "SELECT", "INSERT")
	}
	return result, nil
}
