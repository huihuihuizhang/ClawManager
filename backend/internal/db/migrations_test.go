package db

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSplitSQLStatements(t *testing.T) {
	input := `
-- create table comment
CREATE TABLE demo (
  id INT PRIMARY KEY,
  note VARCHAR(255) DEFAULT 'hello;world'
);

/* block comment */
INSERT INTO demo (id, note) VALUES (1, 'value');
UPDATE demo SET note = "a;quoted" WHERE id = 1;
`

	got := splitSQLStatements(input)
	want := []string{
		"CREATE TABLE demo (\n  id INT PRIMARY KEY,\n  note VARCHAR(255) DEFAULT 'hello;world'\n)",
		"INSERT INTO demo (id, note) VALUES (1, 'value')",
		`UPDATE demo SET note = "a;quoted" WHERE id = 1`,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected statements:\nwant: %#v\ngot: %#v", want, got)
	}
}

func TestMigration023IsEmbedded(t *testing.T) {
	files, err := embeddedMigrations.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}

	found := false
	for _, file := range files {
		if file.Name() == "023_add_runtime_pool_v2.sql" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("migration 023_add_runtime_pool_v2.sql is not embedded")
	}
}

func TestOpenClaw81UpgradeMigrationsAreEmbeddedAndDataSafe(t *testing.T) {
	safety, err := embeddedMigrations.ReadFile("migrations/058_add_openclaw_runtime_upgrade_safety.sql")
	if err != nil {
		t.Fatal(err)
	}
	safetySQL := string(safety)
	for _, contract := range []string{"runtime_upgrade_items", "runtime_upgrade_audits", "preflight_id", "capabilities_json", "rollback_status"} {
		if !strings.Contains(safetySQL, contract) {
			t.Fatalf("migration 058 missing %q", contract)
		}
	}
	pin, err := embeddedMigrations.ReadFile("migrations/059_pin_openclaw_2026_8_1_images.sql")
	if err != nil {
		t.Fatal(err)
	}
	pinSQL := string(pin)
	if !strings.Contains(pinSQL, "2026.8.1") || !strings.Contains(pinSQL, "image IN") {
		t.Fatal("migration 059 must update only known previous defaults to 2026.8.1")
	}
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM instances", "DELETE FROM runtime_pods"} {
		if strings.Contains(strings.ToUpper(safetySQL+pinSQL), destructive) {
			t.Fatalf("OpenClaw upgrade migration contains destructive statement %q", destructive)
		}
	}
	release, err := embeddedMigrations.ReadFile("migrations/060_allow_terminal_runtime_upgrade_instance_deletion.sql")
	if err != nil {
		t.Fatal(err)
	}
	releaseSQL := string(release)
	if !strings.Contains(releaseSQL, "DROP FOREIGN KEY fk_runtime_upgrade_item_instance") {
		t.Fatal("migration 060 must release only the historical instance deletion blocker")
	}
	for _, destructive := range []string{"DELETE FROM", "DROP TABLE", "TRUNCATE"} {
		if strings.Contains(strings.ToUpper(releaseSQL), destructive) {
			t.Fatalf("migration 060 must preserve audit and user rows; found %q", destructive)
		}
	}
	sourceIdentity, err := embeddedMigrations.ReadFile("migrations/061_persist_runtime_upgrade_source_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentitySQL := string(sourceIdentity)
	for _, required := range []string{"source_gateway_id", "source_generation", "source_pod_uid", "source_deployment_name", "source_image_digest"} {
		if !strings.Contains(sourceIdentitySQL, required) {
			t.Fatalf("migration 061 missing %q", required)
		}
	}
	for _, destructive := range []string{"DELETE FROM", "DROP TABLE", "TRUNCATE"} {
		if strings.Contains(strings.ToUpper(sourceIdentitySQL), destructive) {
			t.Fatalf("migration 061 must preserve existing rollout and user rows; found %q", destructive)
		}
	}
	followLatest, err := embeddedMigrations.ReadFile("migrations/062_follow_openclaw_latest_images.sql")
	if err != nil {
		t.Fatal(err)
	}
	followLatestSQL := string(followLatest)
	for _, required := range []string{
		"ghcr.io/yuan-lab-llm/agentsruntime/openclaw:2026.8.1",
		"ghcr.io/yuan-lab-llm/agentsruntime/openclaw:latest",
		"ghcr.io/yuan-lab-llm/agentsruntime/openclaw-lite:2026.8.1",
		"ghcr.io/yuan-lab-llm/agentsruntime/openclaw-lite:latest",
		"image IN",
	} {
		if !strings.Contains(followLatestSQL, required) {
			t.Fatalf("migration 062 missing %q", required)
		}
	}
	for _, destructive := range []string{"DELETE FROM", "DROP TABLE", "TRUNCATE"} {
		if strings.Contains(strings.ToUpper(followLatestSQL), destructive) {
			t.Fatalf("migration 062 must preserve custom image settings and user rows; found %q", destructive)
		}
	}
}

func TestMigration034UpdatesLiteDefaultImages(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/034_update_lite_default_images.sql")
	if err != nil {
		t.Fatalf("read migration 034: %v", err)
	}
	sql := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, image := range []string{
		"ghcr.io/yuan-lab-llm/agentsruntime/openclaw-lite:latest",
		"ghcr.io/yuan-lab-llm/agentsruntime/hermes-lite:latest",
	} {
		if !strings.Contains(sql, image) {
			t.Fatalf("migration 034 must update lite image %s", image)
		}
	}
}

func TestMigration023IsRetrySafe(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/023_add_runtime_pool_v2.sql")
	if err != nil {
		t.Fatalf("read migration 023: %v", err)
	}

	sql := string(raw)
	if !strings.Contains(sql, "information_schema.COLUMNS") {
		t.Fatalf("migration 023 must guard instance column additions with information_schema.COLUMNS")
	}
	for _, column := range []string{
		"workspace_path",
		"workspace_usage_bytes",
		"runtime_generation",
		"runtime_error_message",
	} {
		if !strings.Contains(sql, "COLUMN_NAME = '"+column+"'") {
			t.Fatalf("migration 023 must guard %s column addition", column)
		}
	}
	for _, table := range []string{
		"runtime_pods",
		"instance_runtime_bindings",
		"runtime_rollouts",
		"workspace_file_audits",
	} {
		if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 023 must create %s idempotently", table)
		}
	}
}

func TestMigration035HardensTeamEventProtocol(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/035_harden_team_event_protocol.sql")
	if err != nil {
		t.Fatalf("read migration 035: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"event_id",
		"completion_id",
		"sequence_no",
		"uk_team_events_event_id",
		"uk_team_events_completion_id",
		"CREATE TABLE IF NOT EXISTS team_work_items",
		"uk_team_work_items_work",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 035 must contain %s", required)
		}
	}
}

func TestMigration036AddsReliableTeamEventOutbox(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/036_add_team_event_outbox.sql")
	if err != nil {
		t.Fatalf("read migration 036: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS team_event_outbox",
		"uk_team_event_outbox_message",
		"idx_team_event_outbox_pending",
		"source_event_id",
		"available_at",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 036 must contain %s", required)
		}
	}
}

func TestMigration037AddsTeamWorkflowLedger(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/037_add_team_workflow_ledger.sql")
	if err != nil {
		t.Fatalf("read migration 037: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"workflow_state",
		"plan_version",
		"ledger_version",
		"accepted_completion_id",
		"assignment_id",
		"canonical_work_id",
		"phase_id",
		"required_for_root",
		"CREATE TABLE IF NOT EXISTS team_workflow_phases",
		"uk_team_workflow_phase",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 037 must contain %s", required)
		}
	}
}

func TestMigration038AddsGatewayTokenAliases(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/038_add_instance_gateway_token_aliases.sql")
	if err != nil {
		t.Fatalf("read migration 038: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS instance_gateway_token_aliases",
		"token_hash CHAR(64)",
		"expires_at TIMESTAMP NOT NULL",
		"last_used_at TIMESTAMP NULL",
		"uk_instance_gateway_token_aliases_hash",
		"ON DELETE CASCADE",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 038 must contain %s", required)
		}
	}
	if strings.Contains(sql, "access_token") {
		t.Fatalf("migration 038 must not store raw access tokens")
	}
}

func TestMigration041AddsSessionUsageIndexes(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/041_add_session_usage_indexes.sql")
	if err != nil {
		t.Fatalf("read migration 041: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"idx_cost_records_instance_id",
		"idx_cost_records_session_id",
		"idx_model_invocations_instance_session",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 041 must contain %s", required)
		}
	}
}

func TestMigration042AddsImmutableReviewContractTarget(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/042_add_team_review_contract.sql")
	if err != nil {
		t.Fatalf("read migration 042: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"review_target_assignment_id",
		"review_target_revision",
		"idx_team_work_items_review_target",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 042 must contain %s", required)
		}
	}
}

func TestMigration048AddsWorkbuddyRuntime(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/048_add_workbuddy_instance_type.sql")
	if err != nil {
		t.Fatalf("read migration 048: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"'workbuddy'",
		"instance_type = 'workbuddy'",
		"LOWER(TRIM(display_name)) = 'workbuddy'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 048 must contain %s", required)
		}
	}
}

func TestManagedRuntimeEnumMigrationsPreserveAllRuntimeTypes(t *testing.T) {
	files := []string{
		"044_add_workbuddy_instance_type.sql",
		"045_add_opencode_instance_type.sql",
		"046_add_opencode_lite_runtime.sql",
		"047_add_deepseek_harness_runtime.sql",
		"048_add_workbuddy_instance_type.sql",
		"049_add_opencode_instance_type.sql",
		"051_add_codex_and_claude_code_instance_types.sql",
		"055_reconcile_instance_type_enum.sql",
	}
	requiredTypes := []string{"'workbuddy'", "'opencode'", "'deepseek-harness'", "'codex'", "'claude-code'"}
	for _, name := range files {
		raw, err := embeddedMigrations.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		sql := string(raw)
		for _, instanceType := range requiredTypes {
			if !strings.Contains(sql, instanceType) {
				t.Fatalf("migration %s must preserve instance type %s", name, instanceType)
			}
		}
	}
}

func TestMigration050UpdatesWorkbuddyWindowsRuntime(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/050_update_workbuddy_windows_runtime.sql")
	if err != nil {
		t.Fatalf("read migration 050: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"windows-vm-workbuddy:latest",
		"runtime_type = 'desktop'",
		"instance_type = 'workbuddy'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 050 must contain %s", required)
		}
	}
}

func TestMigration045AddsNorthboundSecurityState(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/045_add_northbound_api.sql")
	if err != nil {
		t.Fatalf("read migration 045: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS northbound_auth_challenges",
		"CREATE TABLE IF NOT EXISTS northbound_sessions",
		"previous_refresh_token_hash",
		"refresh_token_history",
		"CREATE TABLE IF NOT EXISTS northbound_operations",
		"uk_northbound_operation_idempotency",
		"provisioning_operation_id",
		"uk_instances_provisioning_operation",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 045 must contain %s", required)
		}
	}
}

func TestMigration047AddsInstanceOwner(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/047_add_instance_owner.sql")
	if err != nil {
		t.Fatalf("read migration 047: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"ADD COLUMN owner VARCHAR(128)",
		"COLLATE utf8mb4_bin",
		"owner_normalized",
		"GENERATED ALWAYS AS (LOWER(TRIM(owner))) STORED",
		"idx_instances_user_owner_mode_created",
		"user_id, owner, instance_mode, created_at, id",
		"idx_instances_owner_normalized_mode_created",
		"owner_normalized, instance_mode, created_at, id",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 047 must contain %s", required)
		}
	}
}

func TestMigration049AddsOpenCodeInstanceType(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/049_add_opencode_instance_type.sql")
	if err != nil {
		t.Fatalf("read migration 049: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"MODIFY COLUMN type ENUM",
		"'workbuddy'",
		"'opencode'",
		"'gateway'",
		"'desktop'",
		"OpenCode Lite",
		"OpenCode Pro",
		"agentsruntime/opencode-lite:latest",
		"agentsruntime/opencode:latest",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 049 must contain %s", required)
		}
	}
}

func TestMigration052AddsInstancePVCName(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/052_add_instance_pvc_name.sql")
	if err != nil {
		t.Fatalf("read migration 052: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{"ALTER TABLE instances", "pvc_name", "VARCHAR(253)", "information_schema.COLUMNS", "PREPARE instance_pvc_name_column_stmt"} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 052 must contain %s", required)
		}
	}
}

func TestMigration051AddsCodexAndClaudeCodeInstanceTypes(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/051_add_codex_and_claude_code_instance_types.sql")
	if err != nil {
		t.Fatalf("read migration 051: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"MODIFY COLUMN type ENUM",
		"'workbuddy'",
		"'codex'",
		"'claude-code'",
		"Codex Pro",
		"Claude Code Pro",
		"agentsruntime/codex:latest",
		"agentsruntime/claude-code:latest",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 051 must contain %s", required)
		}
	}
}

func TestMigration053AddsAndBackfillsInstanceRuntimeVariant(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/053_add_instance_runtime_variant.sql")
	if err != nil {
		t.Fatalf("read migration 053: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{"runtime_variant", "'linux'", "'windows'", "workbuddy-linux", "windows-vm-workbuddy", "information_schema.COLUMNS", "PREPARE instance_runtime_variant_column_stmt"} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 053 must contain %s", required)
		}
	}
}

func TestMigration054AddsAndBackfillsSystemImageRuntimeVariant(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/054_add_system_image_runtime_variant.sql")
	if err != nil {
		t.Fatalf("read migration 054: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"system_image_settings",
		"runtime_variant",
		"workbuddy-linux",
		"windows-vm-workbuddy",
		"windows-vm-codex",
		"agentsruntime/codex",
		"WHERE type = 'codex'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 054 must contain %s", required)
		}
	}
}

func TestMigration044AddsWorkbuddyRuntime(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/044_add_workbuddy_instance_type.sql")
	if err != nil {
		t.Fatalf("read migration 044: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"'workbuddy'",
		"instance_type = 'workbuddy'",
		"LOWER(TRIM(display_name)) = 'workbuddy'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 044 must contain %s", required)
		}
	}
}

func TestMigration045BootstrapsAndUpgradesLLMModels(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/045_add_llm_model_reasoning_control.sql")
	if err != nil {
		t.Fatalf("read migration 045: %v", err)
	}

	sql := string(raw)
	createTable := "CREATE TABLE IF NOT EXISTS llm_models"
	guardColumn := "information_schema.COLUMNS"
	addColumn := "ALTER TABLE llm_models ADD COLUMN reasoning_enabled"
	for _, required := range []string{
		createTable,
		guardColumn,
		"TABLE_NAME = 'llm_models'",
		"COLUMN_NAME = 'reasoning_enabled'",
		addColumn,
		"PREPARE stmt FROM @stmt",
		"EXECUTE stmt",
		"DEALLOCATE PREPARE stmt",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 045 must contain %s", required)
		}
	}

	if strings.Index(sql, createTable) > strings.Index(sql, addColumn) {
		t.Fatalf("migration 045 must create the legacy llm_models table before adding reasoning_enabled")
	}
}

func TestMigration056AddsLLMProviderModelCatalog(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/056_add_llm_provider_models.sql")
	if err != nil {
		t.Fatalf("read migration 056: %v", err)
	}

	sql := string(raw)
	for _, required := range []string{
		"information_schema.COLUMNS",
		"TABLE_NAME = 'llm_models'",
		"COLUMN_NAME = 'provider_models_json'",
		"ALTER TABLE llm_models ADD COLUMN provider_models_json TEXT",
		"PREPARE stmt FROM @stmt",
		"EXECUTE stmt",
		"DEALLOCATE PREPARE stmt",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 056 must contain %s", required)
		}
	}
}

func TestMigration047AddsDeepSeekHarnessRuntimes(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/047_add_deepseek_harness_runtime.sql")
	if err != nil {
		t.Fatalf("read migration 047: %v", err)
	}

	sql := string(raw)
	for _, required := range []string{
		"'deepseek-harness'",
		"'desktop'",
		"'gateway'",
		"'DeepSeek Harness Pro'",
		"'DeepSeek Harness Lite'",
		"ghcr.io/yuan-lab-llm/agentsruntime/deepseek-harness:latest",
		"ghcr.io/yuan-lab-llm/agentsruntime/deepseek-harness-lite:latest",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 047 must contain %s", required)
		}
	}
}

func TestMigration058EnablesDeepSeekHarnessProWithoutOverwritingCustomPolicy(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/058_enable_deepseek_harness_pro.sql")
	if err != nil {
		t.Fatalf("read migration 058: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"JSON_LENGTH(allowed_pro_types) = 4",
		"JSON_CONTAINS(allowed_pro_types, JSON_QUOTE('openclaw'))",
		"JSON_ARRAY_APPEND(allowed_pro_types, '$', 'deepseek-harness')",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 058 must contain %s", required)
		}
	}
}

func TestMigration048PreservesAllInstanceTypes(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/048_fix_instance_type_enum.sql")
	if err != nil {
		t.Fatalf("read migration 048: %v", err)
	}

	sql := string(raw)
	for _, instanceType := range []string{
		"'openclaw'",
		"'ubuntu'",
		"'debian'",
		"'centos'",
		"'custom'",
		"'webtop'",
		"'hermes'",
		"'workbuddy'",
		"'opencode'",
		"'deepseek-harness'",
	} {
		if !strings.Contains(sql, instanceType) {
			t.Fatalf("migration 048 must preserve instance type %s", instanceType)
		}
	}
}

func TestMigration049BackfillsLDAPLoginAliasesWithJoin(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/049_add_ldap_login_alias.sql")
	if err != nil {
		t.Fatalf("read migration 049: %v", err)
	}

	sql := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, required := range []string{
		"ALTER TABLE users ADD COLUMN login_alias",
		"UPDATE users AS u\nJOIN",
		"AS unique_ldap_usernames ON unique_ldap_usernames.username = u.username",
		"HAVING COUNT(*) = 1",
		"local_username_key",
		"uk_users_local_username",
		"uk_users_provider_login_alias",
		"uk_users_provider_external_id",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 049 must contain %s", required)
		}
	}
	if strings.Contains(sql, "SELECT COUNT(*) FROM users AS same_uid") {
		t.Fatalf("migration 049 must not use a same-table correlated subquery in the update")
	}
}

func TestMigration050IncludesLDAPTLSCertificateSettings(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/050_add_enterprise_auth_settings.sql")
	if err != nil {
		t.Fatalf("read migration 050: %v", err)
	}

	sql := string(raw)
	for _, required := range []string{
		"ldap_tls_ca_file VARCHAR(1000) NOT NULL DEFAULT ''",
		"ldap_tls_server_name VARCHAR(255) NOT NULL DEFAULT ''",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 050 must contain %s", required)
		}
	}
}

func TestMigration063CreatesSecurityScanSchema(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/063_add_security_scan_tables.sql")
	if err != nil {
		t.Fatalf("read migration 063: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 4 {
		t.Fatalf("migration 063 must contain exactly four statements, got %d", len(statements))
	}

	tables := []string{
		"security_scan_configs",
		"security_scan_jobs",
		"security_scan_job_items",
		"security_scan_reports",
	}
	for i, table := range tables {
		if !strings.Contains(statements[i], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 063 statement %d must create %s idempotently", i+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"quick_analyzers_json LONGTEXT NOT NULL",
		"deep_analyzers_json LONGTEXT NOT NULL",
		"idx_security_scan_jobs_status (status, created_at)",
		"idx_security_scan_jobs_asset_type (asset_type, created_at)",
		"FOREIGN KEY (job_id) REFERENCES security_scan_jobs(id) ON DELETE CASCADE",
		"uk_security_scan_job_items_job_asset (job_id, asset_type, asset_id)",
		"idx_security_scan_job_items_job (job_id, status)",
		"uk_security_scan_reports_job (job_id)",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 063 missing %q", required)
		}
	}

	if got := strings.Count(sql, "FOREIGN KEY (job_id) REFERENCES security_scan_jobs(id) ON DELETE CASCADE"); got != 2 {
		t.Fatalf("migration 063 must define exactly two cascading job foreign keys, got %d", got)
	}

	upperSQL := strings.ToUpper(sql)
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 063 must preserve existing security scan data; found %q", destructive)
		}
	}
}

func TestMigration064OwnsSystemImageSettingsSchema(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/064_reconcile_system_image_settings_schema.sql")
	if err != nil {
		t.Fatalf("read migration 064: %v", err)
	}

	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS system_image_settings",
		"runtime_type ENUM('desktop', 'shell', 'gateway') NOT NULL DEFAULT 'desktop'",
		"runtime_variant VARCHAR(32) NOT NULL DEFAULT ''",
		"is_enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"information_schema.COLUMNS",
		"ALTER TABLE system_image_settings ADD COLUMN runtime_type",
		"ALTER TABLE system_image_settings ADD COLUMN runtime_variant",
		"ALTER TABLE system_image_settings ADD COLUMN is_enabled",
		"MODIFY COLUMN runtime_type ENUM('desktop', 'shell', 'gateway')",
		"HAVING COUNT(*) = 1",
		"SUM(COLUMN_NAME = 'instance_type') = 1",
		"ALTER TABLE system_image_settings DROP INDEX",
		"CREATE INDEX idx_instance_type ON system_image_settings (instance_type)",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 064 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 064 must preserve system image rows; found %q", destructive)
		}
	}
}

func TestMigration065CreatesSystemBackupControlMetadataCore(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/065_add_system_backup_control_metadata_core.sql")
	if err != nil {
		t.Fatalf("read migration 065: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	tables := []string{
		"system_backup_installation_state",
		"system_backup_evidence",
		"system_backup_evidence_chunks",
		"system_backup_log_chunks",
		"system_backup_dependency_health",
		"system_backup_provider_capabilities",
		"system_backup_compact_tombstones",
	}
	if len(statements) != len(tables) {
		t.Fatalf("migration 065 must contain exactly %d statements, got %d", len(tables), len(statements))
	}
	for i, table := range tables {
		if !strings.Contains(statements[i], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 065 statement %d must create %s idempotently", i+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_installation_origin (origin_installation_id)",
		"CONSTRAINT chk_sb_installation_monitoring CHECK",
		"UNIQUE KEY uk_sb_evidence_public_id (public_id)",
		"UNIQUE KEY uk_sb_evidence_public_owner_type (public_id, owner_target_public_id, evidence_type)",
		"CONSTRAINT chk_sb_evidence_owner_id CHECK",
		"CONSTRAINT chk_sb_evidence_failure CHECK",
		"CONSTRAINT chk_sb_evidence_storage CHECK",
		"CONSTRAINT chk_sb_evidence_encryption CHECK",
		"content_size_bytes <= 1073741824",
		"UNIQUE KEY uk_sb_evidence_chunk (evidence_id, chunk_index)",
		"FOREIGN KEY (evidence_id) REFERENCES system_backup_evidence(id) ON DELETE CASCADE",
		"UNIQUE KEY uk_sb_log_chunk (task_type, task_public_id, job_uid, job_generation, chunk_sequence)",
		"FOREIGN KEY (redacted_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT",
		"UNIQUE KEY uk_sb_dependency_identity (dependency_kind, identity_hash, identity_version, owner_target_type, owner_target_public_id)",
		"UNIQUE KEY uk_sb_provider_capability (provider_role, provider_identity_hash, provider_ref_version, capability_code)",
		"CONSTRAINT chk_sb_provider_role_code CHECK",
		"UNIQUE KEY uk_sb_tombstone_source (origin_installation_id, source_type, source_public_id)",
		"UNIQUE KEY uk_sb_tombstone_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"CONSTRAINT chk_sb_tombstone_retention CHECK",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 065 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 065 must be additive; found %q", destructive)
		}
	}
}

func TestMigration066CreatesConfigAndOperationAuthorities(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/066_add_system_backup_config_and_operations.sql")
	if err != nil {
		t.Fatalf("read migration 066: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 7 {
		t.Fatalf("migration 066 must contain two creates and five idempotent FK statements, got %d", len(statements))
	}
	if !strings.Contains(statements[0], "CREATE TABLE IF NOT EXISTS system_backup_configs") {
		t.Fatalf("migration 066 statement 1 must create system_backup_configs")
	}
	if !strings.Contains(statements[1], "CREATE TABLE IF NOT EXISTS system_backup_operations") {
		t.Fatalf("migration 066 statement 2 must create system_backup_operations")
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_config_version (origin_installation_id, version)",
		"UNIQUE KEY uk_sb_config_snapshot (origin_installation_id, version, config_sha256, config_size_bytes)",
		"FOREIGN KEY (origin_installation_id, copied_from_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_config_durations_1 CHECK",
		"CONSTRAINT chk_sb_config_durations_2 CHECK",
		"CONSTRAINT chk_sb_config_capacity CHECK",
		"CONSTRAINT chk_sb_config_relationships CHECK",
		"controller_claim_heartbeat_seconds * 3 <= controller_claim_ttl_seconds",
		"staging_capacity_bytes * 10 >= max_artifact_bytes * 11 + max_index_bytes * 10",
		"capture_certificate_ttl_seconds > backup_task_deadline_seconds",
		"provider_proof_issuers_registry_sha256",
		"status_relay_ref_version",
		"UNIQUE KEY uk_sb_operation_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"UNIQUE KEY uk_sb_operation_origin_public (origin_installation_id, public_id)",
		"retry_of_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL",
		"KEY idx_sb_operation_retry (origin_installation_id, retry_of_operation_public_id)",
		"FOREIGN KEY (origin_installation_id, retry_of_operation_public_id) REFERENCES system_backup_operations(origin_installation_id, public_id) ON DELETE RESTRICT",
		"retry_of_operation_public_id <> public_id",
		"CONSTRAINT chk_sb_operation_target_id CHECK",
		"external_action_public_ids_canonical_json BLOB NOT NULL",
		"external_action_public_ids_size_bytes = OCTET_LENGTH(external_action_public_ids_canonical_json)",
		"CONSTRAINT chk_sb_operation_result CHECK",
		"CONSTRAINT chk_sb_operation_sync_terminal CHECK",
		"CONSTRAINT chk_sb_operation_failure CHECK",
		"CONSTRAINT chk_sb_operation_claim CHECK",
		"CONSTRAINT chk_sb_operation_reconcile CHECK",
		"FOREIGN KEY (redacted_response_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT",
		"FOREIGN KEY (origin_installation_id, result_config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT",
		"CONSTRAINT_NAME = 'fk_sb_installation_active_config'",
		"ALTER TABLE system_backup_installation_state ADD CONSTRAINT fk_sb_installation_active_config",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 066 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	if strings.Contains(sql, "retry_of_operation_id") {
		t.Fatal("migration 066 must not use an auto-increment ID in a CHECK constraint")
	}
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 066 must preserve existing rows; found %q", destructive)
		}
	}
}

func TestMigration067CreatesTaskExecutionAuthorities(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/067_add_system_backup_task_execution_core.sql")
	if err != nil {
		t.Fatalf("read migration 067: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 5 {
		t.Fatalf("migration 067 must contain five additive CREATE TABLE statements, got %d", len(statements))
	}
	for index, table := range []string{
		"system_backups",
		"system_restore_drills",
		"system_backup_preflights",
		"system_backup_artifact_verifications",
		"system_backup_attempts",
	} {
		if !strings.Contains(statements[index], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 067 statement %d must create %s", index+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_backup_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"UNIQUE KEY uk_sb_backup_origin_public (origin_installation_id, public_id)",
		"UNIQUE KEY uk_sb_backup_origin_matrix (origin_installation_id, public_id, matrix_key)",
		"UNIQUE KEY uk_sb_backup_origin_registration (origin_installation_id, public_id, artifact_registration_id, artifact_registration_hash)",
		"CONSTRAINT chk_sb_backup_cancel CHECK",
		"CONSTRAINT chk_sb_backup_commit CHECK",
		"status = 'finalization_unknown' AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE",
		"CONSTRAINT chk_sb_backup_artifact CHECK",
		"CONSTRAINT chk_sb_backup_eligibility CHECK",
		"UNIQUE KEY uk_sb_drill_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"UNIQUE KEY uk_sb_drill_local_source (origin_installation_id, public_id, local_source_backup_public_id)",
		"CONSTRAINT chk_sb_drill_cleanup CHECK",
		"CONSTRAINT chk_sb_drill_eligibility CHECK",
		"UNIQUE KEY uk_sb_preflight_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"CONSTRAINT chk_sb_preflight_mode CHECK",
		"UNIQUE KEY uk_sb_verify_create (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)",
		"CONSTRAINT chk_sb_verify_usable CHECK",
		"CONSTRAINT chk_sb_verify_result CHECK",
		"UNIQUE KEY uk_sb_attempt_unit (target_type, target_public_id, attempt_no, phase)",
		"CONSTRAINT chk_sb_attempt_phase CHECK",
		"CONSTRAINT chk_sb_attempt_sealed CHECK",
		"status <> 'sealed' AND NOT (status = 'succeeded' AND target_type = 'backup' AND phase IN ('capture', 'secret_capture'))",
		"CONSTRAINT chk_sb_attempt_status CHECK",
		"FOREIGN KEY (origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes) REFERENCES system_backup_configs(origin_installation_id, version, config_sha256, config_size_bytes) ON DELETE RESTRICT",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 067 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 067 must preserve existing rows; found %q", destructive)
		}
	}
}

func TestMigration069CreatesPromotionAuthority(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/069_add_system_backup_promotion_authority.sql")
	if err != nil {
		t.Fatalf("read migration 069: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 1 || !strings.Contains(statements[0], "CREATE TABLE IF NOT EXISTS system_backup_promotions") {
		t.Fatalf("migration 069 must contain one additive system_backup_promotions CREATE TABLE statement")
	}

	sql := statements[0]
	for _, required := range []string{
		"UNIQUE KEY uk_sb_promotion_active (origin_installation_id, matrix_key, active_guard)",
		"FOREIGN KEY (origin_installation_id, backup_public_id, matrix_key) REFERENCES system_backups(origin_installation_id, public_id, matrix_key) ON DELETE RESTRICT",
		"FOREIGN KEY (origin_installation_id, drill_public_id, backup_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id, local_source_backup_public_id) ON DELETE RESTRICT",
		"FOREIGN KEY (drill_evidence_public_id) REFERENCES system_backup_evidence(public_id) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_promotion_creation_health CHECK",
		"CONSTRAINT chk_sb_promotion_registration CHECK",
		"CONSTRAINT chk_sb_promotion_lifecycle CHECK",
		"record_status = 'superseded' AND superseded_by_public_id IS NOT NULL",
		"record_status = 'revoked' AND superseded_by_public_id IS NULL",
		"OCTET_LENGTH(revoked_reason) BETWEEN 1 AND 512",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 069 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, forbidden := range []string{"CURRENT_HEALTH", "PROVIDER_PAYLOAD", "CREDENTIAL_VALUE", "DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, forbidden) {
			t.Fatalf("migration 069 must keep derived or owner payload state external; found %q", forbidden)
		}
	}
}

func TestMigration070CreatesPruneAuthority(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/070_add_system_backup_prune_authority.sql")
	if err != nil {
		t.Fatalf("read migration 070: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 2 {
		t.Fatalf("migration 070 must contain two additive CREATE TABLE statements, got %d", len(statements))
	}
	for index, table := range []string{"system_backup_prune_runs", "system_backup_prune_items"} {
		if !strings.Contains(statements[index], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 070 statement %d must create %s", index+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_prune_run_create (origin_installation_id, create_actor_type, create_actor_id, create_endpoint, create_idempotency_key)",
		"UNIQUE KEY uk_sb_prune_run_confirmation_id (origin_installation_id, confirmation_id)",
		"UNIQUE KEY uk_sb_prune_run_confirmation (origin_installation_id, confirmation_actor_id, confirmation_endpoint, confirmation_idempotency_key)",
		"CONSTRAINT chk_sb_prune_run_candidate CHECK",
		"CONSTRAINT chk_sb_prune_run_confirmation CHECK",
		"confirmation_candidate_hash = candidate_hash",
		"confirmation_cutoff_at = older_than",
		"confirmation_config_version = config_version",
		"CONSTRAINT chk_sb_prune_run_retry CHECK",
		"CONSTRAINT chk_sb_prune_run_status CHECK",
		"UNIQUE KEY uk_sb_prune_item_origin_public (origin_installation_id, public_id)",
		"UNIQUE KEY uk_sb_prune_item_plan (prune_run_id, artifact_public_id, item_type, canonical_location_hash, immutable_version_sentinel)",
		"FOREIGN KEY (origin_installation_id, artifact_public_id, artifact_registration_id, artifact_registration_hash) REFERENCES system_backups(origin_installation_id, public_id, artifact_registration_id, artifact_registration_hash) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_prune_item_kind CHECK",
		"CONSTRAINT chk_sb_prune_item_location CHECK",
		"canonical_location_size_bytes = OCTET_LENGTH(canonical_location_key)",
		"canonical_location_hash = SHA2(canonical_location_key, 256)",
		"CONSTRAINT chk_sb_prune_item_blocked CHECK",
		"CONSTRAINT chk_sb_prune_item_status CHECK",
		"status = 'blocked_by_delete' AND external_action_public_id IS NULL",
		"status <> 'blocked_by_delete' AND external_action_public_id IS NOT NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 070 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, forbidden := range []string{"STRONG_AUTH_PROOF", "PROVIDER_PAYLOAD", "PROVIDER_LOCATOR", "CATALOG_PAYLOAD", "CREDENTIAL_VALUE", "DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, forbidden) {
			t.Fatalf("migration 070 must keep owner payloads and provider execution external; found %q", forbidden)
		}
	}
}

func TestMigration071CreatesExternalActionAuthority(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/071_add_system_backup_external_action_authority.sql")
	if err != nil {
		t.Fatalf("read migration 071: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 11 {
		t.Fatalf("migration 071 must contain one create and ten idempotent FK statements, got %d", len(statements))
	}
	if !strings.Contains(statements[0], "CREATE TABLE IF NOT EXISTS system_backup_external_actions") {
		t.Fatalf("migration 071 statement 1 must create system_backup_external_actions")
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_external_action_identity (target_type, target_public_id, action_type, action_key)",
		"UNIQUE KEY uk_sb_external_action_unresolved_backup (origin_installation_id, unresolved_backup_guard)",
		"GENERATED ALWAYS AS (CASE WHEN target_type = 'backup' AND state IN ('request_sent', 'provider_unreachable') THEN target_public_id ELSE NULL END) STORED",
		"FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT",
		"FOREIGN KEY (origin_installation_id, prune_item_target_public_id) REFERENCES system_backup_prune_items(origin_installation_id, public_id) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_external_action_type CHECK",
		"CONSTRAINT chk_sb_external_action_payload CHECK",
		"payload_sha256 = SHA2(canonical_payload_bytes, 256)",
		"content_length = OCTET_LENGTH(canonical_payload_bytes)",
		"CONSTRAINT chk_sb_external_action_keys CHECK",
		"FOREIGN KEY (provider_proof_evidence_public_id, provider_proof_target_public_id, provider_proof_evidence_type) REFERENCES system_backup_evidence(public_id, owner_target_public_id, evidence_type) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_external_action_state CHECK",
		"observed_checksum = payload_sha256",
		"observed_checksum <> payload_sha256",
		"state = 'confirmed_absent' AND last_checked_at IS NOT NULL AND last_checked_at >= dispatch_deadline",
		"CONSTRAINT_NAME = 'fk_sb_backup_finalization_action'",
		"ALTER TABLE system_backups ADD CONSTRAINT fk_sb_backup_finalization_action",
		"CONSTRAINT_NAME = 'fk_sb_prune_item_external_action'",
		"ALTER TABLE system_backup_prune_items ADD CONSTRAINT fk_sb_prune_item_external_action",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 071 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, forbidden := range []string{"CREDENTIAL_ENVELOPE", "PRESIGNED_URL", "AUTHORIZATION", "OPAQUE_CREDENTIAL", "DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, forbidden) {
			t.Fatalf("migration 071 must persist immutable non-secret requests without implementing provider dispatch; found %q", forbidden)
		}
	}
}

func TestMigration072CreatesCheckAuthorities(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/072_add_system_backup_check_authority.sql")
	if err != nil {
		t.Fatalf("read migration 072: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 2 {
		t.Fatalf("migration 072 must contain two additive CREATE TABLE statements, got %d", len(statements))
	}
	for index, table := range []string{"system_backup_source_writer_check_states", "system_backup_check_results"} {
		if !strings.Contains(statements[index], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 072 statement %d must create %s", index+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"UNIQUE KEY uk_sb_writer_check_config (origin_installation_id, config_version)",
		"FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_writer_check_hashes CHECK",
		"CONSTRAINT chk_sb_writer_check_result CHECK",
		"check_state = 'clean' AND reason_code = 'none' AND difference_count = 0 AND last_success_at IS NOT NULL AND last_success_at = checked_at",
		"check_state = 'drift' AND reason_code IN ('identity_mismatch', 'writer_missing', 'writer_unregistered', 'policy_mismatch') AND difference_count >= 1",
		"CONSTRAINT chk_sb_writer_check_claim CHECK",
		"UNIQUE KEY uk_sb_check_result_identity (target_type, target_public_id, attempt_no_sentinel, mode, category, check_code)",
		"FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT",
		"FOREIGN KEY (origin_installation_id, cleanup_target_public_id, cleanup_operation_type) REFERENCES system_backup_operations(origin_installation_id, public_id, operation_type) ON DELETE RESTRICT",
		"CONSTRAINT chk_sb_check_result_target CHECK",
		"mode = 'backup_validate' AND attempt_no IS NOT NULL AND attempt_no >= 1",
		"CONSTRAINT chk_sb_check_result_category CHECK",
		"CONSTRAINT chk_sb_check_result_payload CHECK",
		"expected_canonical_json BLOB NOT NULL",
		"actual_canonical_json BLOB NOT NULL",
		"expected_sha256 = SHA2(expected_canonical_json, 256)",
		"actual_sha256 = SHA2(actual_canonical_json, 256)",
		"JSON_LENGTH(CONVERT(expected_canonical_json USING utf8mb4)) <= 128",
		"CONSTRAINT chk_sb_check_result_status CHECK",
		"status = 'warning' AND skip_reason IS NULL AND warning_code IS NOT NULL",
		"status = 'failed' AND skip_reason IS NULL AND warning_code IS NULL AND check_classification IS NOT NULL AND failure_category <> 'none'",
		"evidence_public_id IS NOT NULL AND evidence_sha256 IS NOT NULL",
		"CONSTRAINT chk_sb_check_result_evidence CHECK",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 072 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, forbidden := range []string{"RAW_WRITER_INVENTORY", "CHECK_REGISTRY_JSON", "PROVIDER_PAYLOAD", "CREDENTIAL_VALUE", "DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, forbidden) {
			t.Fatalf("migration 072 must keep owner discovery and verifier registries external; found %q", forbidden)
		}
	}
}

func TestMigration068CreatesCoordinationAndObservabilityAuthorities(t *testing.T) {
	raw, err := embeddedMigrations.ReadFile("migrations/068_add_system_backup_coordination_observability.sql")
	if err != nil {
		t.Fatalf("read migration 068: %v", err)
	}

	statements := splitSQLStatements(string(raw))
	if len(statements) != 6 {
		t.Fatalf("migration 068 must contain six additive CREATE TABLE statements, got %d", len(statements))
	}
	for index, table := range []string{
		"system_backup_events",
		"system_backup_alert_states",
		"system_artifact_lease_states",
		"system_artifact_leases",
		"system_maintenance_locks",
		"system_maintenance_mutation_leases",
	} {
		if !strings.Contains(statements[index], "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("migration 068 statement %d must create %s", index+1, table)
		}
	}

	sql := strings.Join(statements, "\n")
	for _, required := range []string{
		"KEY idx_sb_event_cursor (target_type, target_public_id, created_at, id)",
		"CONSTRAINT chk_sb_event_type CHECK",
		"CONSTRAINT chk_sb_event_task_status CHECK",
		"CONSTRAINT chk_sb_event_details CHECK",
		"UNIQUE KEY uk_sb_alert_scope (origin_installation_id, rule_key, matrix_key, task_type, task_purpose)",
		"CONSTRAINT chk_sb_alert_sequence CHECK",
		"CONSTRAINT chk_sb_alert_lifecycle CHECK",
		"UNIQUE KEY uk_sb_artifact_lease_mode (origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode)",
		"UNIQUE KEY uk_sb_artifact_lease_holder (origin_installation_id, source_artifact_type, source_public_id, holder_type, holder_public_id)",
		"UNIQUE KEY uk_sb_artifact_delete_guard (origin_installation_id, delete_source_guard)",
		"CONSTRAINT chk_sb_artifact_lease_holder CHECK",
		"FOREIGN KEY (origin_installation_id, source_artifact_type, source_public_id, lease_generation, lease_mode) REFERENCES system_artifact_lease_states(origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode) ON DELETE RESTRICT ON UPDATE RESTRICT",
		"UNIQUE KEY uk_sb_maintenance_gate (origin_installation_id, scope)",
		"CONSTRAINT chk_sb_maintenance_idle CHECK",
		"CONSTRAINT chk_sb_maintenance_fence CHECK",
		"TIMESTAMPDIFF(MICROSECOND, heartbeat_at, lease_expires_at) <= lock_ttl_seconds * 1000000",
		"FOREIGN KEY (origin_installation_id, scope) REFERENCES system_maintenance_locks(origin_installation_id, scope) ON DELETE RESTRICT",
		"TIMESTAMPDIFF(MICROSECOND, heartbeat_at, expires_at) <= lease_ttl_seconds * 1000000",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 068 missing %q", required)
		}
	}

	upperSQL := strings.ToUpper(sql)
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(upperSQL, destructive) {
			t.Fatalf("migration 068 must preserve existing rows; found %q", destructive)
		}
	}
}

func TestSystemImageSettingRepositoryHasNoRuntimeDDL(t *testing.T) {
	raw, err := os.ReadFile("../repository/system_image_setting_repository.go")
	if err != nil {
		t.Fatalf("read system image setting repository: %v", err)
	}

	source := strings.ToUpper(string(raw))
	for _, forbidden := range []string{"CREATE TABLE", "ALTER TABLE", "CREATE INDEX", "INFORMATION_SCHEMA"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("system image setting repository must not own runtime DDL; found %q", forbidden)
		}
	}
}
