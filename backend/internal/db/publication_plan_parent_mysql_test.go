package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const parentInstallation = "installation_original_parent_fixture"
const parentBackupA = "sbk_11111111-1111-4111-8111-111111111111"
const parentBackupB = "sbk_22222222-2222-4222-8222-222222222222"

// These are explicitly inert SQL parent fixtures. They prove native relational
// constraints, not a valid encrypted business plan or a successful backup.
func seedPublicationPlanParentFixtures(t *testing.T, ctx context.Context, database *sql.DB, invalidOldPublish bool) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("publication parent seed", err)
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "admin-control-redacted-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Request struct {
			Config json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(raw, &example) != nil {
		t.Fatal("config example")
	}
	var values struct {
		Alert                            string      `json:"alert_profile"`
		Minimum                          json.Number `json:"minimum_recovery_points"`
		Durations, Capacity, Concurrency map[string]json.Number
		Preflight                        map[string]json.Number `json:"preflight_limits"`
		Registries                       []struct {
			Kind            string `json:"registry_kind"`
			Version, SHA256 string
		}
		References []struct {
			Purpose, Version string
			IdentityHash     string `json:"identity_hash"`
		}
	}
	if json.Unmarshal(example.Request.Config, &values) != nil {
		t.Fatal("config fixture")
	}
	digest := sha256.Sum256([]byte(`{}`))
	checksum := hex.EncodeToString(digest[:])
	columns := []string{"origin_installation_id", "version", "config_sha256", "config_size_bytes", "enabled", "alert_profile", "minimum_recovery_points", "created_by"}
	args := []any{parentInstallation, 1, checksum, 2, false, values.Alert, values.Minimum.String(), "system:parent-fixture"}
	for name, group := range map[string]map[string]json.Number{"durations": values.Durations, "capacity": values.Capacity, "concurrency": values.Concurrency, "preflight": values.Preflight} {
		for key, value := range group {
			if name == "preflight" {
				key = "preflight_" + key
			}
			columns = append(columns, key)
			args = append(args, value.String())
		}
	}
	for _, ref := range values.Registries {
		columns = append(columns, ref.Kind+"_registry_version", ref.Kind+"_registry_sha256")
		args = append(args, ref.Version, ref.SHA256)
	}
	for _, ref := range values.References {
		columns = append(columns, ref.Purpose+"_identity_hash", ref.Purpose+"_ref_version")
		args = append(args, ref.IdentityHash, ref.Version)
	}
	exec("INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	exec(`INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key) VALUES(?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, parentInstallation)
	for _, backup := range []string{parentBackupA, parentBackupB} {
		exec(`INSERT INTO system_backup_v2_backups(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,source_orchestrator,source_profile,matrix_key,runner,task_purpose,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id) VALUES(?,?,'system','system:controller','ParentFixture',?,?,?,1,'{}',2,?,TIMESTAMPADD(MINUTE,5,UTC_TIMESTAMP(6)),'kubernetes','cluster','k8s-cluster','k8s','functional_test','workspace',?,'fixture-v1',?,'fixture-v1','same-cluster-copy','','local')`, backup, parentInstallation, backup, checksum, backup, checksum, checksum, checksum)
		exec(`INSERT INTO system_backup_v2_execution_inputs(origin_installation_id,task_public_id,task_type,profile_json,profile_sha256,request_json) VALUES(?,?,'backup','{}',?,'{}')`, parentInstallation, backup, checksum)
		for _, phase := range []string{"capture", "secret_capture", "publish"} {
			exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) VALUES('backup',?,1,?)`, backup, phase)
		}
	}
	exec(`INSERT INTO system_backup_v2_execution_plans(origin_installation_id,task_public_id,schema_version,profile_sha256,config_sha256,plan_sha256,key_version,nonce,ciphertext) VALUES(?,?,'parent-fixture.v1',?,?,?,'fixture-v1',?,?)`, parentInstallation, parentBackupA, checksum, checksum, checksum, make([]byte, 12), make([]byte, 18))
	if !invalidOldPublish {
		exec(`INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) VALUES(?,?,1,'capture','plan',?,'fixture-v1',?)`, parentInstallation, parentBackupA, checksum, []byte("inert original plan DATA"))
	}
	for _, phase := range []string{"capture", "secret_capture", "publish"} {
		exec(`INSERT INTO system_backup_v2_job_send_intents(origin_installation_id,task_public_id,phase,job_unit_key,namespace_name,namespace_uid,job_name,spec_sha256) VALUES(?,?,?,'parent-fixture','fixture','fixture-ns',?,?)`, parentInstallation, parentBackupA, phase, "parent-"+strings.ReplaceAll(phase, "_", "-"), checksum)
	}
}

func checkPublicationPlanParentConstraints(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	insert := func(backup string, attempt int, phase, unit string) error {
		_, err := database.ExecContext(ctx, `INSERT INTO system_backup_v2_job_send_intents(origin_installation_id,task_public_id,phase,job_unit_key,attempt_no,namespace_name,namespace_uid,job_name,spec_sha256) VALUES(?,?,?,?,?,'fixture','fixture-ns',?,?)`, parentInstallation, backup, phase, unit, attempt, "parent-"+unit, digest)
		return err
	}
	for _, phase := range []string{"capture", "secret_capture", "publish"} {
		var count int
		if database.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase=? AND job_unit_key='parent-fixture'`, parentInstallation, parentBackupA, phase).Scan(&count) != nil || count != 1 {
			t.Fatal("preexisting original 121 row was lost", phase)
		}
	}
	for _, item := range []struct{ phase, unit, constraint string }{{"publish", "missing-plan", "sbv2_fk_job_send_publication_plan"}, {"capture", "missing-legacy-plan", "sbv2_fk_job_send_legacy_plan"}, {"secret_capture", "missing-secret-plan", "sbv2_fk_job_send_legacy_plan"}} {
		if err := insert(parentBackupB, 1, item.phase, item.unit); err == nil || !strings.Contains(err.Error(), item.constraint) {
			t.Fatal("missing/wrong-task parent accepted", item.unit, err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) VALUES(?,?,2,'capture','plan',?,'fixture-v1','wrong attempt DATA')`, parentInstallation, parentBackupB, digest); err != nil {
		t.Fatal(err)
	}
	if err := insert(parentBackupB, 1, "publish", "wrong-attempt-plan"); err == nil || !strings.Contains(err.Error(), "sbv2_fk_job_send_publication_plan") {
		t.Fatal("wrong-attempt plan parent accepted", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) VALUES(?,?,1,'capture','capture_result',?,'fixture-v1','result only DATA')`, parentInstallation, parentBackupB, digest); err != nil {
		t.Fatal(err)
	}
	if err := insert(parentBackupB, 1, "publish", "result-only-plan"); err == nil || !strings.Contains(err.Error(), "sbv2_fk_job_send_publication_plan") {
		t.Fatal("capture_result substituted for original plan", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) VALUES(?,?,1,'capture','plan',?,'fixture-v1','matching original plan DATA')`, parentInstallation, parentBackupB, digest); err != nil {
		t.Fatal(err)
	}
	if err := insert(parentBackupB, 1, "publish", "matching-plan"); err != nil {
		t.Fatal("matching original 122 plan parent rejected", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) VALUES('backup',?,2,'publish')`, parentBackupB); err != nil {
		t.Fatal(err)
	}
	if err := insert(parentBackupB, 2, "publish", "attempt-two"); err == nil || !strings.Contains(err.Error(), "sbv2_chk_job_send_hash") {
		t.Fatal("original attempt=1 CHECK was not the actual refusal", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE system_backup_v2_job_send_intents SET phase='capture' WHERE task_public_id=? AND job_unit_key='matching-plan'`, parentBackupB); err == nil || !strings.Contains(err.Error(), "sbv2_fk_job_send_legacy_plan") {
		t.Fatal("phase change escaped legacy plan parent", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE system_backup_v2_job_send_intents SET publication_plan_kind='capture_result' WHERE task_public_id=? AND job_unit_key='matching-plan'`, parentBackupB); err == nil {
		t.Fatal("caller changed original plan record kind")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=1 AND record_kind='plan'`, parentInstallation, parentBackupB); err == nil {
		t.Fatal("bound original plan parent deleted")
	}
}
