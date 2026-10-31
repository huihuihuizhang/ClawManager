package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// This exercises the DATA collector/registered proof protocol on real original
// SQL, not capture/provider authorization. The service's concrete live capture
// wrapper and D's original worker supply those independent boundaries.
func TestAControlEvidenceActualSQLCompleteNonemptyWindowAndReadback(t *testing.T) {
	x, _, _ := newAOriginalPublicationService(t)
	h := x.history
	// Use the independently owned admin metadata fixture for source data setup;
	// no broad privilege is granted to the actual worker/controller account.
	ctx := context.Background()
	conn, err := h.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("actual source metadata seed", err)
		}
	}
	exec("SET FOREIGN_KEY_CHECKS=0")
	for _, item := range [][2]string{{"001_init_schema.sql", "users"}, {"001_init_schema.sql", "audit_logs"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_restore_drills"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_preflights"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_artifact_verifications"}, {"100_backup_v2_add_system_backup_promotion_authority.sql", "system_backup_v2_promotions"}, {"096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_dependency_health"}, {"096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_provider_capabilities"}, {"099_backup_v2_add_system_backup_coordination_observability.sql", "system_backup_v2_alert_states"}} {
		exec(aPublicationActualTable(t, item[0], item[1]))
	}
	exec("RENAME TABLE system_backup_v2_installation_state TO system_backup_v2_installation_state_a_source_fixture")
	exec(aPublicationActualTable(t, "096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_installation_state"))
	exec("SET FOREIGN_KEY_CHECKS=1")
	exec(`INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,monitoring_armed,monitoring_armed_reason,matrix_key) VALUES(?,1,TRUE,UTC_TIMESTAMP(6),FALSE,'none','k8s-cluster')`, h.original.InstallationID)
	const secretMarker = "opaque-sensitive-token-must-not-enter-sidecar"
	for i := 0; i < 121; i++ {
		exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,request_id) VALUES(?,'backup',?,?,'info','capturing',?,FALSE,'actual-control-history')`, h.original.InstallationID, h.original.TaskPublicID, c.TaskClaimAcquiredEvent, secretMarker)
	}
	details, _ := json.Marshal(map[string]string{"origin_installation_id": h.original.InstallationID, "token": secretMarker, "password": secretMarker})
	exec(`INSERT INTO audit_logs(action,resource_type,details) VALUES('system_backup.control.snapshot','system_backup_v2',?)`, details)
	exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present) VALUES('installation_foreign_control','backup',?,?,'info','capturing',?,FALSE)`, h.original.TaskPublicID, c.TaskClaimAcquiredEvent, secretMarker)
	scope := ce.Scope{Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: h.original.AttemptNo}
	sourceID, err := ce.SourceIdentity(h.cfg.Deployment.ServerUUID, h.cfg.Deployment.Database)
	if err != nil {
		t.Fatal(err)
	}
	expected := ce.Expected{Scope: scope, ConfigSHA256: h.original.ConfigSHA256, SourceIdentitySHA256: sourceID, SchemaRegistry: ce.RegistryPin{Version: "local-source-schema-r1", SHA256: hash([]byte("independent fixture schema"))}, RedactionRegistry: ce.RegistryPin{Version: "local-redaction-r1", SHA256: hash([]byte("independent fixture redaction"))}}
	names := []string{"system_backup_v2_backups", "system_backup_v2_configs", "system_backup_v2_evidence"}
	sort.Strings(names)
	namesRaw, _ := ce.Canonical(names)
	sourceBody, err := ce.Canonical(ce.SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: scope, ConfigSHA256: expected.ConfigSHA256, SourceIdentitySHA256: sourceID, Registry: expected.SchemaRegistry, ExcludedNamesSHA256: hash(namesRaw), IncludedControlCount: 0})
	if err != nil {
		t.Fatal(err)
	}
	source := ce.RegisteredEvidence{PublicID: "sev_00000000-0000-4000-8000-000000000010", SHA256: hash(sourceBody), OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: sourceBody}
	tx, err := h.admin.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = ce.RegisterSQL(ctx, tx, scope, []ce.RegisteredEvidence{source}, h.original.DeadlineAt); err != nil {
		tx.Rollback()
		t.Fatal("original registered source fixture", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = h.admin.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	registered, err := ce.LoadRegisteredSQL(ctx, tx, scope, ce.EvidenceRef{PublicID: source.PublicID, SHA256: source.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ce.CollectSQL(ctx, tx, expected, 3600, names, registered)
	if err != nil {
		t.Fatal("actual nine-group RR SQL snapshot", err)
	}
	if len(snapshot.Groups["event"]) != 121 || len(snapshot.Groups["audit"]) != 1 || len(snapshot.Groups["installation_state"]) != 1 {
		t.Fatal("actual metadata history was truncated or crossed installation scope")
	}
	proposal, err := ce.Assemble(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(proposal.Prepared.SidecarJSON, []byte(secretMarker)) || bytes.Contains(proposal.Prepared.ProofsJSON, []byte(secretMarker)) {
		t.Fatal("raw event/audit secret leaked")
	}
	if err = ce.RegisterSQL(ctx, tx, scope, proposal.Evidence, h.original.DeadlineAt); err != nil {
		t.Fatal("actual canonical proof registration", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = h.admin.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	entries := []ce.RegisteredEvidence{}
	for _, ref := range proposal.Prepared.Locator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, scope, ref)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	rebuilt, err := ce.Rebuild(ctx, proposal.Prepared.Locator, entries)
	if err != nil {
		t.Fatal("same registered bodies did not rebuild", err)
	}
	sidecar, err := ce.Verify(ctx, rebuilt.SidecarJSON, rebuilt.ProofsJSON, expected)
	if err != nil || sidecar.Groups["event"].Count != 121 || len(sidecar.Groups["event"].Evidence) != 4 {
		t.Fatal("independent original SQL body verification", err)
	}
	if _, err = ce.Rebuild(ctx, proposal.Prepared.Locator, entries[1:]); err == nil {
		t.Fatal("missing registered artifact body repaired")
	}
	// The captured metadata cutoff is real and precedes this task's terminal.
	var now time.Time
	h.admin.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now)
	if sidecar.End.After(now) || sidecar.Generated.After(now) {
		t.Fatal("invented future terminal/self-reference cutoff")
	}
	tx.Rollback()
	// A subsequent, honestly over-budget declared window rejects in real SQL.
	// It cannot silently shorten the original hour, retain its first 640 rows,
	// or overwrite the earlier immutable 121-record capture/proofs.
	for i := 121; i <= ce.MaxGroupRecords; i++ {
		exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,request_id) VALUES(?,'backup',?,?,'info','capturing','subsequent history',FALSE,'actual-control-history')`, h.original.InstallationID, h.original.TaskPublicID, c.TaskClaimAcquiredEvent)
	}
	tx, err = h.admin.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	oversized, err := ce.CollectSQL(ctx, tx, expected, 3600, names, registered)
	if !errors.Is(err, ce.ErrCapacity) || oversized.Groups != nil {
		t.Fatal("real SQL capacity truncated or falsified original coverage", err)
	}
	if _, err = ce.Verify(ctx, rebuilt.SidecarJSON, rebuilt.ProofsJSON, expected); err != nil {
		t.Fatal("new history changed original immutable snapshot", err)
	}
}
