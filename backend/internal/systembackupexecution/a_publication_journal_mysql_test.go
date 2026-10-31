package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

func aPublicationActualTable(t *testing.T, file, table string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", file))
	if err != nil {
		t.Fatal(err)
	}
	start := "CREATE TABLE IF NOT EXISTS " + table + " ("
	_, body, ok := strings.Cut(string(raw), start)
	if !ok {
		t.Fatal("actual table not found", table)
	}
	body, _, ok = strings.Cut(body, ";\n")
	if !ok {
		body, _, ok = strings.Cut(strings.SplitN(string(raw), start, 2)[1], ";\r\n")
	}
	if !ok {
		t.Fatal("table end", table)
	}
	return start + body + ";"
}

// The original consumer fixture owns and UUID/marker-checks its random schema.
// Replace only its narrow test ledgers with EXACT production DDL. All CHECKs,
// ENUMs, generated columns, unique indexes and relevant FKs stay enforced.
func aUseActualPublicationDDL(t *testing.T, x *aPublisherVerifierFixture, target PublicationTargetMaterials) {
	t.Helper()
	h := x.history
	ctx := context.Background()
	conn, err := h.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("actual publication DDL/seed", err)
		}
	}
	var config []byte
	var version uint64
	var heartbeat, lease, deadline time.Time
	var originalCapacity int64
	if h.admin.QueryRow("SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1",h.original.InstallationID).Scan(&originalCapacity)!=nil{t.Fatal("original metadata capacity")}
	originalKEKIdentity, originalKEKVersion := x.cfg.Binding.ConfigRef.IdentityHash, x.cfg.Binding.ConfigRef.Version
	if h.admin.QueryRow("SELECT config_snapshot_json,row_version,heartbeat_at,controller_lease_expires_at,deadline_at FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&config, &version, &heartbeat, &lease, &deadline) != nil {
		t.Fatal("original task metadata")
	}
	// FK checks are disabled ONLY on this isolated DDL connection while the
	// original mutually-referencing production tables are created, then restored
	// before any seed or production operation. No CHECK/unique is disabled.
	exec("SET FOREIGN_KEY_CHECKS=0")
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_backups", "system_backup_v2_operations", "system_backup_v2_evidence", "system_backup_v2_events"} {
		exec("RENAME TABLE " + table + " TO " + table + "_a_narrow_fixture")
	}
	tables := [][2]string{{"096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_evidence"}, {"097_backup_v2_add_system_backup_config_and_operations.sql", "system_backup_v2_configs"}, {"097_backup_v2_add_system_backup_config_and_operations.sql", "system_backup_v2_operations"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_backups"}, {"099_backup_v2_add_system_backup_coordination_observability.sql", "system_backup_v2_events"}, {"101_backup_v2_add_system_backup_prune_authority.sql", "system_backup_v2_prune_runs"}, {"101_backup_v2_add_system_backup_prune_authority.sql", "system_backup_v2_prune_items"}, {"102_backup_v2_add_system_backup_external_action_authority.sql", "system_backup_v2_external_actions"}}
	for _, item := range tables {
		exec(aPublicationActualTable(t, item[0], item[1]))
	}
	exec(aPublicationActualTable(t, "096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_evidence_chunks"))
	exec("ALTER TABLE system_backup_v2_backups ADD CONSTRAINT sbv2_fk_sb_backup_finalization_action FOREIGN KEY(finalization_action_public_id) REFERENCES system_backup_v2_external_actions(public_id) ON DELETE RESTRICT")
	exec("SET FOREIGN_KEY_CHECKS=1")
	exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) SELECT public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at FROM system_backup_v2_evidence_a_narrow_fixture`)
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
		Enabled                          bool        `json:"enabled"`
		Alert                            string      `json:"alert_profile"`
		Minimum                          json.Number `json:"minimum_recovery_points"`
		Durations, Capacity, Concurrency map[string]json.Number
		Preflight                        map[string]json.Number `json:"preflight_limits"`
		Registries                       []security.BootstrapRegistryRef
		References                       []security.BootstrapSecretRef
	}
	if json.Unmarshal(example.Request.Config, &values) != nil {
		t.Fatal("config values")
	}
	values.Capacity["control_metadata_capacity_bytes"]=json.Number(strconv.FormatInt(originalCapacity,10))
	columns := []string{"origin_installation_id", "version", "config_sha256", "config_size_bytes", "enabled", "alert_profile", "minimum_recovery_points", "created_by"}
	args := []any{h.original.InstallationID, 1, hash(config), len(config), true, values.Alert, values.Minimum.String(), "system:controller"}
	for group, members := range map[string]map[string]json.Number{"durations": values.Durations, "capacity": values.Capacity, "concurrency": values.Concurrency, "preflight_limits": values.Preflight} {
		for name, value := range members {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			columns = append(columns, name)
			args = append(args, value.String())
		}
	}
	for _, ref := range values.Registries {
		columns = append(columns, ref.Kind+"_registry_version", ref.Kind+"_registry_sha256")
		args = append(args, ref.Version, ref.SHA256)
	}
	for _, ref := range values.References {
		identity, version := ref.IdentityHash, ref.Version
		switch ref.Purpose {
		case "kek":
			identity, version = originalKEKIdentity, originalKEKVersion
		case "artifact_write":
			identity, version = target.WriteIdentityHash, target.WriteRefVersion
		case "artifact_read":
			identity, version = target.ReadIdentityHash, target.ReadRefVersion
		case "artifact_ca":
			identity, version = target.CAIdentityHash, target.CARefVersion
		}
		columns = append(columns, ref.Purpose+"_identity_hash", ref.Purpose+"_ref_version")
		args = append(args, identity, version)
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	exec("INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+marks+")", args...)
	exec(`INSERT INTO system_backup_v2_backups(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,status,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,controller_owner,row_version,heartbeat_at,controller_lease_expires_at,deadline_at,started_at,source_orchestrator,source_profile,matrix_key,runner,task_purpose,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id,maintenance_lock_owner,maintenance_fencing_token,created_at) VALUES(?,?,'system','system:controller','ActualPublicationFixture','actual-publication-fixture',?,?,'validating',1,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),'kubernetes','cluster','k8s-cluster','k8s','functional_test','workspace',?,?,?,?,'same-cluster-copy','','local',?,?,TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)))`, h.original.TaskPublicID, h.original.InstallationID, hash([]byte("original-create")), h.original.RequestID, config, len(config), hash(config), h.token.Owner, version, heartbeat, lease, deadline, target.ReadIdentityHash, target.ReadRefVersion, target.CAIdentityHash, target.CARefVersion, h.original.MaintenanceOwner, h.original.MaintenanceFencingToken)
	account := strings.Split(h.owner.Identity.DeploymentBinding().DatabaseAccount, "@")[0]
	database := h.owner.Identity.DeploymentBinding().Database
	grants, err := c.PublicationGrantSQL(database, account, "127.0.0.1", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range grants {
		// The focused capture fixture predates unrelated runtime tables. Apply
		// the official role's exact verbs to every real table present here; no
		// hand-written broader test privilege is introduced.
		_, tablePart, ok := strings.Cut(statement, "`.`")
		if !ok {
			t.Fatal("official scoped table grant", statement)
		}
		table, _, ok := strings.Cut(tablePart, "`")
		if !ok {
			t.Fatal("official table boundary")
		}
		var exists int
		if conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&exists) != nil {
			t.Fatal("table inventory")
		}
		if exists == 1 {
			exec(statement)
		}
	}
	// Verify enforcement is actually on for this pooled production connection.
	var checks int
	if h.db.QueryRow("SELECT @@foreign_key_checks").Scan(&checks) != nil || checks != 1 {
		t.Fatal("production FK checks disabled")
	}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_external_actions"} {
		var count int
		if h.admin.QueryRow("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND CONSTRAINT_TYPE='CHECK'", table).Scan(&count) != nil || count < 5 {
			t.Fatal("production CHECKs missing", table, count)
		}
	}
}

func TestAPublicationOriginalJournalRealDDLAndLostAcknowledgements(t *testing.T) {
	x := newAPublisherVerifierFixture(t, true)
	aStartPublisherVerifierSamePod(t, x)
	h := x.history
	store, state := newANativePublicationStore(t, time.Minute)
	store.config.InstallationID = h.original.InstallationID
	store.config.Root = h.original.InstallationID + "/"
	aUseActualPublicationDDL(t, x, store.config)
	ctx := context.Background()
	access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
	if err != nil {
		t.Fatal("original current claim on actual DDL", err)
	}
	payload := []byte(`{"original":"manifest"}`)
	intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/3/manifest.json", Payload: payload, Deadline: access.ValidUntil().Add(-time.Second)}
	action, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent)
	if err != nil || !send {
		t.Fatal("actual original journal freeze", err)
	}
	if action.Deadline.Nanosecond()%1000 != 0 {
		t.Fatal("journal deadline was not frozen at SQL microseconds")
	}
	var status, attention, actionID string
	var canCancel bool
	if h.db.QueryRow("SELECT status,attention_reason,can_cancel,finalization_action_public_id FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&status, &attention, &canCancel, &actionID) != nil || status != "publishing" || attention != "none" || canCancel || actionID != action.ID {
		t.Fatal("same original task did not close cancellation atomically")
	}
	state.lostACK = true
	if _, err = store.create(ctx, action.Key, bytes.NewReader(action.Payload), action.Size, action.PayloadSHA, action.Deadline); err == nil {
		t.Fatal("transport ACK should be lost")
	}
	object, _, err := readPublicationJSON(ctx, store, action, access.ValidUntil())
	if err != nil {
		t.Fatal(err)
	}
	if err = h.service.recordPublicationObservation(ctx, h.token, h.original.AttemptNo, action, object, nil); err != nil {
		t.Fatal("actual journal confirmation", err)
	}
	recovered, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent)
	if err != nil || send || recovered.State != "confirmed_present" || !recovered.ObjectVersion.Valid || recovered.ObjectVersion.String != "original-v1" || state.puts != 1 {
		t.Fatal("original request replayed or observation lost", err)
	}
	// A different payload for the same original identity never starts a write.
	intent.Payload = []byte(`{"replacement":true}`)
	if _, send, err = h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent); err == nil || send {
		t.Fatal("frozen payload replaced")
	}
	// Exercise the REAL CHECK/FK constraints, not a varchar status substitute.
	for _, q := range []string{"UPDATE system_backup_v2_backups SET can_cancel=TRUE WHERE public_id=?", "UPDATE system_backup_v2_backups SET status='succeeded' WHERE public_id=?", "UPDATE system_backup_v2_backups SET finalization_action_public_id='sxa_00000000-0000-4000-8000-000000000999' WHERE public_id=?"} {
		if _, err = h.admin.Exec(q, h.original.TaskPublicID); err == nil {
			t.Fatal("actual original DDL accepted invalid finalization state")
		}
	}
}

func newAOriginalPublicationService(t *testing.T) (*aPublisherVerifierFixture, *nativePublicationS3, *aNativePublicationServer) {
	t.Helper()
	store, state := newANativePublicationStore(t, time.Minute)
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &store.config})
	aStartPublisherVerifierSamePod(t, x)
	aUseActualPublicationDDL(t, x, store.config)
	return x, store, state
}

func TestAPublicationActualServiceTargetAndConfirmedReadRechecks(t *testing.T) {
	for _, mode := range []string{"unchanged", "actual-renew-during-get", "original-grant-revoke-during-get", "target-pin-change-during-get", "journal-key-change-during-get", "journal-version-change-during-get"} {
		t.Run(mode, func(t *testing.T) {
			x, store, state := newAOriginalPublicationService(t)
			h := x.history
			ctx := context.Background()
			access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
			if err != nil {
				t.Fatal(err)
			}
			intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/3/manifest.json", Payload: []byte(`{"original":"whole-manifest"}`), Deadline: access.ValidUntil().Add(-time.Second)}
			first, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent)
			if err != nil || first.Version != "original-v1" || state.puts != 1 {
				t.Fatal("actual service publication", err)
			}
			changed := false
			state.onGet = func() {
				if changed {
					return
				}
				changed = true
				switch mode {
				case "actual-renew-during-get":
					fresh, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Renew(ctx, h.token, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
					if err != nil || fresh.RowVersion != h.token.RowVersion+1 {
						t.Fatal("actual current Renew", err)
					}
				case "original-grant-revoke-during-get":
					if os.WriteFile(h.cfg.GrantMount.File, []byte(`{"revoked":true}`), 0600) != nil {
						t.Fatal("actual grant mutation")
					}
				case "target-pin-change-during-get":
					if os.WriteFile(h.service.Config.PublicationTarget.Path, []byte(`{"substitute":true}`), 0600) != nil {
						t.Fatal("actual independent target mutation")
					}
				case "journal-key-change-during-get":
					if _, err := h.admin.Exec("UPDATE system_backup_v2_external_actions SET final_key=? WHERE target_public_id=?", store.config.Root+"other/manifest.json", h.original.TaskPublicID); err != nil {
						t.Fatal(err)
					}
				case "journal-version-change-during-get":
					if _, err := h.admin.Exec("UPDATE system_backup_v2_external_actions SET row_version=row_version+1 WHERE target_public_id=?", h.original.TaskPublicID); err != nil {
						t.Fatal(err)
					}
				}
			}
			object, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent)
			if !changed || state.puts != 1 {
				t.Fatal("confirmed original was replayed or network test missed")
			}
			if mode == "unchanged" {
				if err != nil || object.Version != first.Version || object.SHA256 != first.SHA256 {
					t.Fatal("confirmed original read", err)
				}
			} else if err == nil || object.Version != "" {
				t.Fatal("GET changed authority returned proof", err)
			}
		})
	}
}

func TestAPublicationUnknownOriginalExpiredDispatchRemainsQueryOnly(t *testing.T) {
	x, store, state := newAOriginalPublicationService(t)
	h := x.history
	ctx := context.Background()
	intent := publicationJSONIntent{Kind: "marker_put", Key: store.config.Root + h.original.TaskPublicID + "/3/_COMMITTED", Payload: []byte(`{"original":"commit-marker"}`), Deadline: time.Now().Add(400 * time.Millisecond)}
	action, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent)
	if err != nil || !send {
		t.Fatal(err)
	}
	// Simulate death after the committed dispatch boundary, before the syscall.
	// Recovery has no knowledge whether a request ever reached the provider.
	time.Sleep(450 * time.Millisecond)
	object, _, observeErr := readPublicationJSON(ctx, store, action, time.Now().Add(time.Second))
	if observeErr != errPublicationUnavailable {
		t.Fatal("404 was promoted to absence", observeErr)
	}
	if err = h.service.recordPublicationObservation(ctx, h.token, h.original.AttemptNo, action, object, observeErr); err != errPublicationUnavailable {
		t.Fatal("unknown persistence", err)
	}
	var status, attention, stateSQL string
	var canCancel bool
	if h.db.QueryRow("SELECT status,attention_reason,can_cancel FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&status, &attention, &canCancel) != nil || status != "finalization_unknown" || attention != "external_result_unknown" || canCancel {
		t.Fatal("actual task did not retain unknown")
	}
	if h.db.QueryRow("SELECT state FROM system_backup_v2_external_actions WHERE public_id=?", action.ID).Scan(&stateSQL) != nil || stateSQL != "provider_unreachable" {
		t.Fatal("actual journal did not retain unknown")
	}
	// Even a historical zero-count row is not permission to issue a syscall.
	if _, err = h.admin.Exec("UPDATE system_backup_v2_external_actions SET send_attempt_count=0 WHERE public_id=?", action.ID); err != nil {
		t.Fatal(err)
	}
	original, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent)
	if err != nil || send || original.ID != action.ID || !original.Deadline.Equal(action.Deadline) || state.puts != 0 {
		t.Fatal("expired original action regenerated or retried", err)
	}
	beforeObserve := uint64(0)
	if h.db.QueryRow("SELECT observe_attempt_count FROM system_backup_v2_external_actions WHERE public_id=?", action.ID).Scan(&beforeObserve) != nil {
		t.Fatal("original observation count")
	}
	if _, err = (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second); err != nil {
		t.Fatal("actual current release", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err = h.service.RunPublicationPass(ctx); err != errPublicationUnavailable {
		t.Fatal("actual service recovery pass", err)
	}
	var afterObserve uint64
	var owner sql.NullString
	if h.db.QueryRow("SELECT observe_attempt_count FROM system_backup_v2_external_actions WHERE public_id=?", action.ID).Scan(&afterObserve) != nil || afterObserve != beforeObserve+1 {
		t.Fatal("service did not observe original action")
	}
	if h.db.QueryRow("SELECT controller_owner,status FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&owner, &status) != nil || owner.Valid || status != "finalization_unknown" || state.puts != 0 {
		t.Fatal("service synthesized terminal or replayed dispatch")
	}
}

func TestAPublicationActualClaimLongFixedWindowAndExplicitRenew(t *testing.T) {
	if os.Getenv("A_PUBLICATION_LONG_STREAM_TEST") != "1" {
		t.Skip("explicit 31-second original-claim local SQL/TLS test")
	}
	x, store, state := newAOriginalPublicationService(t)
	h := x.history
	ctx := context.Background()
	// A new token is explicitly obtained BEFORE any access/DEK/receipt exists.
	policy := c.LeasePolicy{TTL: 60 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: time.Second}
	token, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Renew(ctx, h.token, policy)
	if err != nil {
		t.Fatal(err)
	}
	access, err := h.service.publicationAccess(ctx, token, h.original.AttemptNo)
	if err != nil {
		t.Fatal(err)
	}
	until := access.ValidUntil()
	if time.Until(until) < 35*time.Second {
		t.Fatal("original business grant does not allow the tested fixed stage")
	}
	intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/3/manifest.json", Payload: []byte(`{"original":"bounded-long-read"}`), Deadline: until.Add(-time.Second)}
	first, err := h.service.publishOriginalJSON(ctx, token, h.original.AttemptNo, store, intent)
	if err != nil {
		t.Fatal(err)
	}
	state.delay = 31 * time.Second
	start := time.Now()
	object, err := h.service.publishOriginalJSON(ctx, token, h.original.AttemptNo, store, intent)
	if err != nil || object.Version != first.Version || object.receipt == nil || time.Since(start) < 30*time.Second || state.puts != 1 || !time.Now().Before(until) || !access.ValidUntil().Equal(until) {
		t.Fatal("actual fixed live claim did not survive legal long stage", err)
	}
	// Receipt can join the SAME actual consumer transaction.
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = object.recheckPublicationReceiptTx(ctx, tx, token); err != nil {
		tx.Rollback()
		t.Fatal("same original consumer receipt", err)
	}
	tx.Rollback()
	next, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Renew(ctx, token, policy)
	if err != nil || next.RowVersion != token.RowVersion+1 {
		t.Fatal("explicit boundary Renew", err)
	}
	tx, err = h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if object.recheckPublicationReceiptTx(ctx, tx, next) == nil || object.recheckPublicationReceiptTx(ctx, tx, token) == nil {
		t.Fatal("old receipt adopted renewed claim")
	}
}
