//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
	"github.com/golang-jwt/jwt/v5"
)

// Establish a plain consistent read after real A authorization, then commit a
// Job change on another connection before D reads its task/execution rows. This
// would expose mixed times under ReadCommitted; RepeatableRead must retain the
// earlier observation while the final A permission check remains current.
type dTaskExecutionSnapshotScope struct {
	base    *SystemBackupReadScope
	taskID  string
	advance func(context.Context) error
}

func (s dTaskExecutionSnapshotScope) AuthorizeRead(ctx context.Context, tx *sql.Tx) (string, error) {
	installation, err := s.base.AuthorizeRead(ctx, tx)
	if err != nil {
		return "", err
	}
	var id string
	if err = tx.QueryRowContext(ctx, "SELECT public_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?", installation, s.taskID).Scan(&id); err != nil {
		return "", err
	}
	if id != s.taskID {
		return "", ErrRegistrationUnavailable
	}
	if err = s.advance(ctx); err != nil {
		return "", err
	}
	return installation, nil
}
func (s dTaskExecutionSnapshotScope) RecheckRead(ctx context.Context, tx *sql.Tx, installation string) error {
	return s.base.RecheckRead(ctx, tx, installation)
}

// This test runs only in the fresh migration namespace. It uses the complete
// migrated 066/067/080 schema, not the narrower A authorization probe DDL.
func TestDAdminReadFullSchemaMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	db.SetMaxOpenConns(8)
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("full read probe is outside the pinned run-owned MySQL")
	}
	for _, filename := range []string{"097_backup_v2_add_system_backup_config_and_operations.sql", "098_backup_v2_add_system_backup_task_execution_core.sql", "109_backup_v2_add_system_backup_registration_runtime.sql"} {
		var count int
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE filename=?", filename).Scan(&count))
		if count != 1 {
			t.Fatal("complete migration not registered", filename)
		}
	}
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_operations", "system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_admin_sessions"} {
		var engine string
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&engine))
		if engine != "InnoDB" {
			t.Fatal("unexpected table engine", table, engine)
		}
	}
	fixture, err := os.ReadFile(os.Getenv("D_ADMIN_READ_FULL_FIXTURE"))
	mysqlMust(t, err)
	digest := sha256.Sum256(fixture)
	if hex.EncodeToString(digest[:]) != os.Getenv("D_ADMIN_READ_FULL_FIXTURE_SHA256") ||
		len(fixture) < 1000 || !strings.Contains(string(fixture), "INSERT INTO system_backup_v2_configs") ||
		strings.Contains(strings.ToUpper(string(fixture)), "DROP DATABASE") {
		t.Fatal("full read fixture is not pinned")
	}
	const own = "installation_d_admin_read_full"
	const foreign = "installation_d_admin_read_foreign"
	seedConfig := func(installation string) {
		conn, e := db.Conn(ctx)
		mysqlMust(t, e)
		defer conn.Close()
		_, e = conn.ExecContext(ctx, "SET @installation_id=?", installation)
		mysqlMust(t, e)
		_, e = conn.ExecContext(ctx, string(fixture))
		mysqlMust(t, e)
	}
	seedConfig(own)
	seedConfig(foreign)
	var userID int64
	var passwordHash string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT id,password_hash FROM users WHERE role='admin' AND is_active=TRUE ORDER BY id LIMIT 1").Scan(&userID, &passwordHash))
	secret := []byte(strings.Repeat("s", 32))
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID, "token_type": "access", "jti": "d-full-read", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}).SignedString(secret)
	mysqlMust(t, err)
	root := t.TempDir()
	newService := func(installation string) (*systembackupread.Service, *SystemBackupReadScope) {
		t.Helper()
		rbac := []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"read-v1","installation_id":"` + installation + `","bindings":[{"actor_id":"` + strconv.FormatInt(userID, 10) + `","subject":"user:` + strconv.FormatInt(userID, 10) + `","role":"viewer"}]}`)
		rbacHash := registrationHash(string(rbac))
		registryPath := filepath.Join(root, installation, "rbac_bindings", "read-v1", rbacHash+".json")
		mysqlMust(t, os.MkdirAll(filepath.Dir(registryPath), 0700))
		mysqlMust(t, os.WriteFile(registryPath, rbac, 0600))
		_, e := db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET rbac_bindings_registry_version='read-v1',rbac_bindings_registry_sha256=?,config_sha256=SHA2('{}',256),config_size_bytes=2 WHERE origin_installation_id=? AND version=1", rbacHash, installation)
		mysqlMust(t, e)
		_, e = db.ExecContext(ctx, "INSERT INTO system_backup_v2_admin_sessions(origin_installation_id,session_sha256,user_id,subject,credential_hash,expires_at,revoked) VALUES(?,?,?,?,?,UTC_TIMESTAMP(6)+INTERVAL 5 MINUTE,FALSE)", installation, registrationHash(token), userID, "user:"+strconv.FormatInt(userID, 10), registrationHash(passwordHash))
		mysqlMust(t, e)
		pinsRaw, e := json.Marshal(SystemBackupReadPins{InstallationID: installation, ConfigVersion: 1, RBACVersion: "read-v1", RBACSHA256: rbacHash, RegistryDirectory: filepath.Join(root, installation)})
		mysqlMust(t, e)
		pinsPath := filepath.Join(root, installation, "read-pins.json")
		mysqlMust(t, os.WriteFile(pinsPath, pinsRaw, 0600))
		sessions, e := NewSQLLoginSessions(db, DatabaseIdentity{ServerUUID: actualUUID, Database: cfg.DBName}, installation, secret)
		mysqlMust(t, e)
		authorizer, e := LoadSystemBackupReadAuthorizer(sessions, pinsPath, registrationHash(string(pinsRaw)))
		mysqlMust(t, e)
		request := httptest.NewRequest("GET", "/api/v1/admin/system-backups", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		scope, e := authorizer.Scope(request)
		mysqlMust(t, e)
		service, e := systembackupread.NewService(db, scope, []byte(strings.Repeat("c", 32)))
		mysqlMust(t, e)
		return service, scope
	}
	ownService, ownScope := newService(own)
	foreignService, foreignScope := newService(foreign)
	// This probe and the following live HTTP probe share the migrated database.
	// Public IDs are globally unique, so installation isolation alone cannot
	// separate fixtures. Reserve UUID prefix 000000d1 for full-schema resources.
	seedBackup := func(installation, suffix string) string {
		publicID := "sbk_000000d1-0000-4000-8000-0000000000" + suffix
		_, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_backups
		(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,
		 config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,
		 source_orchestrator,source_profile,matrix_key,runner,requested_parts,artifact_read_identity_hash,
		 artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id)
		 VALUES(?,?,'admin',?,'POST /system-backups',?,REPEAT('a',64),?,1,'{}',2,SHA2('{}',256),
		 UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,'kubernetes','single-node','k8s-single-node','k8s','mysql',
		 REPEAT('b',64),'fixture-v1',REPEAT('c',64),'fixture-v1','dr-ready-external','', 'isolated')`,
			publicID, installation, strconv.FormatInt(userID, 10), "d-full-read-backup-"+suffix, "d-full-read-"+suffix)
		mysqlMust(t, e)
		return publicID
	}
	first := seedBackup(own, "01")
	second := seedBackup(own, "02")
	third := seedBackup(own, "03")
	_ = seedBackup(foreign, "04")
	otherKinds := []struct {
		kind systembackupread.TaskKind
		id   string
	}{
		{systembackupread.DrillTask, "sdr_000000d1-0000-4000-8000-000000000001"},
		{systembackupread.PreflightTask, "spf_000000d1-0000-4000-8000-000000000001"},
		{systembackupread.VerificationTask, "sav_000000d1-0000-4000-8000-000000000001"},
	}
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_restore_drills
		(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,
		 config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,
		 source_artifact_type,source_public_id,target_profile,restore_target_config_ref,restore_target_config_hash,cleanup_policy)
		 VALUES(?,?,'admin',?,'POST /system-restore-drills','d-full-read-drill-01',REPEAT('a',64),'d-full-read-drill-01',
		 1,'{}',2,SHA2('{}',256),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,
		 'backup',?,'single-node','isolated-target',REPEAT('d',64),'delete-on-success')`, otherKinds[0].id, own, strconv.FormatInt(userID, 10), first)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_preflights
		(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,
		 config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,
		 source_artifact_type,source_public_id,target_profile,restore_target_config_ref,restore_target_config_hash,artifact_compatibility)
		 VALUES(?,?,'admin',?,'POST /system-backup-preflights','d-full-read-preflight-01',REPEAT('a',64),'d-full-read-preflight-01',
		 1,'{}',2,SHA2('{}',256),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,
		 'backup',?,'single-node','isolated-target',REPEAT('d',64),'supported')`, otherKinds[1].id, own, strconv.FormatInt(userID, 10), first)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_artifact_verifications
		(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,
		 config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,
		 verification_scope,source_artifact_type,source_public_id,artifact_state_before,artifact_state_after,
		 unusable_reason_before,unusable_reason_after)
		 VALUES(?,?,'admin',?,'POST /system-backup-artifact-verifications','d-full-read-verify-01',REPEAT('a',64),'d-full-read-verify-01',
		 1,'{}',2,SHA2('{}',256),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,
		 'health','backup',?,'staging','staging','not_committed','not_committed')`, otherKinds[2].id, own, strconv.FormatInt(userID, 10), first)
	mysqlMust(t, err)
	page, err := ownService.ListTaskDTO(ownScope.Context(), systembackupread.BackupTask, "", 2, "")
	mysqlMust(t, err)
	if len(page.Items) != 2 || page.Items[0].PublicID != third || page.Items[1].PublicID != second || page.NextCursor == nil || page.Consistency != "stable_cutoff" {
		t.Fatalf("first full-schema page invalid: %+v", page)
	}
	_ = seedBackup(own, "05") // A later insert must not drift into the held cutoff.
	page2, err := ownService.ListTaskDTO(ownScope.Context(), systembackupread.BackupTask, "", 2, *page.NextCursor)
	mysqlMust(t, err)
	if len(page2.Items) != 1 || page2.Items[0].PublicID != first || page2.NextCursor != nil {
		t.Fatalf("second full-schema page invalid: %+v", page2)
	}
	if _, err := foreignService.ListTaskDTO(foreignScope.Context(), systembackupread.BackupTask, "", 2, *page.NextCursor); !errors.Is(err, systembackupread.ErrDenied) {
		t.Fatalf("cross-install cursor was accepted: %v", err)
	}
	for _, item := range otherKinds {
		other, e := ownService.ListTaskDTO(ownScope.Context(), item.kind, "pending", 2, "")
		mysqlMust(t, e)
		if len(other.Items) != 1 || other.Items[0].PublicID != item.id || other.Items[0].TaskType != item.kind ||
			other.Items[0].OriginInstallationID != own || other.NextCursor != nil || other.Consistency != "eventual" {
			t.Fatalf("full-schema task list invalid for %s: %+v", item.kind, other)
		}
		cross, e := foreignService.ListTaskDTO(foreignScope.Context(), item.kind, "pending", 2, "")
		mysqlMust(t, e)
		if len(cross.Items) != 0 {
			t.Fatalf("cross-install task row leaked for %s: %+v", item.kind, cross)
		}
	}
	for i := 1; i <= 3; i++ {
		id := "sop_000000d1-0000-4000-8000-00000000000" + strconv.Itoa(i)
		_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_operations
		(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,
		 idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,
		 external_action_public_ids_sha256,status,next_reconcile_at,deadline_at)
		 VALUES(?,?,'control_metadata_gc','system',?,'system','system:controller','DFullRead',?,REPEAT('a',64),
		 '[]',2,SHA2('[]',256),'pending',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR)`, id, own, own, "d-full-read-operation-"+strconv.Itoa(i))
		mysqlMust(t, err)
	}
	operations, err := ownService.ListOperationDTO(ownScope.Context(), 2, "")
	mysqlMust(t, err)
	if len(operations.Items) != 2 || operations.NextCursor == nil {
		t.Fatalf("operation page invalid: %+v", operations)
	}
	operations2, err := ownService.ListOperationDTO(ownScope.Context(), 2, *operations.NextCursor)
	mysqlMust(t, err)
	if len(operations2.Items) != 1 || operations2.NextCursor != nil {
		t.Fatalf("operation continuation invalid: %+v", operations2)
	}
	detail, err := ownService.GetOperationDTO(ownScope.Context(), operations.Items[0].PublicID)
	mysqlMust(t, err)
	if detail.PublicID != operations.Items[0].PublicID || detail.OriginInstallationID != own || detail.FailureMessage != nil {
		t.Fatalf("operation detail projection invalid: %+v", detail)
	}
	if _, err := foreignService.ListOperationDTO(foreignScope.Context(), 2, *operations.NextCursor); !errors.Is(err, systembackupread.ErrDenied) {
		t.Fatalf("cross-install operation cursor was accepted: %v", err)
	}
	// D's partial overview contribution reads complete status groups under the
	// real A request scope. It must not derive totals from the earlier pages or
	// include another installation's rows; this is not a full OverviewResource.
	ownControlReader, err := systembackupread.NewReader(db, ownScope)
	mysqlMust(t, err)
	foreignControlReader, err := systembackupread.NewReader(db, foreignScope)
	mysqlMust(t, err)
	t.Run("task_execution_scoped_attempts_and_progress", func(t *testing.T) {
		targets := append([]struct {
			kind systembackupread.TaskKind
			id   string
		}{{systembackupread.BackupTask, first}}, otherKinds...)
		phases := map[systembackupread.TaskKind]string{
			systembackupread.BackupTask: "capture", systembackupread.DrillTask: "restore",
			systembackupread.PreflightTask: "preflight", systembackupread.VerificationTask: "verify",
		}
		for index, target := range targets {
			phase := phases[target.kind]
			for _, attempt := range []int{1, 2} {
				_, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_attempts
				(target_type,target_public_id,attempt_no,phase,status,started_at)
				VALUES(?,?,?,?,'running',UTC_TIMESTAMP(6))`, string(target.kind), target.id, attempt, phase)
				mysqlMust(t, e)
			}
			jobUID := "00000000-0000-4000-8000-00000000002" + strconv.Itoa(index)
			_, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_job_observations
			(schema_version,origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key,
			job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at,
			last_accepted_sequence,last_accepted_body_sha256,last_observed_status,last_observed_at,
			progress_sequence,progress_digest_sha256,last_business_progress_at)
			VALUES('system-backup-job-observation.v1',?,?,?,2,?,'source_mysql',?,2,'fixture-relay','v1',
			UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE,5,REPEAT('a',64),'running',UTC_TIMESTAMP(6),3,REPEAT('b',64),UTC_TIMESTAMP(6))`,
				own, string(target.kind), target.id, phase, jobUID)
			mysqlMust(t, e)
			snapshot, e := ownControlReader.ReadTaskExecution(ownScope.Context(), target.kind, target.id)
			mysqlMust(t, e)
			attempts, jobs := snapshot.Attempts(), snapshot.JobObservations()
			if snapshot.Task().PublicID != target.id || len(attempts) != 2 || len(jobs) != 1 ||
				jobs[0].InstallationID != own || jobs[0].AttemptNumber != 2 || jobs[0].Generation != 2 || jobs[0].Phase != phase || !jobs[0].BusinessProgressAt.Valid {
				t.Fatal("task execution snapshot lost scoped history/current progress", snapshot.Task(), attempts, jobs)
			}
			if _, e = foreignControlReader.ReadTaskExecution(foreignScope.Context(), target.kind, target.id); !errors.Is(e, systembackupread.ErrNotFound) {
				t.Fatal("foreign task execution was visible", e)
			}
			// A later relay observation/heartbeat alone must retain the recorded
			// business-progress time, even when its accepted sequence advances.
			before := jobs[0].BusinessProgressAt
			_, e = db.ExecContext(ctx, `UPDATE system_backup_v2_job_observations SET
			last_accepted_sequence=6,last_observed_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE job_uid=?`, jobUID)
			mysqlMust(t, e)
			after, e := ownControlReader.ReadTaskExecution(ownScope.Context(), target.kind, target.id)
			mysqlMust(t, e)
			if got := after.JobObservations(); len(got) != 1 || got[0].AcceptedSequence != 6 || !got[0].BusinessProgressAt.Time.Equal(before.Time) {
				t.Fatal("heartbeat changed business progress", got)
			}
			if target.kind == systembackupread.BackupTask {
				racedScope := dTaskExecutionSnapshotScope{base: ownScope, taskID: target.id, advance: func(ctx context.Context) error {
					_, e := db.ExecContext(ctx, `UPDATE system_backup_v2_job_observations SET
					last_accepted_sequence=7,progress_sequence=7,last_observed_at=UTC_TIMESTAMP(6),
					last_business_progress_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE job_uid=?`, jobUID)
					return e
				}}
				racedReader, e := systembackupread.NewReader(db, racedScope)
				mysqlMust(t, e)
				raced, e := racedReader.ReadTaskExecution(ownScope.Context(), target.kind, target.id)
				mysqlMust(t, e)
				if got := raced.JobObservations(); len(got) != 1 || got[0].AcceptedSequence != 6 || !got[0].BusinessProgressAt.Time.Equal(before.Time) {
					t.Fatal("task detail mixed observations across transaction snapshots", got)
				}
				var currentSequence int
				mysqlMust(t, db.QueryRowContext(ctx, "SELECT last_accepted_sequence FROM system_backup_v2_job_observations WHERE job_uid=?", jobUID).Scan(&currentSequence))
				if currentSequence != 7 {
					t.Fatal("snapshot race did not commit the competing observation")
				}
			}
		}
	})
	dCheckDetailControlMySQL(t, db, ownScope, foreignScope, own, first, otherKinds)
	t.Run("overview_control_complete_counts_and_installation_isolation", func(t *testing.T) {
		control, e := ownControlReader.ReadOverviewControl(ownScope.Context())
		mysqlMust(t, e)
		state := control.InstallationState()
		if state.InstallationID != own || state.ConfigVersion != 1 || state.LastEffectiveEnabled ||
			control.TaskStatusCounts(systembackupread.BackupTask)["pending"] != 4 || control.OperationStatusCounts()["pending"] != 3 {
			t.Fatal("overview control state/counts do not match committed own rows", state)
		}
		for _, kind := range []systembackupread.TaskKind{systembackupread.DrillTask, systembackupread.PreflightTask, systembackupread.VerificationTask} {
			if control.TaskStatusCounts(kind)["pending"] != 1 {
				t.Fatal("overview omitted task category", kind)
			}
		}
		foreignControl, e := foreignControlReader.ReadOverviewControl(foreignScope.Context())
		mysqlMust(t, e)
		if foreignControl.TaskStatusCounts(systembackupread.BackupTask)["pending"] != 1 || foreignControl.OperationStatusCounts()["pending"] != 0 {
			t.Fatal("overview counts crossed installation boundary")
		}
	})
	t.Run("overview_current_promotion_binding_and_availability_loss", func(t *testing.T) {
		empty, e := ownControlReader.ReadOverviewPromotionControl(ownScope.Context())
		mysqlMust(t, e)
		if _, present := empty.CurrentPromotion(); present {
			t.Fatal("empty promotion table invented a baseline")
		}
		backupID := seedBackup(own, "91")
		drillID := "sdr_000000d1-0000-4000-8000-000000000091"
		evidenceID := "sev_000000d1-0000-4000-8000-000000000091"
		promotionID := "spm_000000d1-0000-4000-8000-000000000091"
		_, e = db.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='succeeded',can_cancel=FALSE,
		started_at=created_at,finished_at=UTC_TIMESTAMP(6),task_purpose='acceptance',
		requested_parts='mysql,redis,object_storage,workspace,deployment_resources,secret_bundle',
		artifact_state='committed',artifact_usable=TRUE,artifact_unusable_reason='none',artifact_committed_at=UTC_TIMESTAMP(6),
		artifact_uri='fixture-artifact',artifact_immutable_version='v1',artifact_checksum=REPEAT('a',64),
		manifest_uri='fixture-manifest',manifest_immutable_version='v1',manifest_checksum=REPEAT('a',64),
		index_uri='fixture-index',index_immutable_version='v1',index_checksum=REPEAT('a',64),
		marker_uri='fixture-marker',marker_immutable_version='v1',marker_checksum=REPEAT('a',64),
		acceptance_uri='fixture-acceptance',acceptance_immutable_version='v1',acceptance_checksum=REPEAT('b',64),
		artifact_registration_id='registration-fixture-91',artifact_registration_hash=REPEAT('c',64),consistency='strong',
		acceptance_eligible=TRUE,eligibility_reason_codes='eligible',eligibility_decision_hash=REPEAT('d',64),
		eligibility_decided_at=UTC_TIMESTAMP(6),row_version=3,prune_guard_version=2 WHERE origin_installation_id=? AND public_id=?`, own, backupID)
		mysqlMust(t, e)
		_, e = db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence
		(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,
		content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at)
		VALUES(?,'drill',?,'verifier_report','inline','{}',SHA2('{}',256),2,'application/json','none','public','healthy',UTC_TIMESTAMP(6)+INTERVAL 1 HOUR)`, evidenceID, drillID)
		mysqlMust(t, e)
		_, e = db.ExecContext(ctx, `INSERT INTO system_backup_v2_restore_drills
		(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,
		config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,status,can_cancel,deadline_at,started_at,finished_at,
		source_artifact_type,source_public_id,source_manifest_checksum,source_acceptance_checksum,target_profile,restore_target_config_ref,restore_target_config_hash,
		cleanup_policy,cleanup_status,verifier_aggregate_status,verifier_passed,verifier_report_evidence_public_id,verifier_report_evidence_sha256,
		consistency,acceptance_eligible,eligibility_reason_codes,eligibility_decision_hash,eligibility_decided_at)
		VALUES(?,?,'admin',?,'DFullBaseline','d-full-baseline-drill-91',REPEAT('a',64),'d-full-baseline-drill-91',
		1,'{}',2,SHA2('{}',256),'succeeded',FALSE,UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),
		'backup',?,REPEAT('a',64),REPEAT('b',64),'single-node','fixture-target',REPEAT('c',64),
		'delete-on-success','succeeded','passed',1,?,SHA2('{}',256),'strong',TRUE,'eligible',REPEAT('d',64),UTC_TIMESTAMP(6))`,
			drillID, own, strconv.FormatInt(userID, 10), backupID, evidenceID)
		mysqlMust(t, e)
		_, e = db.ExecContext(ctx, `INSERT INTO system_backup_v2_promotions
		(public_id,origin_installation_id,matrix_key,backup_public_id,drill_public_id,manifest_checksum,acceptance_checksum,
		artifact_registration_id,artifact_registration_hash,eligibility_decision_hash,drill_evidence_public_id,drill_evidence_hash,
		source_backup_row_version,source_drill_row_version,source_prune_guard_version,config_version,
		creation_artifact_health,creation_artifact_access_health,creation_kek_health,creation_signature_health,
		creation_catalog_health,creation_evidence_health,creation_attestation_health,creation_health_snapshot_sha256,creation_health_observed_at,created_by)
		VALUES(?,?,'k8s-single-node',?,?,REPEAT('a',64),REPEAT('b',64),'registration-fixture-91',REPEAT('c',64),REPEAT('d',64),?,SHA2('{}',256),
		3,1,2,1,'healthy','healthy','healthy','healthy','healthy','healthy','healthy',REPEAT('f',64),UTC_TIMESTAMP(6),?)`,
			promotionID, own, backupID, drillID, evidenceID, strconv.FormatInt(userID, 10))
		mysqlMust(t, e)
		bound, e := ownControlReader.ReadOverviewPromotionControl(ownScope.Context())
		mysqlMust(t, e)
		p, present := bound.CurrentPromotion()
		if !present || p.PublicID != promotionID || p.Backup.PublicID != backupID || p.Drill.SourcePublicID != backupID || p.Evidence.OwnerPublicID != drillID || p.Evidence.ContentSHA256 != registrationHash("{}") {
			t.Fatal("promotion source/evidence binding lost", p, present)
		}
		cross, e := foreignControlReader.ReadOverviewPromotionControl(foreignScope.Context())
		mysqlMust(t, e)
		if _, present := cross.CurrentPromotion(); present {
			t.Fatal("promotion crossed installation boundary")
		}
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET artifact_state='corrupt',artifact_usable=FALSE,artifact_unusable_reason='corrupt',row_version=row_version+1 WHERE public_id=?", backupID)
		mysqlMust(t, e)
		changed, e := ownControlReader.ReadOverviewPromotionControl(ownScope.Context())
		mysqlMust(t, e)
		p, present = changed.CurrentPromotion()
		if !present || p.Backup.ArtifactUsable || p.Backup.ArtifactState != "corrupt" || p.SourceBackupRowVersion != 3 || p.Backup.RowVersion != 4 || p.CreationHealth[0] != "healthy" {
			t.Fatal("current availability erased or rewrote creation baseline", p, present)
		}
	})
	tx, err := db.BeginTx(ownScope.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	mysqlMust(t, err)
	defer tx.Rollback()
	_, err = ownScope.AuthorizeRead(ownScope.Context(), tx)
	mysqlMust(t, err)
	revokeCtx, stopRevoke := context.WithTimeout(ctx, 5*time.Second)
	defer stopRevoke()
	revoked := make(chan error, 1)
	go func() {
		_, e := db.ExecContext(revokeCtx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", own, registrationHash(token))
		revoked <- e
	}()
	select {
	case e := <-revoked:
		t.Fatal("revocation bypassed the held full-schema read lock", e)
	case <-time.After(200 * time.Millisecond):
	}
	mysqlMust(t, ownScope.RecheckRead(ownScope.Context(), tx, own))
	mysqlMust(t, tx.Commit())
	select {
	case e := <-revoked:
		mysqlMust(t, e)
	case <-revokeCtx.Done():
		t.Fatal("revocation did not finish after read commit")
	}
	if _, err := ownService.ListTaskDTO(ownScope.Context(), systembackupread.BackupTask, "", 2, ""); !errors.Is(err, ErrRegistrationPermission) {
		t.Fatalf("revoked session retained task read: %v", err)
	}
	if _, err := ownService.ListOperationDTO(ownScope.Context(), 2, ""); !errors.Is(err, ErrRegistrationPermission) {
		t.Fatalf("revoked session retained operation read: %v", err)
	}
	if control, e := ownControlReader.ReadOverviewControl(ownScope.Context()); !errors.Is(e, ErrRegistrationPermission) || control.InstallationState().InstallationID != "" {
		t.Fatalf("revoked session retained overview control read: %v", e)
	}
	if execution, e := ownControlReader.ReadTaskExecution(ownScope.Context(), systembackupread.BackupTask, first); !errors.Is(e, ErrRegistrationPermission) || execution.Task().PublicID != "" || len(execution.Attempts()) != 0 || len(execution.JobObservations()) != 0 {
		t.Fatalf("revoked session retained task execution read: %v", e)
	}
	if detail, e := ownControlReader.ReadTaskDetailControl(ownScope.Context(), systembackupread.BackupTask, first); !errors.Is(e, ErrRegistrationPermission) || detail.Execution().Task().PublicID != "" {
		t.Fatalf("revoked session retained detail control read: %v", e)
	}
	if events, e := ownService.ListTaskEventsDTO(ownScope.Context(), systembackupread.BackupTask, first, 2, ""); !errors.Is(e, ErrRegistrationPermission) || events.InstallationID != "" || events.Resource.Items != nil {
		t.Fatalf("revoked session retained public event read: %v", e)
	}
	if promotion, e := ownControlReader.ReadOverviewPromotionControl(ownScope.Context()); !errors.Is(e, ErrRegistrationPermission) || promotion.Control().InstallationState().InstallationID != "" {
		t.Fatalf("revoked session retained promotion control read: %v", e)
	}
	t.Log("PASS full 066/067/080 schema, real rows, pagination, cross-install cursor, revocation lock")
}
