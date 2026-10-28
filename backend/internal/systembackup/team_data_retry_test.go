package systembackup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func failRetryFixture(t *testing.T, s *TeamDataService, operation, source string) TeamDataJob {
	t.Helper()
	id, _ := RandomID("sdr_")
	if operation == "backup" {
		id, _ = RandomID("sbk_")
	}
	_, e := s.db.Exec("INSERT INTO system_team_data_backup_jobs(public_id,operation,source_backup_id,actor_id,idempotency_key,request_hash,config_hash,status,phase) VALUES(?,?,NULLIF(?,''),1,?,?,?,'failed','capture_mysql')", id, operation, source, "original-"+id, strings.Repeat("a", 64), s.configHash)
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.Get(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestTeamDataRetryCreatesOneAttemptAndReplaysAfterDisable(t *testing.T) {
	s := teamDataJobFixture(t)
	ctx := context.Background()
	original := failRetryFixture(t, s, "backup", "")
	next, e := s.Retry(ctx, 1, original.ID, "retry-backup-original-key")
	if e != nil || next.ID == original.ID || next.Operation != "backup" || teamDataRetry(next).Of != original.ID {
		t.Fatal("retry did not retain original identity", e)
	}
	s.cfg.Disabled = true
	replay, e := s.Retry(ctx, 1, original.ID, "retry-backup-original-key")
	if e != nil || replay.ID != next.ID {
		t.Fatal("accepted retry lost after disabling", e)
	}
	if _, e = s.Retry(ctx, 1, original.ID, "retry-backup-other-key"); e == nil || e.Error() != "feature_disabled" {
		t.Fatal("disabled creates new retry", e)
	}
	s.cfg.Disabled = false
	_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='canceled' WHERE public_id=?", next.ID)
	if e != nil {
		t.Fatal(e)
	}
	other := failRetryFixture(t, s, "backup", "")
	if _, e = s.Retry(ctx, 1, other.ID, "retry-backup-original-key"); e == nil || e.Error() != "idempotency_conflict" {
		t.Fatal("retry key reassigned to another original", e)
	}
	old, e := s.Get(ctx, original.ID)
	if e != nil || old.Status != "failed" {
		t.Fatal("original history overwritten", e)
	}
}

func TestTeamDataRestoreRetryQueuesOwnedCleanupBeforeRestore(t *testing.T) {
	s := teamDataJobFixture(t)
	ctx := context.Background()
	backup, _ := RandomID("sbk_")
	original := failRetryFixture(t, s, "restore", backup)
	cleanup, e := s.Retry(ctx, 1, original.ID, "retry-restore-key-0001")
	if e != nil || cleanup.Operation != "cleanup" || cleanup.SourceID != original.ID || teamDataRetry(cleanup).Next != "restore" {
		t.Fatal("restore started before owned cleanup", e)
	}
	// Simulate only the completed cleanup metadata to exercise the real durable
	// continuation; no resource is claimed restored by this fixture.
	_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='cleaned' WHERE public_id=?", original.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='succeeded',phase='retry_pending' WHERE public_id=?", cleanup.ID)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.Retry(ctx, 1, original.ID, "retry-restore-key-0001")
	if e != nil || replay.ID != cleanup.ID {
		t.Fatal("status transition changed accepted retry", e)
	}
	if _, e = s.Retry(ctx, 1, original.ID, "retry-restore-second-click"); e == nil || e.Error() != "conflict_active_job" {
		t.Fatal("second click competed with automatic continuation", e)
	}
	if e = s.continueQueuedRetry(ctx); e != nil {
		t.Fatal(e)
	}
	blocked, e := s.Get(ctx, cleanup.ID)
	if e != nil || blocked.Phase != "retry_blocked" || blocked.Status != "succeeded" {
		t.Fatal("missing artifact silently queued or hung retry", e, blocked.Phase)
	}
	var restores int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM system_team_data_backup_jobs WHERE operation='restore'").Scan(&restores); e != nil || restores != 1 {
		t.Fatal("unavailable artifact created a second restore", e)
	}
}

func TestTeamDataRetryResolvesPublishedBackupWithoutRecapture(t *testing.T) {
	s, a, _ := teamDataManagementFixture(t)
	jobs := teamDataJobFixture(t)
	s.db, s.configHash, s.owner = jobs.db, jobs.configHash, jobs.owner
	ctx := context.Background()
	id := a.Manifest.Payload.BackupID
	_, e := s.db.Exec("INSERT INTO system_team_data_backup_jobs(public_id,operation,actor_id,idempotency_key,request_hash,config_hash,status,phase) VALUES(?,'backup',1,'publication-reply-lost',?,?,'failed','publishing')", id, s.configHash, s.configHash)
	if e != nil {
		t.Fatal(e)
	}
	check, e := s.Retry(ctx, 1, id, "resolve-original-publication")
	if e != nil || check.Operation != "verify" || check.SourceID != id {
		t.Fatal("published backup was recaptured", e)
	}
	replay, e := s.Retry(ctx, 1, id, "resolve-original-publication")
	if e != nil || replay.ID != check.ID {
		t.Fatal("verification retry duplicated", e)
	}
}

func TestTeamDataCleanedRestoreContinuationUsesOneDurableChild(t *testing.T) {
	s, a, _ := teamDataManagementFixture(t)
	jobs := teamDataJobFixture(t)
	s.db, s.configHash, s.owner = jobs.db, jobs.configHash, jobs.owner
	ctx := context.Background()
	original := failRetryFixture(t, s, "restore", a.Manifest.Payload.BackupID)
	cleanup, e := s.Retry(ctx, 1, original.ID, "restart-owned-restore")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='cleaned' WHERE public_id=?", original.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='succeeded',phase='retry_pending' WHERE public_id=?", cleanup.ID)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = s.continueQueuedRetry(ctx); e != nil {
			t.Fatal(e)
		}
		// Lost projection acknowledgement: exact original child key must be reused.
		if i == 0 {
			_, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET phase='retry_pending' WHERE public_id=?", cleanup.ID)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	final, e := s.Get(ctx, cleanup.ID)
	if e != nil || teamDataRetry(final).Followup == "" {
		t.Fatal("queued retry never linked its child", e)
	}
	child, e := s.Get(ctx, teamDataRetry(final).Followup)
	if e != nil || child.Operation != "restore" || child.SourceID != original.SourceID {
		t.Fatal("wrong restore continuation", e)
	}
	var count int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM system_team_data_backup_jobs WHERE idempotency_key=?", "retry-followup-"+cleanup.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate restore child", e)
	}
}

func TestTeamDataRestartRetainsPublicationBoundaryForRetry(t *testing.T) {
	s, a, _ := teamDataManagementFixture(t)
	jobs := teamDataJobFixture(t)
	s.db, s.configHash, s.owner = jobs.db, jobs.configHash, jobs.owner
	ctx := context.Background()
	id := a.Manifest.Payload.BackupID
	_, e := s.db.Exec("INSERT INTO system_team_data_backup_jobs(public_id,operation,actor_id,idempotency_key,request_hash,config_hash,status,phase,owner_id) VALUES(?,'backup',1,'restart-publication-original',?,?,'running','publishing','dead-process')", id, s.configHash, s.configHash)
	if e != nil {
		t.Fatal(e)
	}
	run, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	_ = s.runOwned(run)
	stop()
	old, e := s.Get(ctx, id)
	if e != nil || old.Phase != "interrupted" {
		t.Fatal(e, old.Phase)
	}
	var report TeamDataReport
	if json.Unmarshal(old.Report, &report) != nil || report.InterruptedPhase != "publishing" {
		t.Fatal("lost uncertain publication boundary")
	}
	next, e := s.Retry(ctx, 1, id, "retry-interrupted-publication")
	if e != nil || next.Operation != "verify" || next.SourceID != id {
		t.Fatal("restarted publication recaptured instead of checking original", e)
	}
}

func TestTeamDataCanceledCleanupDoesNotStartAnotherRestore(t *testing.T) {
	s := teamDataJobFixture(t)
	s.cfg.DeadlineSeconds = 60
	ctx := context.Background()
	backup, _ := RandomID("sbk_")
	original := failRetryFixture(t, s, "restore", backup)
	cleanup, e := s.Retry(ctx, 1, original.ID, "cancel-restore-retry-key")
	if e != nil {
		t.Fatal(e)
	}
	// An already-cleaned original needs no physical deletion. Exercise the real
	// executor completion/cancel race without pretending to provision resources.
	if _, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='cleaned' WHERE public_id=?", original.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='running',owner_id=? WHERE public_id=?", s.owner, cleanup.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Cancel(ctx, cleanup.ID); e != nil {
		t.Fatal(e)
	}
	cleanup, e = s.Get(ctx, cleanup.ID)
	if e != nil {
		t.Fatal(e)
	}
	conn, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	s.execute(ctx, conn, cleanup)
	actual, e := s.Get(ctx, cleanup.ID)
	if e != nil || actual.Phase != "retry_stopped" || actual.Status != "succeeded" {
		t.Fatal("cancel lost to automatic continuation", e, actual.Phase, actual.Status)
	}
	if e = s.continueQueuedRetry(ctx); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM system_team_data_backup_jobs WHERE status='pending'").Scan(&count); e != nil || count != 0 {
		t.Fatal("canceled retry queued work", e, count)
	}
}

func TestTeamDataContinuationDeadlineReleasesWaitingWithoutCreatingWork(t *testing.T) {
	s := teamDataJobFixture(t)
	s.cfg.DeadlineSeconds = 60
	ctx := context.Background()
	backup, _ := RandomID("sbk_")
	original := failRetryFixture(t, s, "restore", backup)
	cleanup, e := s.Retry(ctx, 1, original.ID, "bounded-restore-retry")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='cleaned' WHERE public_id=?", original.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE system_team_data_backup_jobs SET status='succeeded',phase='retry_pending',finished_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 2 MINUTE) WHERE public_id=?", cleanup.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.continueQueuedRetry(ctx); e != nil {
		t.Fatal(e)
	}
	actual, e := s.Get(ctx, cleanup.ID)
	if e != nil || actual.Phase != "retry_blocked" || actual.Error != "retry_deadline_exceeded" {
		t.Fatal("continuation waits indefinitely", e, actual.Phase, actual.Error)
	}
	if _, e = s.Create(ctx, 1, "unrelated-backup-after-retry-timeout", "backup", ""); e != nil {
		t.Fatal("failed continuation blocks other backups", e)
	}
}
