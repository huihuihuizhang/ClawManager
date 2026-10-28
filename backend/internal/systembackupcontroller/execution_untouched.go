package systembackupcontroller

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
)

// FailUntouched closes expired/revoked preparation only after proving that no
// source action could have been sent. Metadata/plan custody is not source IO.
// Unknown legacy actions, a gate acquisition, or ANY dispatched resource keep
// the task protected for the full recovery protocol.
func (g SQLCaptureGate) FailUntouched(ctx context.Context, a d.Authority) error {
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	var status, phase, gateOwner string
	var effects int
	if tx.QueryRowContext(ctx, "SELECT status FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE", a.TaskPublicID).Scan(&status) != nil || (status != "preparing" && status != "ready_for_capture") {
		return ErrExecutionRecoveryRequired
	}
	if tx.QueryRowContext(ctx, "SELECT phase,COALESCE(owner,'') FROM system_backup_gate WHERE scope=? FOR SHARE", g.Authority.ApplicationScope).Scan(&phase, &gateOwner) != nil || phase != "idle" || gateOwner != "" {
		return ErrExecutionRecoveryRequired
	}
	if tx.QueryRowContext(ctx, `SELECT
 (SELECT COUNT(*) FROM system_backup_v2_runtime_captures WHERE task_public_id=?)+
 (SELECT COUNT(*) FROM system_backup_v2_runtime_writers WHERE task_public_id=?)+
 (SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND create_dispatched=TRUE)+
 (SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?)+
 (SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE target_type='backup' AND target_public_id=?)`, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID).Scan(&effects) != nil || effects != 0 {
		return ErrExecutionRecoveryRequired
	}
	r, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='failed',failure_category='not_ready',finished_at=UTC_TIMESTAMP(6),can_cancel=FALSE,controller_owner=NULL,controller_lease_expires_at=NULL,next_reconcile_at=NULL,row_version=row_version+1 WHERE public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6)`, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion)
	if ok, z := exactlyOneRow(r); e != nil || z != nil || !ok {
		return ErrClaimLost
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_attempts SET status='failed',failure_category='not_ready',started_at=COALESCE(started_at,UTC_TIMESTAMP(6)),finished_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND status='preparing'", a.TaskPublicID, a.AttemptNo); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) VALUES(?,'backup',?,'task_status_changed','warning','failed','Preparation stopped before any source action; execution readiness or authority was lost.',?)", a.InstallationID, a.TaskPublicID, a.RequestID); e != nil {
		return e
	}
	var now = a.DeadlineAt
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || g.Recovery.Identity.checkSQLAction(ctx, tx, a, now, "recover") != nil {
		return ErrExecutionAuthority
	}
	return tx.Commit()
}
