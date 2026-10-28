package systembackupcontroller

import (
	"context"
	"database/sql"

	d "clawreef/internal/systembackupdispatch"
)

// FinishCapture consumes physical stop/resume facts, never just Runner success.
// Captured is NOT published or independently recoverable: success stops at
// validating for the separately authorized M3 finalizer.
func (g SQLCaptureGate) FinishCapture(ctx context.Context, w ExecutionWork, out ExecutionOutcome) error {
	if !g.ready() {
		return d.ErrNotReady
	}
	a := w.Input.Authority
	if w.Step == ExecutionRecover && out.Err == nil && out.Recovery.CollectorsStopped && out.Recovery.WritersResumed {
		if e := g.FinalizeRecovery(ctx, a); e != nil {
			return e
		}
	}
	tx, e := g.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = g.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	var stopped, resumed sql.NullTime
	if e = tx.QueryRowContext(ctx, "SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=? FOR UPDATE", a.TaskPublicID, a.MaintenanceFencingToken).Scan(&stopped, &resumed); e != nil || !stopped.Valid || !resumed.Valid {
		return ErrExecutionRecoveryRequired
	}
	var old string
	if e = tx.QueryRowContext(ctx, "SELECT status FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE", a.TaskPublicID).Scan(&old); e != nil {
		return e
	}
	if old != "capturing" && old != "canceling" {
		return ErrExecutionAuthority
	}
	status, category, attemptStatus := "validating", "none", "sealed"
	cancelRequested, e := executionCancelRequested(ctx, tx, a)
	if e != nil {
		return e
	}
	var finished any
	if out.Err != nil || w.Step == ExecutionRecover || old == "canceling" || cancelRequested {
		status, category, attemptStatus = "failed", "runner_failed", "failed"
		if old == "canceling" || cancelRequested {
			status, category, attemptStatus = "canceled", "canceled_by_actor", "canceled"
		}
		var now sql.NullTime
		if e = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); e != nil {
			return e
		}
		finished = now.Time
	} else {
		if len(out.Results) == 0 {
			return ErrExecutionRecord
		}
		var digest string
		if tx.QueryRowContext(ctx, "SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE task_public_id=? AND attempt_no=? AND phase=? AND record_kind='capture_result' FOR SHARE", a.TaskPublicID, a.AttemptNo, a.Phase).Scan(&digest) != nil || !executionHash.MatchString(digest) {
			return ErrExecutionRecord
		}
	}
	r, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status=?,failure_category=?,finished_at=?,can_cancel=?,controller_owner=NULL,controller_lease_expires_at=NULL,row_version=row_version+1,next_reconcile_at=NULL WHERE public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6)`, status, category, finished, status == "validating", a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion)
	if ok, z := exactlyOneRow(r); e != nil || z != nil || !ok {
		return ErrClaimLost
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_attempts SET status=?,failure_category=?,started_at=COALESCE(started_at,UTC_TIMESTAMP(6)),finished_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase IN ('capture','secret_capture') AND status IN ('preparing','running')", attemptStatus, category, a.TaskPublicID, a.AttemptNo); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) VALUES(?,'backup',?,'task_status_changed','info',?,'Capture stopped and source business resumed; outcome recorded.',?)", a.InstallationID, a.TaskPublicID, status, a.RequestID); e != nil {
		return e
	}
	if cancelRequested {
		if e = finishExecutionCancellation(ctx, tx, a); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}
