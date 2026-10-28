package systembackupcontroller

import (
	"context"
)

// ExecutionFailureReporter records an observed inability to reconcile. It
// grants no source action, stop proof, claim transfer or terminal state.
type ExecutionFailureReporter interface {
	ReportExecutionBlocked(context.Context, ExecutionWork) error
}

// ReportExecutionBlocked runs only after the original runner has returned.
// A current exact claim is required even for this fixed, redacted diagnostic.
// Terminal/new-owner work is never modified; missing SQL still fails closed.
func (s *SQLExecutionWorkStore) ReportExecutionBlocked(ctx context.Context, w ExecutionWork) error {
	a := w.Input.Authority
	if s == nil || s.Queue.DB == nil || ctx == nil || ctx.Err() != nil || a.InstallationID != s.Queue.InstallationID || a.ClaimOwner != s.Queue.Owner || !validExecutionInput(a, s.Queue.InstallationID) || (w.Step != ExecutionCapture && w.Step != ExecutionRecover) {
		return ErrExecutionAuthority
	}
	tx, err := s.Queue.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var engine, status, request string
	if tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR SHARE").Scan(&engine) != nil || engine != "v2" {
		return ErrExecutionAuthority
	}
	err = tx.QueryRowContext(ctx, `SELECT status,request_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) FOR UPDATE`, a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion).Scan(&status, &request)
	if err != nil || request != a.RequestID || (status != "capturing" && status != "acquiring_gate" && status != "canceling") {
		return ErrClaimLost
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_events WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND event_type='diagnostic.d.recovery_blocked'`, a.InstallationID, a.TaskPublicID).Scan(&count) != nil {
		return ErrExecutionRecord
	}
	if count == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,detail_reason,detail_attempt_number,request_id) VALUES(?,'backup',?,'diagnostic.d.recovery_blocked','error',?,'Execution reconciliation is blocked. Original data and resources remain protected until collector exit and source recovery are confirmed. Automatic recovery will check the original operation again.',TRUE,'original_recovery_required',?,?)`, a.InstallationID, a.TaskPublicID, status, a.AttemptNo, request)
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}

var _ ExecutionFailureReporter = (*SQLExecutionWorkStore)(nil)
