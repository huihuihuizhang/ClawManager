package systembackupcontroller

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
)

func executionCancelRequested(ctx context.Context, tx *sql.Tx, a d.Authority) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status IN ('pending','running') FOR SHARE`, a.InstallationID, a.TaskPublicID).Scan(&count)
	return count > 0, err
}

// Caller holds the original root lock and has already established actual
// collector exit/source recovery, or proved no source action was dispatched.
func finishExecutionCancellation(ctx context.Context, tx *sql.Tx, a d.Authority) error {
	_, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_operations SET status='succeeded',http_status=202,started_at=COALESCE(started_at,UTC_TIMESTAMP(6)),finished_at=UTC_TIMESTAMP(6),claim_owner=NULL,claim_expires_at=NULL,next_reconcile_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status IN ('pending','running')`, a.InstallationID, a.TaskPublicID)
	return err
}
