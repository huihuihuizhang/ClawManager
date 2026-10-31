package systembackupcontroller

import (
	"context"
	"database/sql"

	d "clawreef/internal/systembackupdispatch"
)

// recheckHeldCapture is used ONLY after snapshot acquired all original locks
// in gate-before-business order. It rereads the same current facts in one SQL
// round trip; it is not an initial admission, authority cache or grant. The
// owner's current grant callback and SQL-clock floor remain in RecheckAfter.
func (s SQLExecutionAuthority) recheckHeldCapture(ctx context.Context, tx *sql.Tx, a d.Authority, first executionSnapshot) (executionSnapshot, error) {
	if !first.heldCapture || s.ApplicationScope == "" || a.TaskType != "backup" || a.Phase != "capture" || a.MaintenanceFencingToken == 0 {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	query := `SELECT UTC_TIMESTAMP(6),(
 BINARY e.engine=BINARY 'v2' AND BINARY g.phase=BINARY 'held' AND BINARY g.owner=BINARY ? AND g.generation=? AND g.fencing_token=c.held_token AND c.gate_generation=? AND c.held_token IS NOT NULL
AND BINARY m.gate_state=BINARY 'held' AND BINARY m.lock_owner=BINARY ? AND m.fencing_token=? AND m.row_version=? AND m.lease_expires_at=? AND m.absolute_hold_deadline_at=?
AND BINARY i.schema_version=BINARY 'system-backup-installation-state.v1' AND i.row_version=? AND i.active_config_version>0 AND BINARY active.schema_version=BINARY 'system-backup-config.v1' AND active.enabled=TRUE
AND BINARY b.schema_version=BINARY 'system-backup-task.v1' AND BINARY b.task_type=BINARY ? AND BINARY b.request_id=BINARY ? AND BINARY b.status=BINARY 'capturing' AND BINARY b.controller_owner=BINARY ? AND b.row_version=?
AND b.controller_lease_expires_at=? AND b.deadline_at=? AND b.config_version=? AND BINARY b.config_snapshot_sha256=BINARY ? AND b.config_snapshot_size_bytes=? AND BINARY b.config_snapshot_json=BINARY ?
AND BINARY original.canonical_config_json=BINARY b.config_snapshot_json AND BINARY b.maintenance_lock_owner=BINARY ? AND b.maintenance_fencing_token=?
AND BINARY t.status=BINARY 'running' AND t.row_version=? AND (SELECT attempt_no FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=b.public_id AND phase='capture' ORDER BY attempt_no DESC LIMIT 1 FOR SHARE)=?
AND NOT EXISTS(SELECT 1 FROM system_backup_v2_operations WHERE origin_installation_id=b.origin_installation_id AND target_type='backup' AND target_public_id=b.public_id AND operation_type='cancel' AND status IN ('pending','running') FOR SHARE)
AND UTC_TIMESTAMP(6)<b.controller_lease_expires_at AND UTC_TIMESTAMP(6)<b.deadline_at AND UTC_TIMESTAMP(6)<m.lease_expires_at AND UTC_TIMESTAMP(6)<m.absolute_hold_deadline_at)
FROM system_backup_gate g
JOIN system_backup_v2_engine_bindings e ON e.scope='installation'
JOIN system_backup_v2_runtime_captures c ON c.task_public_id=? AND c.application_scope=g.scope
JOIN system_backup_v2_maintenance_locks m ON m.origin_installation_id=? AND m.scope=? AND m.lock_name='system_backup_capture_gate'
JOIN system_backup_v2_installation_state i ON i.origin_installation_id=m.origin_installation_id
JOIN system_backup_v2_configs active ON active.origin_installation_id=i.origin_installation_id AND active.version=i.active_config_version
JOIN system_backup_v2_backups b ON b.origin_installation_id=i.origin_installation_id AND b.public_id=c.task_public_id
JOIN system_backup_v2_configs original ON original.origin_installation_id=b.origin_installation_id AND original.version=b.config_version AND original.config_sha256=b.config_snapshot_sha256 AND original.config_size_bytes=b.config_snapshot_size_bytes
JOIN system_backup_v2_attempts t ON t.target_type='backup' AND t.target_public_id=b.public_id AND t.attempt_no=? AND t.phase='capture'
WHERE g.scope=? AND BINARY b.origin_installation_id=BINARY ? FOR SHARE`
	v := first
	var valid bool
	err := tx.QueryRowContext(ctx, query, a.TaskPublicID, a.MaintenanceFencingToken, a.MaintenanceFencingToken, a.MaintenanceOwner, a.MaintenanceFencingToken, first.gateVersion, first.gateUntil, first.holdUntil, first.installationVersion, a.TaskType, a.RequestID, a.ClaimOwner, a.ClaimRowVersion, first.claimUntil, a.DeadlineAt, a.ConfigVersion, a.ConfigSHA256, len(first.config), first.config, a.MaintenanceOwner, a.MaintenanceFencingToken, first.attemptVersion, a.AttemptNo, a.TaskPublicID, a.InstallationID, CaptureGateScope, a.AttemptNo, s.ApplicationScope, a.InstallationID).Scan(&v.now, &valid)
	if err != nil || !valid {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	// A lock wait or delayed result delivery may cross an original expiry.
	// MySQL's UTC_TIMESTAMP above belongs to the start of that statement;
	// sample again AFTER the complete current facts have actually been read.
	factsAt := v.now
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&v.now) != nil || v.now.Before(factsAt) || v.now.Before(first.now) ||
		!v.now.Before(first.claimUntil) || !v.now.Before(a.DeadlineAt) || !v.now.Before(first.gateUntil) || !v.now.Before(first.holdUntil) {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	return v, nil
}
