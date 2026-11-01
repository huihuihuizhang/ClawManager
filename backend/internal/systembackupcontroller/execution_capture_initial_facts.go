package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"

	d "clawreef/internal/systembackupdispatch"
)

// snapshot has ALREADY acquired the original engine/application/runtime,
// maintenance, installation, active-config and task locks in their original
// order, checked task/config bytes and selected only the held capture branch.
// Combine the remaining shared metadata reads without omitting any fact.
func (s SQLExecutionAuthority) completeHeldSnapshot(ctx context.Context, tx *sql.Tx, a d.Authority, v executionSnapshot, fence uint64, report func(ExecutionBindDiagnostic)) (executionSnapshot, error) {
	var original []byte
	var latest, taskFence uint64
	var canceled int
	var taskOwner string
	query := `SELECT original.canonical_config_json,t.status,t.row_version,
(SELECT attempt_no FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=b.public_id AND phase='capture' ORDER BY attempt_no DESC LIMIT 1 FOR SHARE),
(SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=b.origin_installation_id AND target_type='backup' AND target_public_id=b.public_id AND operation_type='cancel' AND status IN ('pending','running') FOR SHARE),
b.maintenance_lock_owner,b.maintenance_fencing_token
FROM system_backup_v2_configs original
JOIN system_backup_v2_backups b ON b.origin_installation_id=original.origin_installation_id AND b.public_id=?
JOIN system_backup_v2_attempts t ON t.target_type='backup' AND t.target_public_id=b.public_id AND t.attempt_no=? AND t.phase='capture'
WHERE original.origin_installation_id=? AND original.version=? AND original.config_sha256=? AND original.config_size_bytes=? FOR SHARE`
	err := tx.QueryRowContext(ctx, query, a.TaskPublicID, a.AttemptNo, a.InstallationID, a.ConfigVersion, a.ConfigSHA256, len(v.config)).Scan(&original, &v.attemptStatus, &v.attemptVersion, &latest, &canceled, &taskOwner, &taskFence)
	if err != nil || !bytes.Equal(original, v.config) || latest != a.AttemptNo || v.attemptStatus != "running" || v.attemptVersion == 0 || canceled != 0 || v.gateState != "held" || v.gateOwner != a.MaintenanceOwner || fence != a.MaintenanceFencingToken || taskOwner != a.MaintenanceOwner || taskFence != fence || fence == 0 {
		reportExecutionBindDiagnostic(report, "bind-snapshot-held-original-facts", err)
		return executionSnapshot{}, ErrExecutionAuthority
	}
	// Statement start time cannot cover delayed delivery or a lock wait.
	err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&v.now)
	if err != nil || v.now.IsZero() || !v.now.Before(v.claimUntil) || !v.now.Before(a.DeadlineAt) || !v.now.Before(v.gateUntil) || !v.now.Before(v.holdUntil) {
		reportExecutionBindClockDiagnostic(report, v, a.DeadlineAt, err)
		return executionSnapshot{}, ErrExecutionAuthority
	}
	return v, nil
}
