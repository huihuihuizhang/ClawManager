package systembackupexecution

import (
	"context"
	"database/sql"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Locator DATA only. The following same-TX Gate.Bind must acquire locks in
// its original gate-before-task order and completely recheck these facts.
// Locking the task here would invert that order against heartbeat/key checks.
const originalCaptureAuthorityLookupSQL = `SELECT controller_owner,row_version,request_id,config_version,config_snapshot_sha256,deadline_at,maintenance_fencing_token FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`

func readOriginalCaptureAuthorityLookup(ctx context.Context, tx *sql.Tx, authority *d.Authority) error {
	if tx == nil || authority == nil {
		return c.ErrExecutionAuthority
	}
	return tx.QueryRowContext(ctx, originalCaptureAuthorityLookupSQL, authority.InstallationID, authority.TaskPublicID).Scan(&authority.ClaimOwner, &authority.ClaimRowVersion, &authority.RequestID, &authority.ConfigVersion, &authority.ConfigSHA256, &authority.DeadlineAt, &authority.MaintenanceFencingToken)
}
