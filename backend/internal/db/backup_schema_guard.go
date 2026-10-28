package db

import (
	"context"
	"database/sql"
	"errors"
)

var ErrBackupControlImportRequired = errors.New("unversioned backup control schema requires explicit isolated import")

// The backup-only fork historically used the same table name for a different
// schema. IF NOT EXISTS would let the wrong application continue against it.
// Detect this before any migration or business process can write to that DB.
func checkBackupControlSchema(ctx context.Context, pool interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var legacy, other, columns int
	if err := pool.QueryRowContext(ctx, `SELECT
COALESCE(SUM(COLUMN_NAME='singleton_id'),0),COALESCE(SUM(COLUMN_NAME='id'),0),COUNT(*)
FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_installation_state'`).Scan(&legacy, &other, &columns); err != nil {
		return err
	}
	if other != 0 || (columns != 0 && legacy != 1) {
		return ErrBackupControlImportRequired
	}
	return nil
}
