package systembackupsecurity

import (
	"context"
	"database/sql"
	"math"
	"time"
)

const capacityAllocationQuery = `SELECT TABLE_NAME,TABLE_TYPE,DATA_LENGTH,INDEX_LENGTH FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND (LEFT(TABLE_NAME,14)='system_backup_' OR LEFT(TABLE_NAME,15)='system_restore_' OR TABLE_NAME='system_backup_v2_backups' OR TABLE_NAME='audit_logs')`

// Start the original freshness window before measuring either physical space
// or table allocation. Slow collection must not renew the age of old space.
// The caller has already pinned SQL identity, grants and the real data mount.
func measureRegistrationCapacity(ctx context.Context, db *sql.Conn, expected CapacityCollectorConfig, available func() (int64, error)) (CapacityReport, error) {
	fail := func() (CapacityReport, error) { return CapacityReport{}, ErrRegistrationUnavailable }
	if ctx == nil || ctx.Err() != nil || db == nil || available == nil || expected.Validate() != nil {
		return fail()
	}
	r := CapacityReport{ServerUUID: expected.ServerUUID, Database: expected.Database}
	if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&r.ObservedAt) != nil || r.ObservedAt.IsZero() {
		return fail()
	}
	var err error
	r.AvailableBytes, err = available()
	if err != nil || r.AvailableBytes < 0 {
		return fail()
	}
	rows, err := db.QueryContext(ctx, capacityAllocationQuery)
	if err != nil {
		return fail()
	}
	defer rows.Close()
	remaining := make(map[string]bool, len(expected.Tables))
	for _, name := range expected.Tables {
		remaining[name] = true
	}
	for rows.Next() {
		var name, kind string
		var data, indexes int64
		if rows.Scan(&name, &kind, &data, &indexes) != nil || !remaining[name] || kind != "BASE TABLE" || data < 0 || indexes < 0 || data > math.MaxInt64-indexes || r.AllocatedBytes > math.MaxInt64-data-indexes {
			return fail()
		}
		delete(remaining, name)
		r.AllocatedBytes += data + indexes
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil || len(remaining) != 0 {
		return fail()
	}
	var finished time.Time
	if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&finished) != nil || ctx.Err() != nil || finished.Before(r.ObservedAt) || !finished.Before(r.ObservedAt.Add(5*time.Second)) {
		return fail()
	}
	return r, nil
}
