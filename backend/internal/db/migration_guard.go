package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"clawreef/internal/migrationcoord"
)

// acquireMigrationLocks keeps both historical protocols on one connection.
// Ordering is always the database-specific legacy lock, then the capture lock.
func acquireMigrationLocks(ctx context.Context, conn *sql.Conn) (func() error, error) {
	var legacy string
	if err := conn.QueryRowContext(ctx, "SELECT CONCAT('cm:migrate:',MD5(DATABASE()))").Scan(&legacy); err != nil {
		return nil, err
	}
	var held []string
	release := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var result error
		for i := len(held) - 1; i >= 0; i-- {
			var ok sql.NullInt64
			if err := conn.QueryRowContext(cleanup, "SELECT RELEASE_LOCK(?)", held[i]).Scan(&ok); err != nil || !ok.Valid || ok.Int64 != 1 {
				result = errors.Join(result, errors.New("migration lock release unconfirmed"))
			}
		}
		if result != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		return result
	}
	for _, name := range []string{legacy, migrationcoord.LockName} {
		var ok sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,30)", name).Scan(&ok); err != nil || !ok.Valid || ok.Int64 != 1 {
			_ = release()
			// A canceled GET_LOCK can have reached the server even when its
			// result was lost. Never return that physical connection to a pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			return nil, errors.New("migration and capture exclusion unavailable")
		}
		held = append(held, name)
	}
	return release, nil
}

// Called with both connection-owned locks before each new DDL file. Tables
// may not exist yet during fresh install, so readiness is checked per table.
func assertBackupCaptureIdle(ctx context.Context, conn *sql.Conn) error {
	checks := []struct{ table, predicate string }{
		{"system_backup_gate", "phase<>'idle'"},
		{"system_backup_gate_admissions", "owner IS NOT NULL"},
		{"system_backup_mutation_leases", "released_at IS NULL"},
		{"system_backup_v2_maintenance_locks", "gate_state<>'idle'"},
		// V2 relinquishes a mutation by deleting its row. Expiry alone is not
		// evidence that a remote writer exited.
		{"system_backup_v2_maintenance_mutation_leases", "1=1"},
	}
	for _, check := range checks {
		var present int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", check.table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		var active int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+check.table+"` WHERE "+check.predicate).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("database migration blocked by active backup coordination")
		}
	}
	return nil
}
