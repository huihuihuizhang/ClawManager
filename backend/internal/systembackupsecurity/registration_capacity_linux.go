//go:build linux

package systembackupsecurity

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"syscall"
)

// collectRegistrationCapacity must run beside MySQL with access to its real
// data volume; auto.cnf must match the live SQL server identity.
func collectRegistrationCapacity(ctx context.Context, db *sql.Conn, expected CapacityCollectorConfig) (CapacityReport, error) {
	var r CapacityReport
	var datadir string
	if db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),@@datadir").Scan(&r.ServerUUID, &r.Database, &datadir) != nil || !filepath.IsAbs(datadir) || r.ServerUUID != expected.ServerUUID || r.Database != expected.Database || filepath.Clean(datadir) != expected.DataDir {
		return r, ErrRegistrationUnavailable
	}
	raw, err := boundedFile(filepath.Join(datadir, "auto.cnf"), 4096)
	if err != nil {
		return r, err
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "server-uuid="+r.ServerUUID {
			found = true
		}
	}
	if !found {
		return r, ErrRegistrationUnavailable
	}
	return measureRegistrationCapacity(ctx, db, expected, func() (int64, error) {
		var stat syscall.Statfs_t
		if syscall.Statfs(datadir, &stat) != nil || stat.Bsize <= 0 || uint64(stat.Bavail) > uint64(1<<62)/uint64(stat.Bsize) {
			return 0, ErrRegistrationUnavailable
		}
		return int64(stat.Bavail) * stat.Bsize, nil
	})
}
