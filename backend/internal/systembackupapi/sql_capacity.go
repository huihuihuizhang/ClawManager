package systembackupapi

import (
	"io"
	"os"
	"time"

	security "clawreef/internal/systembackupsecurity"
)

// Reserve with the same monotonic ledger used by registration. Never reset it
// on a fresh sample: delayed table statistics can omit committed admissions.
func (p *preparedSQLTask) reserveCapacity(q TaskWriteSQL, capacity int64, configBytes int) error {
	return reserveControlCapacity(q, p.writer.capacityFile, capacity, int64(configBytes+len(p.writer.raw)+len(p.body))+65536)
}

func reserveControlCapacity(q TaskWriteSQL, reportFile string, capacity, cost int64) error {
	if cost < 65536 || cost > 1<<20 {
		return &Error{"not_ready"}
	}
	f, err := os.Open(reportFile)
	if err != nil {
		return &Error{"not_ready"}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return &Error{"not_ready"}
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return &Error{"not_ready"}
	}
	report, err := security.ParseCapacityReport(raw)
	if err != nil {
		return &Error{"not_ready"}
	}
	var server, database string
	var now time.Time
	if q.QueryRow("SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &now) != nil || report.ServerUUID != server || report.Database != database || report.ObservedAt.After(now) || report.ObservedAt.Before(now.Add(-5*time.Second)) || report.AllocatedBytes < 0 || report.AvailableBytes < 0 || capacity < 1<<30 || capacity > 1<<40 {
		return &Error{"not_ready"}
	}
	reserve := capacity / 20
	if reserve < 64<<20 {
		reserve = 64 << 20
	}
	if report.AvailableBytes < capacity+reserve+cost {
		return &Error{"capacity_exceeded"}
	}
	if _, err = q.Exec("INSERT INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0) ON DUPLICATE KEY UPDATE id=id", report.ObservedAt.UTC()); err != nil {
		return &Error{"not_ready"}
	}
	var sample time.Time
	var outstanding int64
	if q.QueryRow("SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || report.ObservedAt.Before(sample) || outstanding < 0 || outstanding > capacity || report.AllocatedBytes > capacity-outstanding-cost {
		return &Error{"capacity_exceeded"}
	}
	result, err := q.Exec("UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", cost, sample, outstanding)
	if err != nil {
		return &Error{"not_ready"}
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return &Error{"not_ready"}
	}
	return nil
}
