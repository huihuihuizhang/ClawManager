package systembackupsecurity

import (
	"context"
	"database/sql"
	"time"
)

// CapacityReport is produced by a trusted DB-side collector from the actual
// control-table allocation and filesystem containing the MySQL data volume.
// It must be mounted read-only. Unknown physical capacity is never healthy.
type CapacityReport struct {
	ServerUUID     string    `json:"server_uuid"`
	Database       string    `json:"database"`
	ObservedAt     time.Time `json:"observed_at"`
	AllocatedBytes int64     `json:"allocated_bytes"`
	AvailableBytes int64     `json:"available_bytes"`
}
type RegistrationCapacity struct{ ReportFile string }

func (c RegistrationCapacity) Reserve(ctx context.Context, tx *sql.Tx, capacity int64, inline int) error {
	if inline < 0 || inline > 8192 {
		return ErrRegistrationUnavailable
	}
	return c.reserveCost(ctx, tx, capacity, int64(inline)+65536)
}

// ReserveExecutionPayload budgets immutable encrypted records separately from
// small registration metadata, without weakening the original inline bound.
func (c RegistrationCapacity) ReserveExecutionPayload(ctx context.Context, tx *sql.Tx, capacity int64, payload int) error {
	if payload < 1 || payload > (8<<20)+4096 {
		return ErrRegistrationUnavailable
	}
	return c.reserveCost(ctx, tx, capacity, int64(payload)*2+65536)
}

func (c RegistrationCapacity) reserveCost(ctx context.Context, tx *sql.Tx, capacity, cost int64) error {
	raw, err := boundedFile(c.ReportFile, 4096)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	var report CapacityReport
	if err = decodePinnedRegistry(raw, registrationHash(string(raw)), &report); err != nil {
		return err
	}
	var server, database string
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &now) != nil || server != report.ServerUUID || database != report.Database || report.ObservedAt.After(now) || report.ObservedAt.Before(now.Add(-5*time.Second)) || report.AllocatedBytes < 0 || report.AvailableBytes < 0 || capacity < 1073741824 || capacity > 1099511627776 || cost < 65536 {
		return ErrRegistrationUnavailable
	}
	reserve := capacity / 20
	if reserve < 67108864 {
		reserve = 67108864
	}
	// With estimated InnoDB table allocations, reliable physical headroom is
	// required in addition to the soft budget. Include index/row/audit overhead.
	if report.AvailableBytes < capacity+reserve+cost {
		return ErrRegistrationUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)`, report.ObservedAt.UTC())
	if err != nil {
		return ErrRegistrationUnavailable
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil {
		return ErrRegistrationUnavailable
	}
	// Never reset reservations automatically from a newer estimate: delayed
	// information_schema statistics must not erase already-admitted writes.
	if report.ObservedAt.Before(sample) || outstanding < 0 || outstanding > capacity || report.AllocatedBytes > capacity-outstanding-cost {
		return ErrRegistrationUnavailable
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1", cost)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

// ParseCapacityReport is used by the read-only readiness tool as well.
func ParseCapacityReport(raw []byte) (CapacityReport, error) {
	var r CapacityReport
	err := decodePinnedRegistry(raw, registrationHash(string(raw)), &r)
	return r, err
}
