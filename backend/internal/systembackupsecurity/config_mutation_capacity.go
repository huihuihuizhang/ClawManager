package systembackupsecurity

import (
	"context"
	"database/sql"
	"path/filepath"
	"time"
)

// A reservation is transaction-bound. Recheck performs only local/SQL work;
// ValidUntil is frozen by the caller and checked again after all final callbacks.
type ConfigMutationCapacityReservation interface {
	Recheck(context.Context, *sql.Tx, time.Time) error
	ValidUntil() time.Time
}

type ConfigMutationCapacity struct {
	database        DatabaseIdentity
	reportFile      string
	largeSmokeBytes int64
}

// largeSmokeBytes is the measured control-metadata footprint of the reviewed
// large-smoke run, supplied by deployment, never a request field or estimate.
// Missing evidence cannot be replaced with zero. No report/ledger is generated.
func NewConfigMutationCapacity(database DatabaseIdentity, reportFile string, largeSmokeBytes int64) (*ConfigMutationCapacity, error) {
	if !database.valid() || !filepath.IsAbs(reportFile) || filepath.Clean(reportFile) != reportFile || largeSmokeBytes < 1 || largeSmokeBytes > 1099511627776/2 {
		return nil, ErrRegistrationUnavailable
	}
	return &ConfigMutationCapacity{database, reportFile, largeSmokeBytes}, nil
}

func configMutationSafetyReserve(capacity int64) int64 {
	reserve := (capacity + 19) / 20
	if reserve < 67108864 {
		reserve = 67108864
	}
	return reserve
}
func (c *ConfigMutationCapacity) clock(ctx context.Context, tx *sql.Tx, notBefore time.Time) (time.Time, error) {
	var server, database string
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset) != nil || server != c.database.ServerUUID || database != c.database.Database || now.IsZero() || offset != 0 || now.Before(notBefore) {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return now, nil
}
func (c *ConfigMutationCapacity) Reserve(ctx context.Context, tx *sql.Tx, current, proposed ConfigValues, bytes int, notBefore time.Time) (ConfigMutationCapacityReservation, error) {
	fail := func() (ConfigMutationCapacityReservation, error) { return nil, ErrRegistrationUnavailable }
	if c == nil || ctx == nil || ctx.Err() != nil || tx == nil || notBefore.IsZero() || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 || bytes < 1 || bytes > 1048576 {
		return fail()
	}
	oldCapacity := current.snapshot.numbers["control_metadata_capacity_bytes"]
	capacity := proposed.snapshot.numbers["control_metadata_capacity_bytes"]
	physicalBudget := oldCapacity
	if capacity > physicalBudget {
		physicalBudget = capacity
	}
	if capacity < 2*c.largeSmokeBytes {
		return fail()
	}
	raw, err := boundedFile(c.reportFile, 4096)
	if err != nil {
		return fail()
	}
	report, err := ParseCapacityReport(raw)
	if err != nil || report.ServerUUID != c.database.ServerUUID || report.Database != c.database.Database || report.ObservedAt.IsZero() || report.AllocatedBytes < 0 || report.AvailableBytes < 0 {
		return fail()
	}
	now, err := c.clock(ctx, tx, notBefore)
	until := report.ObservedAt.Add(5 * time.Second)
	if err != nil || report.ObservedAt.After(now) || !now.Before(until) {
		return fail()
	}
	if _, err = tx.ExecContext(ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)", report.ObservedAt.UTC()); err != nil {
		return fail()
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || sample.IsZero() || report.ObservedAt.Before(sample) {
		return fail()
	}
	// The new budget takes effect atomically with this write, allowing an
	// increase to repair an exhausted old soft budget. A decrease must fit the
	// complete measured allocation, monotonic reservations AND safety reserve.
	reserve := configMutationSafetyReserve(capacity)
	cost := int64(bytes) // caller already includes row/index/audit/nonce overhead
	if outstanding < 0 || report.AllocatedBytes >= capacity-reserve || outstanding >= capacity-reserve-report.AllocatedBytes || cost >= capacity-reserve-report.AllocatedBytes-outstanding {
		return fail()
	}
	// Keep the higher old/new physical budget through the transition. Pending
	// reservations also consume physical headroom; a newer sample never resets
	// them or silently assumes delayed table statistics include admitted writes.
	if report.AvailableBytes <= physicalBudget+configMutationSafetyReserve(physicalBudget)+outstanding+cost {
		return fail()
	}
	if !configMutationOne(tx.ExecContext(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", cost, sample, outstanding)) {
		return fail()
	}
	r := &configMutationCapacityReservation{c, tx, report, sample, capacity, physicalBudget, outstanding + cost, until}
	if r.Recheck(ctx, tx, now) != nil {
		return fail()
	}
	return r, nil
}

type configMutationCapacityReservation struct {
	source                    *ConfigMutationCapacity
	tx                        *sql.Tx
	report                    CapacityReport
	sample                    time.Time
	capacity, physical, floor int64
	until                     time.Time
}

func (r *configMutationCapacityReservation) ValidUntil() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.until
}
func (r *configMutationCapacityReservation) Recheck(ctx context.Context, tx *sql.Tx, notBefore time.Time) error {
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil || tx == nil || tx != r.tx || notBefore.IsZero() {
		return ErrRegistrationUnavailable
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || !sample.Equal(r.sample) || outstanding < r.floor || outstanding >= r.capacity-configMutationSafetyReserve(r.capacity)-r.report.AllocatedBytes || r.report.AvailableBytes <= r.physical+configMutationSafetyReserve(r.physical)+outstanding {
		return ErrRegistrationUnavailable
	}
	now, err := r.source.clock(ctx, tx, notBefore)
	if err != nil || !now.Before(r.until) {
		return ErrRegistrationUnavailable
	}
	return nil
}
