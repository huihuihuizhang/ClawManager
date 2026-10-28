package systembackupsecurity

import (
	"context"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// BootstrapCandidateCapacity adapts the original registration capacity report
// to the shared caller-owned bootstrap transaction. It creates neither a report
// nor authorization, and never substitutes unknown physical headroom with zero.
type BootstrapCandidateCapacity struct {
	database   DatabaseIdentity
	reportFile string
}

func NewBootstrapCandidateCapacity(database DatabaseIdentity, reportFile string) (*BootstrapCandidateCapacity, error) {
	if !database.valid() || !filepath.IsAbs(reportFile) || filepath.Clean(reportFile) != reportFile {
		return nil, ErrRegistrationUnavailable
	}
	return &BootstrapCandidateCapacity{database: database, reportFile: reportFile}, nil
}

type PreparedBootstrapCandidateCapacity struct {
	state *bootstrapCandidateCapacityState
}
type bootstrapCandidateCapacityState struct {
	ctx            context.Context
	report         CapacityReport
	reportUsable   bool
	capacity, cost int64
	used           atomic.Bool
}

type BootstrapCandidateCapacityReservation struct {
	state  *bootstrapCandidateCapacityState
	tx     pd.BootstrapSQL
	sample time.Time
	floor  int64
}

func (BootstrapCandidateCapacity) String() string   { return "BootstrapCandidateCapacity" }
func (BootstrapCandidateCapacity) GoString() string { return "BootstrapCandidateCapacity" }
func (BootstrapCandidateCapacity) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (PreparedBootstrapCandidateCapacity) String() string {
	return "PreparedBootstrapCandidateCapacity"
}
func (PreparedBootstrapCandidateCapacity) GoString() string {
	return "PreparedBootstrapCandidateCapacity"
}
func (PreparedBootstrapCandidateCapacity) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (BootstrapCandidateCapacityReservation) String() string {
	return "BootstrapCandidateCapacityReservation"
}
func (BootstrapCandidateCapacityReservation) GoString() string {
	return "BootstrapCandidateCapacityReservation"
}
func (BootstrapCandidateCapacityReservation) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*BootstrapCandidateCapacity) UnmarshalJSON([]byte) error { return ErrRegistrationUnavailable }
func (*PreparedBootstrapCandidateCapacity) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}
func (*BootstrapCandidateCapacityReservation) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}

func sameCandidateCapacityContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	return av.Comparable() && bv.Comparable() && !(av.Kind() == reflect.Pointer && av.IsNil()) && !(bv.Kind() == reflect.Pointer && bv.IsNil()) && a == b
}

// Prepare reads the trusted original report only before transaction locks.
// The original bootstrap admission charges inline=8192 plus 65536 overhead;
// these amounts and its 1GiB..1TiB budget limits remain unchanged here.
func (c *BootstrapCandidateCapacity) Prepare(ctx context.Context, g OfflineBootstrapGrant, config BootstrapConfig) (*PreparedBootstrapCandidateCapacity, error) {
	return c.prepare(ctx, g, config, false)
}

// PrepareAttempt preserves L3 history-read reachability when only the physical
// report is missing or malformed. It captures that failure without permission:
// CapacityObservedAt is nil and Reserve always rejects. Current grant/RBAC and
// exact operation authorization remain mandatory in the enclosing consumer.
func (c *BootstrapCandidateCapacity) PrepareAttempt(ctx context.Context, g OfflineBootstrapGrant, config BootstrapConfig) (*PreparedBootstrapCandidateCapacity, error) {
	return c.prepare(ctx, g, config, true)
}

func (c *BootstrapCandidateCapacity) prepare(ctx context.Context, g OfflineBootstrapGrant, config BootstrapConfig, deferPhysicalError bool) (*PreparedBootstrapCandidateCapacity, error) {
	if c == nil || !sameCandidateCapacityContext(ctx, ctx) || ctx.Err() != nil || !validBootstrapGrant(g) || g.ServerUUID != c.database.ServerUUID || g.Database != c.database.Database || config.SHA256() != g.ConfigSHA256 {
		return nil, ErrRegistrationUnavailable
	}
	capacity := config.numbers["control_metadata_capacity_bytes"]
	if capacity < 1073741824 || capacity > 1099511627776 {
		return nil, ErrRegistrationUnavailable
	}
	state := &bootstrapCandidateCapacityState{ctx: ctx, capacity: capacity, cost: 8192 + 65536}
	physicalFailure := func() (*PreparedBootstrapCandidateCapacity, error) {
		if deferPhysicalError && ctx.Err() == nil {
			return &PreparedBootstrapCandidateCapacity{state}, nil
		}
		return nil, ErrRegistrationUnavailable
	}
	raw, err := boundedFile(c.reportFile, 4096)
	if err != nil {
		return physicalFailure()
	}
	report, err := ParseCapacityReport(raw)
	if err != nil || report.ServerUUID != c.database.ServerUUID || report.Database != c.database.Database || report.ObservedAt.IsZero() || report.AllocatedBytes < 0 || report.AvailableBytes < 0 || capacity < 1073741824 || capacity > 1099511627776 {
		return physicalFailure()
	}
	if ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	report.ObservedAt = report.ObservedAt.UTC()
	state.report, state.reportUsable = report, true
	return &PreparedBootstrapCandidateCapacity{state}, nil
}

// ObservedAt is the original physical report sample, not a refreshed clock.
// Pass it into PreparedBootstrapAuthority.CapacityObservedAt. As in the
// original RegistrationCapacity, age=5 seconds is valid; age>5 is rejected.
func (p *PreparedBootstrapCandidateCapacity) ObservedAt() time.Time {
	if p == nil || p.state == nil || !p.state.reportUsable {
		return time.Time{}
	}
	return p.state.report.ObservedAt
}

func (p *PreparedBootstrapCandidateCapacity) CapacityObservedAt() *time.Time {
	if p == nil || p.state == nil || !p.state.reportUsable {
		return nil
	}
	sample := p.state.report.ObservedAt
	return &sample
}

func bootstrapCandidateCapacityTime(report CapacityReport, now time.Time) bool {
	return !now.IsZero() && !now.Before(report.ObservedAt) && now.Sub(report.ObservedAt) <= 5*time.Second
}

// Reserve belongs at L6, after the complete A/D reference prefix. Copies share
// one-shot use; even a failed ctx/tx binding attempt consumes preparation.
// Never reset the ledger from a newer allocation estimate or release old cost.
func (p *PreparedBootstrapCandidateCapacity) Reserve(ctx context.Context, tx pd.BootstrapSQL) (*BootstrapCandidateCapacityReservation, error) {
	fail := func() (*BootstrapCandidateCapacityReservation, error) { return nil, ErrRegistrationUnavailable }
	if p == nil || p.state == nil || !p.state.used.CompareAndSwap(false, true) {
		return fail()
	}
	s := p.state
	if !s.reportUsable || !sameCandidateCapacityContext(ctx, s.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(tx, tx) {
		return fail()
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != s.report.ServerUUID || database != s.report.Database {
		return fail()
	}
	now, err := tx.SampleTime(ctx)
	reserve := s.capacity / 20
	if reserve < 67108864 {
		reserve = 67108864
	}
	if err != nil || !bootstrapCandidateCapacityTime(s.report, now) || s.report.AvailableBytes < s.capacity+reserve+s.cost {
		return fail()
	}
	if _, err = tx.ExecContext(ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)", s.report.ObservedAt); err != nil {
		return fail()
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || sample.IsZero() || s.report.ObservedAt.Before(sample) || outstanding < 0 || outstanding > s.capacity || s.report.AllocatedBytes > s.capacity-outstanding-s.cost {
		return fail()
	}
	// CAS protects the original ledger sample and amount and latches SQL errors.
	write, ok := tx.(*pd.Transaction)
	if !ok || write.CAS(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", s.cost, sample, outstanding) != nil {
		return fail()
	}
	r := &BootstrapCandidateCapacityReservation{state: s, tx: tx, sample: sample, floor: outstanding + s.cost}
	if r.Recheck(ctx, tx) != nil {
		return fail()
	}
	return r, nil
}

// Recheck uses only the original transaction/ctx, original immutable physical
// sample, and already-locked id=1. It cannot reread a report, renew freshness,
// reset outstanding cost, acquire a new range, or complete the transaction.
func (r *BootstrapCandidateCapacityReservation) Recheck(ctx context.Context, tx pd.BootstrapReadSQL) error {
	if r == nil || r.state == nil || !sameCandidateCapacityContext(ctx, r.state.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(r.tx, tx) {
		return ErrRegistrationUnavailable
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || !sample.Equal(r.sample) || outstanding < r.floor || outstanding > r.state.capacity-r.state.report.AllocatedBytes {
		return ErrRegistrationUnavailable
	}
	now, err := tx.SampleTime(ctx)
	if err != nil || !bootstrapCandidateCapacityTime(r.state.report, now) {
		return ErrRegistrationUnavailable
	}
	return nil
}
