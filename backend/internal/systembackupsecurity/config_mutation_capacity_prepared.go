package systembackupsecurity

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Full GC uses this opt-in preparation before connection/global-lock/Begin.
// Legacy Reserve is deliberately unchanged. This captures evidence, not a
// capacity measurement, authorization, renewed report or transaction grant.
type PreparedConfigMutationCapacity struct{ state *preparedConfigCapacityState }
type preparedConfigCapacityState struct {
	ctx    context.Context
	source *ConfigMutationCapacity
	report CapacityReport
	cost   int
	used   atomic.Bool
}

func (PreparedConfigMutationCapacity) String() string   { return "PreparedConfigMutationCapacity" }
func (PreparedConfigMutationCapacity) GoString() string { return "PreparedConfigMutationCapacity" }
func (PreparedConfigMutationCapacity) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*PreparedConfigMutationCapacity) UnmarshalJSON([]byte) error { return ErrRegistrationUnavailable }

func samePreparedCapacityContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	return av.Comparable() && bv.Comparable() && !(av.Kind() == reflect.Pointer && av.IsNil()) && !(bv.Kind() == reflect.Pointer && bv.IsNil()) && a == b
}

// PreparePinned reads exactly once before SQL ownership. Freshness is checked
// against authoritative SQL samples in Reserve/Recheck, with the ORIGINAL
// strict ObservedAt+5s bound. It never samples or writes a replacement report.
func (c *ConfigMutationCapacity) PreparePinned(ctx context.Context, cost int) (*PreparedConfigMutationCapacity, error) {
	if c == nil || !samePreparedCapacityContext(ctx, ctx) || ctx.Err() != nil || cost < 1 || cost > 1048576 {
		return nil, ErrRegistrationUnavailable
	}
	raw, err := boundedFile(c.reportFile, 4096)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	report, err := ParseCapacityReport(raw)
	if err != nil || report.ServerUUID != c.database.ServerUUID || report.Database != c.database.Database || report.ObservedAt.IsZero() || report.AllocatedBytes < 0 || report.AvailableBytes < 0 || ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	return &PreparedConfigMutationCapacity{&preparedConfigCapacityState{ctx: ctx, source: c, report: report, cost: cost}}, nil
}

// Reserve is single-use across copies, including rejected binding attempts.
// The original legacy numeric/physical inequalities and strict 5s rule remain
// intact. The only I/O here is on the caller's exact transaction; no file read.
func (p *PreparedConfigMutationCapacity) Reserve(ctx context.Context, tx *sql.Tx, source *ConfigMutationCapacity, current, proposed ConfigValues, notBefore time.Time) (ConfigMutationCapacityReservation, error) {
	fail := func() (ConfigMutationCapacityReservation, error) { return nil, ErrRegistrationUnavailable }
	if p == nil || p.state == nil || !p.state.used.CompareAndSwap(false, true) {
		return fail()
	}
	s := p.state
	c := s.source
	report := s.report
	if c == nil || source != c || !samePreparedCapacityContext(ctx, s.ctx) || ctx.Err() != nil || tx == nil || notBefore.IsZero() || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 {
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
	reserve := configMutationSafetyReserve(capacity)
	cost := int64(s.cost)
	if outstanding < 0 || report.AllocatedBytes >= capacity-reserve || outstanding >= capacity-reserve-report.AllocatedBytes || cost >= capacity-reserve-report.AllocatedBytes-outstanding {
		return fail()
	}
	if report.AvailableBytes <= physicalBudget+configMutationSafetyReserve(physicalBudget)+outstanding+cost {
		return fail()
	}
	if !configMutationOne(tx.ExecContext(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", cost, sample, outstanding)) {
		return fail()
	}
	r := &preparedConfigCapacityReservation{state: &preparedConfigReservationState{prepared: s, tx: tx, sample: sample, capacity: capacity, physical: physicalBudget, floor: outstanding + cost, until: until, last: now}}
	if r.Recheck(ctx, tx, now) != nil {
		return fail()
	}
	return r, nil
}

type preparedConfigCapacityReservation struct {
	state *preparedConfigReservationState
}
type preparedConfigReservationState struct {
	sync.Mutex
	prepared                  *preparedConfigCapacityState
	tx                        *sql.Tx
	sample, until, last       time.Time
	capacity, physical, floor int64
	failed                    bool
}

func (preparedConfigCapacityReservation) String() string { return "PreparedConfigMutationReservation" }
func (preparedConfigCapacityReservation) GoString() string {
	return "PreparedConfigMutationReservation"
}
func (preparedConfigCapacityReservation) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*preparedConfigCapacityReservation) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}
func (r *preparedConfigCapacityReservation) ValidUntil() time.Time {
	if r == nil || r.state == nil {
		return time.Time{}
	}
	return r.state.until
}

// SQLFloor exposes only the last authoritative sample to the fixed owner. It
// performs no SQL or report I/O and cannot renew the original until. Subsequent
// owner samples must not regress behind a capacity callback's later sample.
func (r *preparedConfigCapacityReservation) SQLFloor(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	if r == nil || r.state == nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	s := r.state
	s.Lock()
	defer s.Unlock()
	if s.failed || s.prepared == nil || !samePreparedCapacityContext(ctx, s.prepared.ctx) || ctx.Err() != nil || tx != s.tx {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return s.last, nil
}
func (r *preparedConfigCapacityReservation) Recheck(ctx context.Context, tx *sql.Tx, notBefore time.Time) error {
	if r == nil || r.state == nil {
		return ErrRegistrationUnavailable
	}
	s := r.state
	s.Lock()
	defer s.Unlock()
	fail := func() error { s.failed = true; return ErrRegistrationUnavailable }
	p := s.prepared
	if s.failed || p == nil || !samePreparedCapacityContext(ctx, p.ctx) || ctx.Err() != nil || tx == nil || tx != s.tx || notBefore.IsZero() || notBefore.Before(s.last) {
		return fail()
	}
	var sample time.Time
	var outstanding int64
	report := p.report
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || !sample.Equal(s.sample) || outstanding < s.floor || outstanding >= s.capacity-configMutationSafetyReserve(s.capacity)-report.AllocatedBytes || report.AvailableBytes <= s.physical+configMutationSafetyReserve(s.physical)+outstanding {
		return fail()
	}
	now, err := p.source.clock(ctx, tx, notBefore)
	if err != nil || !now.Before(s.until) {
		return fail()
	}
	s.last = now
	return nil
}
