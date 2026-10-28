package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mutationCapacityDB struct {
	identity                          DatabaseIdentity
	now, sample, pendingSample        time.Time
	reserved, pending                 int64
	offset                            int64
	steps, failAt, commits, rollbacks int
	active, zeroCAS                   bool
	afterUpdate                       func()
}
type mutationCapacityConnector struct{ s *mutationCapacityDB }

func (c mutationCapacityConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mutationCapacityConnector) Connect(context.Context) (driver.Conn, error) {
	return &mutationCapacityConn{c.s}, nil
}

type mutationCapacityConn struct{ s *mutationCapacityDB }

func (*mutationCapacityConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*mutationCapacityConn) Close() error                        { return nil }
func (c *mutationCapacityConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (c *mutationCapacityConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.s.active || opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("bad capacity transaction")
	}
	c.s.pending, c.s.pendingSample, c.s.active = c.s.reserved, c.s.sample, true
	return &mutationCapacityTx{c.s}, nil
}
func (c *mutationCapacityConn) step() error {
	c.s.steps++
	if !c.s.active || c.s.steps == c.s.failAt {
		return errors.New("PRIVATE capacity SQL failure")
	}
	return nil
}
func (c *mutationCapacityConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.step(); err != nil {
		return nil, err
	}
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return registrationRow(c.s.identity.ServerUUID, c.s.identity.Database, c.s.now, c.s.offset), nil
	case "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE":
		return registrationRow(c.s.pendingSample, c.s.pending), nil
	}
	return nil, errors.New("unexpected capacity query")
}
func (c *mutationCapacityConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.step(); err != nil {
		return nil, err
	}
	switch q {
	case "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)":
		if len(args) != 1 {
			return nil, errors.New("bad baseline args")
		}
		if c.s.pendingSample.IsZero() {
			c.s.pendingSample, c.s.pending = args[0].Value.(time.Time), 0
		}
	case "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?":
		if len(args) != 3 || args[0].Value.(int64) < 1 || !args[1].Value.(time.Time).Equal(c.s.pendingSample) || args[2].Value != c.s.pending {
			return nil, errors.New("wrong reservation CAS or count")
		}
		if c.s.zeroCAS {
			return driver.RowsAffected(0), nil
		}
		c.s.pending += args[0].Value.(int64)
		if c.s.afterUpdate != nil {
			c.s.afterUpdate()
		}
	default:
		return nil, errors.New("unexpected capacity write")
	}
	return driver.RowsAffected(1), nil
}

type mutationCapacityTx struct{ s *mutationCapacityDB }

func (t *mutationCapacityTx) Commit() error {
	t.s.reserved, t.s.sample, t.s.active = t.s.pending, t.s.pendingSample, false
	t.s.commits++
	return nil
}
func (t *mutationCapacityTx) Rollback() error { t.s.active = false; t.s.rollbacks++; return nil }

type mutationCapacityFixture struct {
	source            *ConfigMutationCapacity
	model             *mutationCapacityDB
	tx                *sql.Tx
	current, proposed ConfigValues
	report            CapacityReport
	notBefore         time.Time
}

func mutationCapacityValues(t *testing.T, capacity int64) ConfigValues {
	t.Helper()
	var doc map[string]any
	if json.Unmarshal(bootstrapFixture(t), &doc) != nil {
		t.Fatal("fixture")
	}
	doc["capacity"].(map[string]any)["control_metadata_capacity_bytes"] = capacity
	raw, _ := json.Marshal(doc)
	v, err := DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func newMutationCapacityFixture(t *testing.T) *mutationCapacityFixture {
	t.Helper()
	now := time.Date(2026, 10, 15, 2, 0, 0, 0, time.UTC)
	identity := DatabaseIdentity{"11111111-2222-3333-4444-555555555555", "synthetic"}
	m := &mutationCapacityDB{identity: identity, now: now, sample: now.Add(-time.Minute), reserved: 1048576}
	db := sql.OpenDB(mutationCapacityConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	source, err := NewConfigMutationCapacity(identity, filepath.Join(t.TempDir(), "capacity.json"), 67108864)
	if err != nil {
		t.Fatal(err)
	}
	v := mutationCapacityValues(t, 10737418240)
	f := &mutationCapacityFixture{source, m, tx, v, v, CapacityReport{identity.ServerUUID, identity.Database, now.Add(-time.Second), 134217728, 107374182400}, now}
	f.write(t)
	return f
}
func (f *mutationCapacityFixture) write(t *testing.T) {
	t.Helper()
	raw, _ := json.Marshal(f.report)
	if err := os.WriteFile(f.source.reportFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *mutationCapacityFixture) reserve() (ConfigMutationCapacityReservation, error) {
	return f.source.Reserve(context.Background(), f.tx, f.current, f.proposed, 524288, f.notBefore)
}

func TestConfigMutationCapacityCompleteCostAndMonotonicReservation(t *testing.T) {
	f := newMutationCapacityFixture(t)
	r, err := f.reserve()
	if err != nil || r == nil || !r.ValidUntil().Equal(f.report.ObservedAt.Add(5*time.Second)) || f.model.pending != 1048576+524288 || f.model.reserved != 1048576 || f.model.commits != 0 {
		t.Fatal("full response cost or caller transaction not preserved", err)
	}
	if !f.model.pendingSample.Equal(f.model.sample) || r.Recheck(context.Background(), f.tx, f.notBefore) != nil {
		t.Fatal("new estimate reset baseline or reservation")
	}
	if err = f.tx.Rollback(); err != nil || f.model.reserved != 1048576 || f.model.commits != 0 {
		t.Fatal("rollback persisted capacity")
	}
}

func TestConfigMutationCapacityTransitionAndUnknowns(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*mutationCapacityFixture)
		pass bool
	}{
		{"raise-exhausted-old-budget", func(f *mutationCapacityFixture) {
			f.current = mutationCapacityValues(t, 1073741824)
			f.proposed = mutationCapacityValues(t, 2147483648)
			f.report.AllocatedBytes = 1200000000
		}, true},
		{"lower-budget-fits", func(f *mutationCapacityFixture) { f.proposed = mutationCapacityValues(t, 1073741824) }, true},
		{"new-ledger-baseline", func(f *mutationCapacityFixture) { f.model.pendingSample = time.Time{} }, true},
		{"soft-reserve-exhausted", func(f *mutationCapacityFixture) {
			f.proposed = mutationCapacityValues(t, 1073741824)
			f.report.AllocatedBytes = 1073741824 - 67108864
		}, false},
		{"pending-reservations-counted", func(f *mutationCapacityFixture) {
			f.model.pending = 10737418240 - configMutationSafetyReserve(10737418240) - f.report.AllocatedBytes
		}, false},
		{"integer-overflow", func(f *mutationCapacityFixture) { f.model.pending = math.MaxInt64 }, false},
		{"allocated-overflow", func(f *mutationCapacityFixture) { f.report.AllocatedBytes = math.MaxInt64 }, false},
		{"negative-reservation", func(f *mutationCapacityFixture) { f.model.pending = -1 }, false},
		{"negative-allocated", func(f *mutationCapacityFixture) { f.report.AllocatedBytes = -1 }, false},
		{"unknown-physical", func(f *mutationCapacityFixture) { f.report.AvailableBytes = 0 }, false},
		{"physical-reserve-boundary", func(f *mutationCapacityFixture) {
			f.report.AvailableBytes = 10737418240 + configMutationSafetyReserve(10737418240) + f.model.pending + 524288
		}, false},
		{"protect-old-physical-budget", func(f *mutationCapacityFixture) {
			f.proposed = mutationCapacityValues(t, 1073741824)
			f.report.AvailableBytes = 2147483648
		}, false},
		{"twice-large-smoke", func(f *mutationCapacityFixture) {
			f.proposed = mutationCapacityValues(t, 1073741824)
			f.source.largeSmokeBytes = 600000000
		}, false},
		{"stale-report", func(f *mutationCapacityFixture) { f.report.ObservedAt = f.notBefore.Add(-5 * time.Second) }, false},
		{"future-report", func(f *mutationCapacityFixture) { f.report.ObservedAt = f.notBefore.Add(time.Microsecond) }, false},
		{"zero-observation", func(f *mutationCapacityFixture) { f.report.ObservedAt = time.Time{} }, false},
		{"older-than-ledger", func(f *mutationCapacityFixture) { f.model.pendingSample = f.report.ObservedAt.Add(time.Microsecond) }, false},
		{"foreign-report", func(f *mutationCapacityFixture) { f.report.Database = "foreign" }, false},
		{"foreign-connection", func(f *mutationCapacityFixture) { f.model.identity.ServerUUID = strings.Repeat("a", 36) }, false},
		{"utc-offset", func(f *mutationCapacityFixture) { f.model.offset = 1 }, false},
		{"clock-backward", func(f *mutationCapacityFixture) { f.model.now = f.notBefore.Add(-time.Microsecond) }, false},
		{"waited-through-expiry", func(f *mutationCapacityFixture) {
			f.model.afterUpdate = func() { f.model.now = f.report.ObservedAt.Add(5 * time.Second) }
		}, false},
		{"zero-cas", func(f *mutationCapacityFixture) { f.model.zeroCAS = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMutationCapacityFixture(t)
			tc.edit(f)
			f.write(t)
			r, err := f.reserve()
			if tc.pass && (err != nil || r == nil) || !tc.pass && (err != ErrRegistrationUnavailable || r != nil) {
				t.Fatal("capacity decision", err, "pass", tc.pass)
			}
			if f.model.commits != 0 || f.model.reserved != 1048576 {
				t.Fatal("source committed reservation")
			}
		})
	}
}

func TestConfigMutationCapacityFinalRecheckCannotResetOrOutliveSample(t *testing.T) {
	for _, name := range []string{"foreign-tx", "sample-reset", "reservation-reset", "extra-reservations-fill-budget", "expired", "valid"} {
		t.Run(name, func(t *testing.T) {
			f := newMutationCapacityFixture(t)
			r, err := f.reserve()
			if err != nil {
				t.Fatal(err)
			}
			tx := f.tx
			switch name {
			case "foreign-tx":
				tx = &sql.Tx{}
			case "sample-reset":
				f.model.pendingSample = f.model.pendingSample.Add(time.Second)
			case "reservation-reset":
				f.model.pending--
			case "extra-reservations-fill-budget":
				f.model.pending = 10737418240
			case "expired":
				f.model.now = r.ValidUntil()
			}
			err = r.Recheck(context.Background(), tx, f.notBefore)
			if name == "valid" && err != nil || name != "valid" && err != ErrRegistrationUnavailable {
				t.Fatal("invalid final capacity decision", err)
			}
		})
	}
	for phase := 1; phase <= 6; phase++ {
		f := newMutationCapacityFixture(t)
		f.model.failAt = phase
		if r, err := f.reserve(); err != ErrRegistrationUnavailable || r != nil {
			t.Fatal("SQL error leaked or admitted", phase, err)
		}
	}
	if configMutationSafetyReserve(2000000001) != 100000001 {
		t.Fatal("five-percent reserve must round up")
	}
}

func TestConfigMutationCapacityRejectsMissingDeploymentEvidence(t *testing.T) {
	f := newMutationCapacityFixture(t)
	for _, footprint := range []int64{0, -1, math.MaxInt64} {
		if c, err := NewConfigMutationCapacity(f.model.identity, f.source.reportFile, footprint); err != ErrRegistrationUnavailable || c != nil {
			t.Fatal("unmeasured smoke footprint accepted", err)
		}
	}
	if c, err := NewConfigMutationCapacity(f.model.identity, "relative.json", 1); c != nil || err != ErrRegistrationUnavailable {
		t.Fatal("request-relative file accepted", err)
	}
	for _, raw := range []string{`null`, `{}`, `{"ServerUUID":"x"}`, `{"server_uuid":null}`} {
		if os.WriteFile(f.source.reportFile, []byte(raw), 0600) != nil {
			t.Fatal("write")
		}
		if r, err := f.reserve(); r != nil || err != ErrRegistrationUnavailable {
			t.Fatal("malformed physical report accepted", err)
		}
	}
}
