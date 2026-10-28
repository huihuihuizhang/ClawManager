package systembackupsecurity

// This driver tests the concrete capacity adapter through the real D guarded
// capability. It proves neither InnoDB range locking nor physical disk capacity.
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type bootstrapCapacityState struct {
	now, sample                          time.Time
	server, database                     string
	outstanding                          int64
	exists, zeroCAS, failCAS             bool
	queries, updates, commits, rollbacks int
}
type bootstrapCapacityConnector struct{ s *bootstrapCapacityState }

func (c bootstrapCapacityConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c bootstrapCapacityConnector) Connect(context.Context) (driver.Conn, error) {
	return &bootstrapCapacityConn{c.s}, nil
}

type bootstrapCapacityConn struct{ s *bootstrapCapacityState }

func (*bootstrapCapacityConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected capacity prepare")
}
func (*bootstrapCapacityConn) Close() error { return nil }
func (c *bootstrapCapacityConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *bootstrapCapacityConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &bootstrapCapacityTx{s: c.s, sample: c.s.sample, outstanding: c.s.outstanding, exists: c.s.exists}, nil
}

type bootstrapCapacityTx struct {
	s           *bootstrapCapacityState
	sample      time.Time
	outstanding int64
	exists      bool
}

func (t *bootstrapCapacityTx) Commit() error { t.s.commits++; return nil }
func (t *bootstrapCapacityTx) Rollback() error {
	t.s.sample, t.s.outstanding, t.s.exists = t.sample, t.outstanding, t.exists
	t.s.rollbacks++
	return nil
}
func (c *bootstrapCapacityConn) QueryContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s := c.s
	s.queries++
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return registrationRow(s.server, s.database, s.now, int64(0)), nil
	case "SELECT @@server_uuid,DATABASE()":
		return registrationRow(s.server, s.database), nil
	case "SELECT UTC_TIMESTAMP(6)":
		return registrationRow(s.now), nil
	case "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE":
		if !s.exists {
			return &registrationTestRows{width: 2}, nil
		}
		return registrationRow(s.sample, s.outstanding), nil
	}
	return nil, errors.New("unexpected capacity query")
}
func (c *bootstrapCapacityConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s := c.s
	switch q {
	case "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)":
		if !s.exists {
			s.exists = true
			s.sample = args[0].Value.(time.Time)
			s.outstanding = 0
		}
		return driver.RowsAffected(1), nil
	case "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?":
		if s.failCAS {
			return nil, errors.New("PRIVATE capacity SQL detail")
		}
		if s.zeroCAS || !s.sample.Equal(args[1].Value.(time.Time)) || s.outstanding != args[2].Value.(int64) {
			return driver.RowsAffected(0), nil
		}
		s.outstanding += args[0].Value.(int64)
		s.updates++
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unexpected capacity mutation")
}

type bootstrapCapacityPolicy struct {
	p *PreparedBootstrapCandidateCapacity
}

func (p bootstrapCapacityPolicy) LockAndAuthorize(context.Context, pd.SQL, pd.Scope) (pd.GuardPlan, error) {
	sample := p.p.ObservedAt()
	return pd.GuardPlan{BindingHash: pd.Hash(strings.Repeat("a", 64)), Deadlines: []time.Time{sample.Add(time.Hour)}, CapacityObservedAt: &sample}, nil
}
func (bootstrapCapacityPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func bootstrapCapacityFixture(t *testing.T) (*BootstrapCandidateCapacity, OfflineBootstrapGrant, BootstrapConfig, *bootstrapCapacityState, string) {
	t.Helper()
	_, g, raw, _ := bootstrapServiceFixture(t)
	config, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	state := &bootstrapCapacityState{now: now, sample: now.Add(-time.Second), server: g.ServerUUID, database: g.Database, outstanding: 100, exists: true}
	path := filepath.Join(t.TempDir(), "original-report.json")
	report := CapacityReport{ServerUUID: g.ServerUUID, Database: g.Database, ObservedAt: now, AllocatedBytes: 1, AvailableBytes: 1099511627776 * 2}
	rawReport, _ := json.Marshal(report)
	if err = os.WriteFile(path, rawReport, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewBootstrapCandidateCapacity(DatabaseIdentity{g.ServerUUID, g.Database}, path)
	if err != nil {
		t.Fatal(err)
	}
	return c, g, config, state, path
}

func TestBootstrapCandidateCapacityOriginalSampleAndBudget(t *testing.T) {
	for _, mode := range []string{"normal", "missing_ledger", "at_five_seconds", "past_five_seconds", "future_report", "future_ledger", "negative_ledger", "soft_full", "physical_full", "zero_cas", "sql_error", "late_floor", "late_sample", "late_expiry", "report_replaced"} {
		t.Run(mode, func(t *testing.T) {
			c, g, config, s, path := bootstrapCapacityFixture(t)
			ctx := context.Background()
			p, err := c.Prepare(ctx, g, config)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing_ledger":
				s.exists = false
			case "at_five_seconds":
				s.now = s.now.Add(5 * time.Second)
			case "past_five_seconds":
				s.now = s.now.Add(5*time.Second + time.Microsecond)
			case "future_report":
				s.now = s.now.Add(-time.Microsecond)
			case "future_ledger":
				s.sample = p.ObservedAt().Add(time.Microsecond)
			case "negative_ledger":
				s.outstanding = -1
			case "soft_full":
				s.outstanding = config.numbers["control_metadata_capacity_bytes"]
			case "physical_full":
				p.state.report.AvailableBytes = 0
			case "zero_cas":
				s.zeroCAS = true
			case "sql_error":
				s.failCAS = true
			case "report_replaced":
				if err = os.WriteFile(path, []byte("changed after original prepare"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := s.outstanding
			db := sql.OpenDB(bootstrapCapacityConnector{s})
			defer db.Close()
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			runner, err := pd.NewTransactions(db, pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}, bootstrapCapacityPolicy{p})
			if err != nil {
				t.Fatal(err)
			}
			var reservation *BootstrapCandidateCapacityReservation
			err = runner.GuardInTx(ctx, tx, func(ctx context.Context, sqltx *pd.Transaction) error {
				var reserveErr error
				reservation, reserveErr = p.Reserve(ctx, sqltx)
				if reserveErr != nil {
					return reserveErr
				}
				switch mode {
				case "late_floor":
					s.outstanding--
				case "late_sample":
					s.sample = s.sample.Add(time.Microsecond)
				case "late_expiry":
					s.now = p.ObservedAt().Add(5*time.Second + time.Microsecond)
				}
				return reservation.Recheck(ctx, sqltx)
			})
			positive := mode == "normal" || mode == "missing_ledger" || mode == "at_five_seconds" || mode == "report_replaced"
			if !positive {
				if err == nil {
					t.Fatal("invalid capacity committed", mode)
				}
				tx.Rollback()
				if s.outstanding != before || s.commits != 0 {
					t.Fatal("capacity rollback escaped", mode, s.outstanding, before)
				}
				return
			}
			if err != nil {
				t.Fatal("valid original capacity rejected", mode, err)
			}
			expected := before + 8192 + 65536
			if mode == "missing_ledger" {
				expected = 8192 + 65536
			}
			if s.outstanding != expected || s.updates != 1 {
				t.Fatal("charge reset or changed", s.outstanding, expected, s.updates)
			}
			if reservation.Recheck(ctx, nil) == nil {
				t.Fatal("nil tx accepted")
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if p.ObservedAt() != p.state.report.ObservedAt {
				t.Fatal("sample refreshed")
			}
		})
	}
}

func TestBootstrapCandidateCapacityBindingAndOutput(t *testing.T) {
	c, g, config, s, _ := bootstrapCapacityFixture(t)
	ctx := context.Background()
	p, err := c.Prepare(ctx, g, config)
	if err != nil {
		t.Fatal(err)
	}
	copy := *p
	wrong, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, err = p.Reserve(wrong, nil); err == nil {
		t.Fatal("replacement context accepted")
	}
	if _, err = copy.Reserve(ctx, nil); err == nil {
		t.Fatal("failed preparation reused")
	}
	if s.queries != 0 {
		t.Fatal("bad binding dispatched SQL")
	}
	for _, value := range []any{*c, c, *p, p, BootstrapCandidateCapacityReservation{}, &BootstrapCandidateCapacityReservation{}} {
		if _, err = json.Marshal(value); !errors.Is(err, ErrRegistrationUnavailable) {
			t.Fatal("opaque JSON accepted", err)
		}
		printed := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(printed, g.ServerUUID) || strings.Contains(printed, c.reportFile) {
			t.Fatal("private capacity data exposed")
		}
	}
	if _, err = c.Prepare(nil, g, config); err == nil {
		t.Fatal("nil context accepted")
	}
	var absent *ConfigBootstrapCandidates
	if _, err = c.Prepare(bootstrapCapacityInvalidContext{plan: absent}, g, config); err == nil {
		t.Fatal("incomparable context accepted")
	}
	var nilContext *bootstrapCapacityNilContext
	if _, err = c.Prepare(nilContext, g, config); err == nil {
		t.Fatal("typed-nil context accepted")
	}
}

func TestBootstrapCandidateCapacityMissingReportDefersOnlyNewConsumption(t *testing.T) {
	c, g, config, s, path := bootstrapCapacityFixture(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Prepare(ctx, g, config); err == nil {
		t.Fatal("strict report preparation accepted missing source")
	}
	p, err := c.PrepareAttempt(ctx, g, config)
	if err != nil || p == nil || p.CapacityObservedAt() != nil || !p.ObservedAt().IsZero() {
		t.Fatal("physical error prevented history branch or fabricated a sample", err)
	}
	if _, err = p.Reserve(ctx, nil); err == nil {
		t.Fatal("deferred report error granted a reservation")
	}
	if s.queries != 0 || s.updates != 0 {
		t.Fatal("missing report dispatched SQL")
	}
	wrong := g
	wrong.ConfigSHA256 = strings.Repeat("f", 64)
	if _, err = c.PrepareAttempt(ctx, wrong, config); err == nil {
		t.Fatal("deferred physical failure bypassed original config binding")
	}
}

// This deliberately incomparable context must be rejected before Err is used.
type bootstrapCapacityInvalidContext struct {
	plan   *ConfigBootstrapCandidates
	values []string
}

func (bootstrapCapacityInvalidContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (bootstrapCapacityInvalidContext) Done() <-chan struct{}       { return nil }
func (bootstrapCapacityInvalidContext) Err() error                  { panic("invalid capacity context was evaluated") }
func (bootstrapCapacityInvalidContext) Value(any) any               { return nil }

type bootstrapCapacityNilContext struct{ context.Context }
