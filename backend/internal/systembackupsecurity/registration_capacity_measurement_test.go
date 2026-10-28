package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"testing"
	"time"
)

type capacityMeasurementModel struct {
	start, end       time.Time
	tables           [][]driver.Value
	clockCalls       int
	measured, closed bool
	fail             string
	iterationErr     bool
}

type capacityMeasurementConnector struct{ model *capacityMeasurementModel }

func (c capacityMeasurementConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c capacityMeasurementConnector) Connect(context.Context) (driver.Conn, error) {
	return &capacityMeasurementConn{c.model}, nil
}

type capacityMeasurementConn struct{ model *capacityMeasurementModel }

func (*capacityMeasurementConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (*capacityMeasurementConn) Begin() (driver.Tx, error) { return nil, errors.New("unused") }
func (*capacityMeasurementConn) Close() error              { return nil }
func (c *capacityMeasurementConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	m := c.model
	switch query {
	case "SELECT UTC_TIMESTAMP(6)":
		m.clockCalls++
		if m.clockCalls == 1 && !m.measured && m.fail != "start" {
			return registrationRow(m.start), nil
		}
		if m.clockCalls == 2 && m.closed && m.fail != "end" {
			return registrationRow(m.end), nil
		}
	case capacityAllocationQuery:
		if m.clockCalls == 1 && m.measured && m.fail != "query" {
			return &capacityMeasurementRows{model: m}, nil
		}
	}
	return nil, errors.New("PRIVATE collection failure or invalid measurement order")
}

type capacityMeasurementRows struct {
	model *capacityMeasurementModel
	index int
}

func (*capacityMeasurementRows) Columns() []string {
	return []string{"TABLE_NAME", "TABLE_TYPE", "DATA_LENGTH", "INDEX_LENGTH"}
}
func (r *capacityMeasurementRows) Close() error {
	r.model.closed = true
	if r.model.fail == "close" {
		return errors.New("PRIVATE close failure")
	}
	return nil
}
func (r *capacityMeasurementRows) Next(values []driver.Value) error {
	if r.index < len(r.model.tables) {
		copy(values, r.model.tables[r.index])
		r.index++
		return nil
	}
	if r.model.iterationErr {
		return errors.New("PRIVATE iteration failure")
	}
	return io.EOF
}

func TestCapacityMeasurementOriginalWindowAndExactTables(t *testing.T) {
	for _, name := range []string{
		"exact", "slow_within_original_window", "same_count_substitution", "missing", "duplicate", "extra", "view", "null_allocation", "negative_data", "negative_index", "row_overflow", "sum_overflow", "start_zero", "clock_reversed", "at_deadline", "past_deadline", "stat_failure", "negative_space", "start", "end", "query", "close", "iteration", "canceled_after_space",
	} {
		t.Run(name, func(t *testing.T) {
			config := capacitySourceFixture(t)
			start := time.Date(2026, 10, 19, 8, 0, 0, 123456000, time.UTC)
			model := &capacityMeasurementModel{start: start, end: start.Add(time.Second), tables: [][]driver.Value{
				{"system_backup_v2_configs", "BASE TABLE", int64(100), int64(25)},
				{"audit_logs", "BASE TABLE", int64(200), int64(50)},
				{"system_backup_v2_backups", "BASE TABLE", int64(300), int64(75)},
			}}
			space := int64(1 << 40)
			var statErr error
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "slow_within_original_window":
				model.end = start.Add(4999 * time.Millisecond)
			case "same_count_substitution":
				model.tables[0][0] = "system_backup_unexpected"
			case "missing":
				model.tables = model.tables[:1]
			case "duplicate":
				model.tables[1][0] = model.tables[0][0]
			case "extra":
				model.tables = append(model.tables, []driver.Value{"system_backup_extra", "BASE TABLE", int64(0), int64(0)})
			case "view":
				model.tables[0][1] = "VIEW"
			case "null_allocation":
				model.tables[0][2] = nil
			case "negative_data":
				model.tables[0][2] = int64(-1)
			case "negative_index":
				model.tables[0][3] = int64(-1)
			case "row_overflow":
				model.tables[0][2] = int64(math.MaxInt64)
			case "sum_overflow":
				model.tables[1][2], model.tables[1][3] = int64(math.MaxInt64-100), int64(0)
			case "start_zero":
				model.start = time.Time{}
			case "clock_reversed":
				model.end = start.Add(-time.Microsecond)
			case "at_deadline":
				model.end = start.Add(5 * time.Second)
			case "past_deadline":
				model.end = start.Add(6 * time.Second)
			case "stat_failure":
				statErr = errors.New("PRIVATE filesystem failure")
			case "negative_space":
				space = -1
			case "iteration":
				model.iterationErr = true
			case "start", "end", "query", "close":
				model.fail = name
			}
			database := sql.OpenDB(capacityMeasurementConnector{model})
			defer database.Close()
			conn, err := database.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			report, err := measureRegistrationCapacity(ctx, conn, config, func() (int64, error) {
				if model.clockCalls != 1 || model.measured {
					t.Error("space measured before original SQL timestamp or more than once")
				}
				model.measured = true
				if name == "canceled_after_space" {
					cancel()
				}
				return space, statErr
			})
			if name == "exact" || name == "slow_within_original_window" {
				if err != nil || report.ServerUUID != config.ServerUUID || report.Database != config.Database || report.AllocatedBytes != 750 || report.AvailableBytes != space || !report.ObservedAt.Equal(start) || !model.closed || model.clockCalls != 2 {
					t.Fatalf("measurement or original timestamp lost: %+v error=%v", report, err)
				}
			} else if !errors.Is(err, ErrRegistrationUnavailable) || report != (CapacityReport{}) {
				t.Fatalf("invalid measurement produced report: %+v error=%v", report, err)
			}
			if model.measured && model.fail != "query" && name != "stat_failure" && name != "negative_space" && name != "canceled_after_space" && !model.closed {
				t.Fatal("allocation cursor leaked")
			}
		})
	}
}
