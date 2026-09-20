package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type acceptanceStateTestConnector struct{ state *acceptanceStateTestDB }

type acceptanceStateTestDB struct {
	values   [][]driver.Value
	query    string
	args     []driver.NamedValue
	queryErr error
}

func (c acceptanceStateTestConnector) Connect(context.Context) (driver.Conn, error) {
	return acceptanceStateTestConn{state: c.state}, nil
}
func (acceptanceStateTestConnector) Driver() driver.Driver { return acceptanceStateTestDriver{} }

type acceptanceStateTestDriver struct{}

func (acceptanceStateTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}

type acceptanceStateTestConn struct{ state *acceptanceStateTestDB }

func (acceptanceStateTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (acceptanceStateTestConn) Close() error { return nil }
func (acceptanceStateTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c acceptanceStateTestConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.query = query
	c.state.args = append([]driver.NamedValue(nil), args...)
	if c.state.queryErr != nil {
		return nil, c.state.queryErr
	}
	return &acceptanceStateTestRows{values: c.state.values}, nil
}

type acceptanceStateTestRows struct {
	values [][]driver.Value
	index  int
}

func (*acceptanceStateTestRows) Columns() []string {
	return []string{"task_type", "consecutive_anomaly_count"}
}
func (*acceptanceStateTestRows) Close() error { return nil }
func (r *acceptanceStateTestRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func TestSQLAcceptanceAnomalyReaderUsesStableBoundedScope(t *testing.T) {
	state := &acceptanceStateTestDB{values: [][]driver.Value{{"backup", int64(2)}, {"drill", int64(3)}}}
	db := sql.OpenDB(acceptanceStateTestConnector{state: state})
	defer db.Close()
	counts, err := (SQLAcceptanceAnomalyReader{DB: db}).Read(context.Background(), "installation_test")
	if err != nil {
		t.Fatal(err)
	}
	if counts[TargetBackup] != 2 || counts[TargetDrill] != 3 || len(counts) != 2 {
		t.Fatalf("unexpected acceptance anomaly counts: %#v", counts)
	}
	for _, required := range []string{"FROM system_backup_alert_states", "matrix_key = 'all'", "task_purpose = 'acceptance'", "LIMIT 3"} {
		if !strings.Contains(state.query, required) {
			t.Fatalf("acceptance anomaly query lacks %q: %s", required, state.query)
		}
	}
	if len(state.args) != 2 || state.args[0].Value != "installation_test" || state.args[1].Value != acceptanceAnomalyStateKey {
		t.Fatalf("acceptance anomaly query arguments = %#v", state.args)
	}
}

func TestSQLAcceptanceAnomalyReaderPreservesMissingAndRejectsInvalidRows(t *testing.T) {
	for _, test := range []struct {
		name       string
		values     [][]driver.Value
		wantCounts int
		wantErr    bool
	}{
		{name: "missing", values: nil, wantCounts: 0},
		{name: "one missing", values: [][]driver.Value{{"backup", int64(1)}}, wantCounts: 1},
		{name: "duplicate", values: [][]driver.Value{{"backup", int64(1)}, {"backup", int64(2)}}, wantErr: true},
		{name: "unknown", values: [][]driver.Value{{"operation", int64(1)}}, wantErr: true},
		{name: "negative", values: [][]driver.Value{{"backup", int64(-1)}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &acceptanceStateTestDB{values: test.values}
			db := sql.OpenDB(acceptanceStateTestConnector{state: state})
			defer db.Close()
			counts, err := (SQLAcceptanceAnomalyReader{DB: db}).Read(context.Background(), "installation_test")
			if test.wantErr {
				if err == nil || counts != nil {
					t.Fatalf("invalid acceptance anomaly rows accepted: %#v", test.values)
				}
				return
			}
			if err != nil || len(counts) != test.wantCounts {
				t.Fatalf("missing acceptance anomaly rows changed: counts=%#v err=%v", counts, err)
			}
		})
	}
}

func TestSQLAcceptanceAnomalyReaderEvaluate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		profile  string
		values   [][]driver.Value
		firing   [2]bool
		severity string
	}{
		{name: "production threshold", profile: "production", values: [][]driver.Value{{"backup", int64(2)}, {"drill", int64(3)}}, firing: [2]bool{false, true}, severity: "critical"},
		{name: "development missing drill", profile: "development", values: [][]driver.Value{{"backup", int64(0)}}, firing: [2]bool{false, true}, severity: "info"},
		{name: "both missing", profile: "production", firing: [2]bool{true, true}, severity: "critical"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &acceptanceStateTestDB{values: tc.values}
			db := sql.OpenDB(acceptanceStateTestConnector{state: state})
			defer db.Close()
			decisions, err := (SQLAcceptanceAnomalyReader{DB: db}).Evaluate(context.Background(), "installation_test", tc.profile)
			if err != nil {
				t.Fatal(err)
			}
			if len(decisions) != 2 || decisions[0].TaskType != TargetBackup || decisions[1].TaskType != TargetDrill {
				t.Fatalf("unexpected decision scope: %#v", decisions)
			}
			for index, decision := range decisions {
				if decision.RuleID != "acceptance-consecutive-anomalies."+tc.profile || decision.Severity != tc.severity || decision.TaskPurpose != "acceptance" || decision.Firing != tc.firing[index] {
					t.Fatalf("unexpected decision %d: %#v", index, decision)
				}
			}
		})
	}
}

func TestSQLAcceptanceAnomalyReaderEvaluateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		profile  string
		values   [][]driver.Value
		queryErr error
		noQuery  bool
	}{
		{name: "invalid profile", profile: "other", noQuery: true},
		{name: "query failed", profile: "production", queryErr: errors.New("unavailable")},
		{name: "invalid row", profile: "production", values: [][]driver.Value{{"backup", int64(-1)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &acceptanceStateTestDB{values: tc.values, queryErr: tc.queryErr}
			db := sql.OpenDB(acceptanceStateTestConnector{state: state})
			defer db.Close()
			decisions, err := (SQLAcceptanceAnomalyReader{DB: db}).Evaluate(context.Background(), "installation_test", tc.profile)
			if err == nil || decisions != nil {
				t.Fatalf("invalid state produced decisions: %#v, err=%v", decisions, err)
			}
			if tc.noQuery && state.query != "" {
				t.Fatalf("invalid input queried DB: %s", state.query)
			}
		})
	}
}
