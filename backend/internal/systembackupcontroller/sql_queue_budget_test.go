package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type queueBudgetDBState struct {
	now        time.Time
	offset     int64
	backup     [][]driver.Value
	drill      [][]driver.Value
	preflight  [][]driver.Value
	verify     [][]driver.Value
	operations [][]driver.Value
	queries    []string
	beganRead  bool
	committed  bool
	rolledBack bool
}

type queueBudgetConnector struct{ state *queueBudgetDBState }

func (c queueBudgetConnector) Connect(context.Context) (driver.Conn, error) {
	return &queueBudgetConn{state: c.state}, nil
}
func (c queueBudgetConnector) Driver() driver.Driver { return queueBudgetDriver{state: c.state} }

type queueBudgetDriver struct{ state *queueBudgetDBState }

func (d queueBudgetDriver) Open(string) (driver.Conn, error) {
	return &queueBudgetConn{state: d.state}, nil
}

type queueBudgetConn struct{ state *queueBudgetDBState }

func (*queueBudgetConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected queue budget preparation")
}
func (*queueBudgetConn) Close() error { return nil }
func (*queueBudgetConn) Begin() (driver.Tx, error) {
	return nil, errors.New("queue budget reader omitted read-only transaction options")
}
func (c *queueBudgetConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	if !options.ReadOnly || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("queue budget reader did not request a repeatable read-only snapshot")
	}
	c.state.beganRead = true
	return &queueBudgetTx{state: c.state}, nil
}

func (c *queueBudgetConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.queries = append(c.state.queries, query)
	if strings.Contains(query, "public_id") || strings.Contains(query, "credential") || strings.Contains(query, "provider_payload") {
		return nil, errors.New("queue budget query selected a forbidden identity or payload")
	}
	if strings.Contains(query, "SELECT UTC_TIMESTAMP(6)") {
		if len(args) != 0 {
			return nil, errors.New("database clock query had arguments")
		}
		return &queueBudgetRows{columns: []string{"database_now", "utc_offset"}, values: [][]driver.Value{{c.state.now, c.state.offset}}}, nil
	}
	if len(args) != 1 || args[0].Value != "installation_test" || !strings.Contains(query, "status = 'pending'") || !strings.Contains(query, " LIMIT ") {
		return nil, errors.New("pending queue budget query has an unexpected filter")
	}
	switch {
	case strings.Contains(query, "FROM system_backups"):
		return &queueBudgetRows{columns: []string{"task_purpose", "created_at", "deadline_at"}, values: c.state.backup}, nil
	case strings.Contains(query, "FROM system_restore_drills"):
		return &queueBudgetRows{columns: []string{"task_purpose", "created_at", "deadline_at"}, values: c.state.drill}, nil
	case strings.Contains(query, "FROM system_backup_preflights"):
		return &queueBudgetRows{columns: []string{"preflight_mode", "created_at", "deadline_at"}, values: c.state.preflight}, nil
	case strings.Contains(query, "FROM system_backup_artifact_verifications"):
		return &queueBudgetRows{columns: []string{"verification_scope", "created_at", "deadline_at"}, values: c.state.verify}, nil
	case strings.Contains(query, "FROM system_backup_operations"):
		return &queueBudgetRows{columns: []string{"operation_type", "created_at", "deadline_at"}, values: c.state.operations}, nil
	default:
		return nil, errors.New("unexpected queue budget table")
	}
}

type queueBudgetTx struct{ state *queueBudgetDBState }

func (t *queueBudgetTx) Commit() error   { t.state.committed = true; return nil }
func (t *queueBudgetTx) Rollback() error { t.state.rolledBack = true; return nil }

type queueBudgetRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *queueBudgetRows) Columns() []string { return r.columns }
func (*queueBudgetRows) Close() error        { return nil }
func (r *queueBudgetRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func TestSQLQueueBudgetReaderEmitsOnlyClosedLowCardinalitySamples(t *testing.T) {
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	state := &queueBudgetDBState{
		now: created.Add(time.Minute),
		backup: [][]driver.Value{
			{"acceptance", created, created.Add(2 * time.Minute)},
			{"acceptance", created.Add(20 * time.Second), created.Add(40 * time.Second)},
		},
		drill:      [][]driver.Value{{"functional_test", created, created.Add(2 * time.Minute)}},
		preflight:  [][]driver.Value{{"production_readonly", created, created.Add(2 * time.Minute)}},
		verify:     [][]driver.Value{{"full", created, created.Add(30 * time.Second)}},
		operations: [][]driver.Value{{"cleanup", created, created.Add(time.Minute)}},
	}
	db := sql.OpenDB(queueBudgetConnector{state: state})
	defer db.Close()
	samples, err := (SQLQueueBudgetReader{DB: db}).Collect(context.Background(), "installation_test")
	if err != nil {
		t.Fatal(err)
	}
	if !state.beganRead || !state.committed || state.rolledBack || len(state.queries) != 6 || len(samples) != 25 {
		t.Fatalf("read-only snapshot began=%t committed=%t rollback=%t queries=%d samples=%d", state.beganRead, state.committed, state.rolledBack, len(state.queries), len(samples))
	}
	for index, limit := range []string{"LIMIT 10001", "LIMIT 9999", "LIMIT 9998", "LIMIT 9997", "LIMIT 9996"} {
		if !strings.HasSuffix(state.queries[index+1], limit) {
			t.Fatalf("query %d did not bound its result to remaining budget plus one: %q", index+1, state.queries[index+1])
		}
	}
	values := make(map[string]float64, len(samples))
	for _, sample := range samples {
		key := sample.MetricName + "/" + sample.TaskType + "/" + sample.TaskPurpose + "/" + sample.PreflightMode + "/" + sample.VerificationScope + "/" + sample.OperationType
		if _, exists := values[key]; exists {
			t.Fatalf("duplicate metric labels: %s", key)
		}
		values[key] = sample.Value
	}
	if values["clawmanager_system_backup_task_queue_deadline_utilization_ratio/backup/acceptance///"] != 2 ||
		values["clawmanager_system_backup_task_queue_deadline_utilization_ratio/drill/functional_test///"] != 0.5 ||
		values["clawmanager_system_backup_preflight_queue_deadline_utilization_ratio///production_readonly//"] != 0.5 ||
		values["clawmanager_system_backup_preflight_queue_deadline_utilization_ratio///functional_test//"] != 0 ||
		values["clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio////full/"] != 2 ||
		values["clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio////health/"] != 0 ||
		values["clawmanager_system_backup_operation_queue_deadline_utilization_ratio/////cleanup"] != 1 ||
		values["clawmanager_system_backup_operation_queue_deadline_utilization_ratio/////cancel"] != 0 {
		t.Fatalf("unexpected queue utilization samples: %#v", values)
	}
}

func TestSQLQueueBudgetReaderRejectsNonUTCUnknownLabelsAndOversizedBacklog(t *testing.T) {
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name        string
		state       *queueBudgetDBState
		wantQueries int
	}{
		{name: "non-UTC", state: &queueBudgetDBState{now: created, offset: int64((8 * time.Hour) / time.Microsecond)}, wantQueries: 1},
		{name: "unknown label", state: &queueBudgetDBState{now: created, backup: [][]driver.Value{{"unregistered", created, created.Add(time.Minute)}}}, wantQueries: 2},
		{name: "unknown preflight mode", state: &queueBudgetDBState{now: created, preflight: [][]driver.Value{{"unregistered", created, created.Add(time.Minute)}}}, wantQueries: 4},
		{name: "unknown verification scope", state: &queueBudgetDBState{now: created, verify: [][]driver.Value{{"unregistered", created, created.Add(time.Minute)}}}, wantQueries: 5},
		{name: "too many rows", state: &queueBudgetDBState{now: created, backup: make([][]driver.Value, MaxQueueBudgetRows+1)}, wantQueries: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "too many rows" {
				for index := range test.state.backup {
					test.state.backup[index] = []driver.Value{"acceptance", created, created.Add(time.Minute)}
				}
			}
			db := sql.OpenDB(queueBudgetConnector{state: test.state})
			defer db.Close()
			samples, err := (SQLQueueBudgetReader{DB: db}).Collect(context.Background(), "installation_test")
			if err == nil || samples != nil || test.state.committed || !test.state.rolledBack || len(test.state.queries) != test.wantQueries {
				t.Fatalf("samples=%v error=%v committed=%t rollback=%t queries=%d", samples, err, test.state.committed, test.state.rolledBack, len(test.state.queries))
			}
		})
	}
	if _, err := (SQLQueueBudgetReader{}).Collect(context.Background(), "installation_test"); err == nil {
		t.Fatal("nil queue budget database was accepted")
	}
}
