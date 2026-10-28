package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type overviewFixture struct {
	health                                             []driver.Value
	state                                              []driver.Value
	tasks, operations                                  [][]driver.Value
	queries                                            []string
	transactions, commits, rollbacks, rechecks, builds int
	options                                            driver.TxOptions
	authorizeErr, recheckErr, commitErr                error
	queryError                                         string
	streamError                                        bool
	taskSchema, storedKind, operationSchema            string
	rollbackDone                                       chan struct{}
}

func newOverviewFixture() *overviewFixture {
	now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
	return &overviewFixture{
		rollbackDone: make(chan struct{}),
		state: []driver.Value{"system-backup-installation-state.v1", "installation_test", int64(3), int64(4), nil, false, false, "none", "k8s-cluster",
			"system-backup-config.v1", "installation_test", int64(3), int64(5), false, now, int64(0)},
		tasks: [][]driver.Value{{"backup", "pending", int64(1200)}, {"backup", "finalization_unknown", int64(7)}, {"backup", "failed", int64(20)},
			{"drill", "restoring", int64(3)}, {"preflight", "succeeded", int64(11)}, {"artifact_verify", "running", int64(2)}},
		operations: [][]driver.Value{{"pending", int64(500)}, {"running", int64(2)}, {"succeeded", int64(9)}},
	}
}
func (f *overviewFixture) AuthorizeRead(_ context.Context, tx *sql.Tx) (string, error) {
	if tx == nil {
		return "", ErrDenied
	}
	if f.authorizeErr != nil {
		return "", f.authorizeErr
	}
	return "installation_test", nil
}
func (f *overviewFixture) RecheckRead(_ context.Context, tx *sql.Tx, installation string) error {
	f.rechecks++
	if tx == nil || installation != "installation_test" {
		return ErrDenied
	}
	return f.recheckErr
}

type overviewConnector struct{ f *overviewFixture }

func (c overviewConnector) Connect(context.Context) (driver.Conn, error) {
	return &overviewConn{c.f}, nil
}
func (overviewConnector) Driver() driver.Driver { return pageDriver{} }

type overviewConn struct{ f *overviewFixture }

func (*overviewConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*overviewConn) Close() error { return nil }
func (c *overviewConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *overviewConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.f.transactions++
	c.f.options = options
	return overviewTx{c.f}, nil
}

type overviewTx struct{ f *overviewFixture }

func (tx overviewTx) Commit() error   { tx.f.commits++; return tx.f.commitErr }
func (tx overviewTx) Rollback() error { tx.f.rollbacks++; close(tx.f.rollbackDone); return nil }

type overviewErrorRows struct {
	*pageRows
	fail bool
}

func (r *overviewErrorRows) Next(dest []driver.Value) error {
	if r.fail && r.pageRows.next > 0 {
		return errors.New("synthetic stream failure")
	}
	return r.pageRows.Next(dest)
}
func (c *overviewConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.queries = append(c.f.queries, query)
	if query == c.f.queryError {
		return nil, errors.New("synthetic overview SQL failure")
	}
	for _, arg := range args {
		if arg.Value != "installation_test" {
			return nil, errors.New("untrusted installation parameter")
		}
	}
	var columns []string
	var values [][]driver.Value
	switch query {
	case controlHealthSQL:
		if len(args) != 1 {
			return nil, errors.New("health query unscoped")
		}
		columns = strings.Split("schema,installation,config,epoch,owner,sequence,controller,database,checked,expiry,interval", ",")
		if c.f.health != nil {
			values = [][]driver.Value{c.f.health}
		}
	case overviewInstallationSQL:
		if len(args) != 1 {
			return nil, errors.New("installation query parameter mismatch")
		}
		columns = strings.Split("state_schema,installation,config_version,state_row_version,first_enabled,last_effective,monitoring,reason,matrix,config_schema,config_installation,selected_version,config_row_version,config_enabled,observed_at,clock_offset", ",")
		if c.f.state != nil {
			values = [][]driver.Value{c.f.state}
		}
	case overviewTaskCountsSQL:
		if len(args) != 4 {
			return nil, errors.New("all task branches must be installation scoped")
		}
		columns = []string{"kind", "schema_version", "task_type", "status", "count"}
		for _, row := range c.f.tasks {
			schema, kind := "system-backup-task.v1", row[0]
			if c.f.taskSchema != "" {
				schema = c.f.taskSchema
			}
			if c.f.storedKind != "" {
				kind = c.f.storedKind
			}
			values = append(values, []driver.Value{row[0], schema, kind, row[1], row[2]})
		}
	case overviewOperationCountsSQL:
		if len(args) != 1 {
			return nil, errors.New("operation query parameter mismatch")
		}
		columns = []string{"schema_version", "status", "count"}
		for _, row := range c.f.operations {
			schema := "system-backup-operation.v1"
			if c.f.operationSchema != "" {
				schema = c.f.operationSchema
			}
			values = append(values, []driver.Value{schema, row[0], row[1]})
		}
	case "SELECT 'owner_fact' WHERE ?":
		if len(args) != 1 {
			return nil, errors.New("owner query unscoped")
		}
		columns = []string{"fact"}
		values = [][]driver.Value{{"verified"}}
	default:
		return nil, fmt.Errorf("unexpected overview query: %s", query)
	}
	rows := &pageRows{columns: columns, values: values}
	if query == overviewTaskCountsSQL && c.f.streamError {
		return &overviewErrorRows{rows, true}, nil
	}
	return rows, nil
}
func overviewReader(t *testing.T, f *overviewFixture) *Reader {
	t.Helper()
	db := sql.OpenDB(overviewConnector{f})
	t.Cleanup(func() { db.Close() })
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOverviewControlCountsAllRowsWithoutCreatingPublicOverview(t *testing.T) {
	f := newOverviewFixture()
	r := overviewReader(t, f)
	result, err := r.ReadOverviewControl(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := result.InstallationState()
	if state.InstallationID != "installation_test" || state.ConfigVersion != 3 || state.StateRowVersion != 4 || state.ConfigRowVersion != 5 || state.MatrixKey != "k8s-cluster" || state.ObservedAt.IsZero() {
		t.Fatal("state projection", state)
	}
	if result.TaskStatusCounts(BackupTask)["pending"] != 1200 || result.TaskStatusCounts(BackupTask)["finalization_unknown"] != 7 ||
		result.TaskStatusCounts(DrillTask)["restoring"] != 3 || result.OperationStatusCounts()["pending"] != 500 {
		t.Fatal("counts were truncated or inferred from page lengths", result)
	}
	for kind, table := range taskTables {
		counts := result.TaskStatusCounts(kind)
		if len(counts) != len(table.status) {
			t.Fatal("not all statuses initialized", kind, counts)
		}
	}
	if f.commits != 1 || f.rollbacks != 0 || f.rechecks != 1 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatal("transaction boundary", f)
	}
	if _, err := json.Marshal(result); err == nil {
		t.Fatal("partial control facts became a public overview")
	}
	if _, err := json.Marshal(state); err == nil {
		t.Fatal("persisted state became a public effective-enabled claim")
	}
	copy := result.TaskStatusCounts(BackupTask)
	copy["pending"] = 0
	if result.TaskStatusCounts(BackupTask)["pending"] != 1200 {
		t.Fatal("mutable count alias")
	}
	operationCopy := result.OperationStatusCounts()
	operationCopy["pending"] = 0
	if result.OperationStatusCounts()["pending"] != 500 {
		t.Fatal("mutable operation alias")
	}
	if result.TaskStatusCounts(TaskKind("catalog_scan")) != nil {
		t.Fatal("unknown category manufactured zero counts")
	}
	for _, query := range f.queries {
		for _, forbidden := range []string{"SELECT *", "config_snapshot_json", "canonical_config_json", "failure_message", "evidence_payload"} {
			if strings.Contains(query, forbidden) {
				t.Fatal("sensitive overview projection", query)
			}
		}
	}
}

func TestOverviewControlEmptyTablesAreExplicitKnownZeros(t *testing.T) {
	f := newOverviewFixture()
	f.tasks = nil
	f.operations = nil
	result, err := overviewReader(t, f).ReadOverviewControl(context.Background())
	if err != nil || len(result.OperationStatusCounts()) != len(operationStatuses) {
		t.Fatal("empty counts", result, err)
	}
	for kind, table := range taskTables {
		counts := result.TaskStatusCounts(kind)
		for status := range table.status {
			count, ok := counts[status]
			if !ok || count != 0 {
				t.Fatal("missing known zero", kind, status)
			}
		}
	}
}

func TestOverviewControlRejectsBrokenState(t *testing.T) {
	for name, mutate := range map[string]func(*overviewFixture){
		"state schema":                          func(f *overviewFixture) { f.state[0] = "future" },
		"cross installation":                    func(f *overviewFixture) { f.state[1] = "installation_other" },
		"config installation":                   func(f *overviewFixture) { f.state[10] = "installation_other" },
		"config version drift":                  func(f *overviewFixture) { f.state[11] = int64(4) },
		"zero state row version":                func(f *overviewFixture) { f.state[3] = int64(0) },
		"unsafe config version":                 func(f *overviewFixture) { f.state[2] = int64(maxJSONSafeInteger + 1); f.state[11] = f.state[2] },
		"unknown matrix":                        func(f *overviewFixture) { f.state[8] = "other" },
		"non UTC database":                      func(f *overviewFixture) { f.state[15] = int64(3600000000) },
		"effective while config disabled":       func(f *overviewFixture) { f.state[5] = true },
		"unarmed after first enable":            func(f *overviewFixture) { f.state[4] = f.state[14].(time.Time).Add(-time.Hour) },
		"armed reason missing":                  func(f *overviewFixture) { f.state[6] = true },
		"previously enabled without first time": func(f *overviewFixture) { f.state[6] = true; f.state[7] = "previously_enabled" },
		"first time in future": func(f *overviewFixture) {
			f.state[4] = f.state[14].(time.Time).Add(time.Hour)
			f.state[6] = true
			f.state[7] = "previously_enabled"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOverviewFixture()
			mutate(f)
			result, err := overviewReader(t, f).ReadOverviewControl(context.Background())
			if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(result, OverviewControlSnapshot{}) || f.commits != 0 || f.rollbacks != 1 {
				t.Fatal("broken state escaped", result, err, f)
			}
		})
	}
}

func TestOverviewControlRejectsInvalidOrIncompleteCounts(t *testing.T) {
	for name, mutate := range map[string]func(*overviewFixture){
		"future task schema":                     func(f *overviewFixture) { f.taskSchema = "system-backup-task.v2" },
		"stored task kind drift":                 func(f *overviewFixture) { f.storedKind = "drill" },
		"future operation schema":                func(f *overviewFixture) { f.operationSchema = "system-backup-operation.v2" },
		"unknown task":                           func(f *overviewFixture) { f.tasks[0][0] = "catalog_scan" },
		"unknown status":                         func(f *overviewFixture) { f.tasks[0][1] = "future" },
		"status from wrong kind":                 func(f *overviewFixture) { f.tasks[0][1] = "restoring" },
		"duplicate task status":                  func(f *overviewFixture) { f.tasks = append(f.tasks, f.tasks[0]) },
		"negative count":                         func(f *overviewFixture) { f.tasks[0][2] = int64(-1) },
		"zero group":                             func(f *overviewFixture) { f.tasks[0][2] = int64(0) },
		"overflow task sum":                      func(f *overviewFixture) { f.tasks[0][2] = int64(maxJSONSafeInteger) },
		"unsafe individual count":                func(f *overviewFixture) { f.tasks[0][2] = int64(maxJSONSafeInteger + 1) },
		"stream failure":                         func(f *overviewFixture) { f.streamError = true },
		"operation status":                       func(f *overviewFixture) { f.operations[0][0] = "finalization_unknown" },
		"duplicate operation status":             func(f *overviewFixture) { f.operations = append(f.operations, f.operations[0]) },
		"overflow operation sum":                 func(f *overviewFixture) { f.operations[0][1] = int64(maxJSONSafeInteger) },
		"negative operation count":               func(f *overviewFixture) { f.operations[0][1] = int64(-1) },
		"zero operation group":                   func(f *overviewFixture) { f.operations[0][1] = int64(0) },
		"operation SQL fails after task success": func(f *overviewFixture) { f.queryError = overviewOperationCountsSQL },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOverviewFixture()
			mutate(f)
			result, err := overviewReader(t, f).ReadOverviewControl(context.Background())
			if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(result, OverviewControlSnapshot{}) || f.commits != 0 || f.rollbacks != 1 {
				t.Fatal("partial/invalid counts escaped", result, err, f)
			}
		})
	}
}

func TestOverviewControlAuthorizationAndCommitFailuresReturnNoPartialData(t *testing.T) {
	permission := errors.New("permission revoked")
	for name, mutate := range map[string]func(*overviewFixture){
		"authorize revoked":             func(f *overviewFixture) { f.authorizeErr = permission },
		"final revoked":                 func(f *overviewFixture) { f.recheckErr = permission },
		"commit unknown":                func(f *overviewFixture) { f.commitErr = errors.New("commit response lost") },
		"missing installation":          func(f *overviewFixture) { f.state = nil },
		"missing with final revocation": func(f *overviewFixture) { f.state = nil; f.recheckErr = permission },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOverviewFixture()
			mutate(f)
			result, err := overviewReader(t, f).ReadOverviewControl(context.Background())
			if err == nil || !reflect.DeepEqual(result, OverviewControlSnapshot{}) {
				t.Fatal("failure exposed data", result, err)
			}
			if f.authorizeErr != nil && len(f.queries) != 0 {
				t.Fatal("queried before authorization")
			}
			if f.state == nil && f.rechecks != 1 {
				t.Fatal("missing row skipped final authority check")
			}
			if f.recheckErr != nil && f.commits != 0 {
				t.Fatal("revoked transaction committed")
			}
			if (f.authorizeErr != nil || f.recheckErr != nil) && !errors.Is(err, permission) {
				t.Fatal("authority error lost", err)
			}
		})
	}
}

func TestOverviewOwnerBuilderSharesTransactionAndCannotCommit(t *testing.T) {
	f := newOverviewFixture()
	r := overviewReader(t, f)
	result, err := readOverviewInTransaction(context.Background(), r, func(ctx context.Context, q overviewReadSQL, control OverviewControlSnapshot) (string, error) {
		f.builds++
		if f.commits != 0 || f.rechecks != 0 {
			t.Fatal("builder outside guarded transaction")
		}
		if _, ok := q.(*sql.Tx); ok {
			t.Fatal("builder received transaction controls")
		}
		if _, ok := q.(interface{ Commit() error }); ok {
			t.Fatal("builder could commit")
		}
		var fact string
		err := q.QueryRowContext(ctx, "SELECT 'owner_fact' WHERE ?", control.InstallationState().InstallationID).Scan(&fact)
		return fact, err
	})
	if err != nil || result != "verified" || f.builds != 1 || f.commits != 1 || f.rechecks != 1 {
		t.Fatal("owner assembly boundary", result, err, f)
	}
	for _, cancelBuild := range []bool{false, true} {
		f := newOverviewFixture()
		r := overviewReader(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		result, err := readOverviewInTransaction(ctx, r, func(context.Context, overviewReadSQL, OverviewControlSnapshot) (string, error) {
			if cancelBuild {
				cancel()
				return "partial", nil
			}
			return "partial", io.ErrUnexpectedEOF
		})
		cancel()
		select {
		case <-f.rollbackDone:
		case <-time.After(time.Second):
			t.Fatal("canceled/failed build did not roll back")
		}
		if err == nil || result != "" || f.commits != 0 || f.rollbacks != 1 {
			t.Fatal("builder failure/cancellation exposed partial result", result, err, f)
		}
	}
}
