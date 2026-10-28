package systembackupapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"testing"

	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// Transaction-driver model only. This tests the real D transaction owner and
// capability shutdown, not MySQL schema, A authentication or B/C execution.
type submissionDB struct {
	order                                         []string
	pending, writes, commits, rollbacks, dispatch int
	execFail, commitUnknown                       bool
}
type submissionConnector struct{ state *submissionDB }

func (c submissionConnector) Connect(context.Context) (driver.Conn, error) {
	return &submissionConn{state: c.state}, nil
}
func (c submissionConnector) Driver() driver.Driver { return submissionDriver{c.state} }

type submissionDriver struct{ state *submissionDB }

func (d submissionDriver) Open(string) (driver.Conn, error) {
	return &submissionConn{state: d.state}, nil
}

type submissionConn struct{ state *submissionDB }

func (c *submissionConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *submissionConn) Close() error                        { return nil }
func (c *submissionConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *submissionConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	if options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("wrong isolation")
	}
	c.state.order = append(c.state.order, "begin")
	return submissionTx{c.state}, nil
}
func (c *submissionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.state.dispatch++
	if c.state.execFail {
		return nil, errors.New("synthetic driver failure")
	}
	c.state.pending++
	return driver.RowsAffected(1), nil
}
func (c *submissionConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.state.dispatch++
	return &submissionRows{}, nil
}

type submissionRows struct{ done bool }

func (*submissionRows) Columns() []string { return []string{"one"} }
func (*submissionRows) Close() error      { return nil }
func (r *submissionRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	values[0] = int64(1)
	return nil
}

type submissionTx struct{ state *submissionDB }

func (tx submissionTx) Commit() error {
	tx.state.order = append(tx.state.order, "commit")
	tx.state.commits++
	tx.state.writes += tx.state.pending
	tx.state.pending = 0
	if tx.state.commitUnknown {
		return errors.New("synthetic unknown commit")
	}
	return nil
}
func (tx submissionTx) Rollback() error {
	tx.state.order = append(tx.state.order, "rollback")
	tx.state.rollbacks++
	tx.state.pending = 0
	return nil
}

type submissionScope struct {
	state   *submissionDB
	deny    bool
	recheck func()
}

func (s submissionScope) AuthorizeAction(context.Context, *sql.Tx) (string, error) {
	s.state.order = append(s.state.order, "authorize")
	return "installation_model", nil
}
func (s submissionScope) RecheckAction(context.Context, *sql.Tx, string) error {
	s.state.order = append(s.state.order, "recheck")
	if s.recheck != nil {
		s.recheck()
	}
	if s.deny {
		return security.ErrRegistrationPermission
	}
	return nil
}
func (submissionScope) Actor() security.RegistrationActor {
	return security.RegistrationActor{UserID: 7}
}
func (submissionScope) IdempotencyKey() string { return "model-key-123456789" }

type submissionPlan func(TaskWriteSQL, TaskSubmissionIdentity) (read.TaskHeader, error)

func (f submissionPlan) Stage(q TaskWriteSQL, id TaskSubmissionIdentity) (read.TaskHeader, error) {
	return f(q, id)
}

func TestSQLTaskSubmissionOwnsCommitRollbackAndCapabilityLifetime(t *testing.T) {
	for _, mode := range []string{"success", "stage_failure", "revoked_after_stage", "ignored_sql_error", "retained_write", "retained_copy", "retained_row", "commit_unknown", "wrong_actor"} {
		t.Run(mode, func(t *testing.T) {
			state := &submissionDB{execFail: mode == "ignored_sql_error", commitUnknown: mode == "commit_unknown"}
			db := sql.OpenDB(submissionConnector{state})
			defer db.Close()
			app := &SQLApplication{db: db}
			var retained TaskWriteSQL
			var row TaskRow
			scope := submissionScope{state: state, deny: mode == "revoked_after_stage"}
			if mode == "retained_write" || mode == "retained_copy" {
				scope.recheck = func() {
					before := state.dispatch
					_, _ = retained.Exec("INSERT INTO model_task VALUES (1)")
					if state.dispatch != before {
						t.Fatal("late SQL dispatched")
					}
				}
			}
			if mode == "retained_row" {
				scope.recheck = func() {
					var value int
					if row.Scan(&value) == nil {
						t.Fatal("late row scan accepted")
					}
				}
			}
			plan := submissionPlan(func(q TaskWriteSQL, identity TaskSubmissionIdentity) (read.TaskHeader, error) {
				state.order = append(state.order, "stage")
				retained = q
				if mode == "retained_copy" {
					copy := reflect.New(reflect.TypeOf(q).Elem())
					copy.Elem().Set(reflect.ValueOf(q).Elem())
					retained = copy.Interface().(TaskWriteSQL)
				}
				if identity.InstallationID != "installation_model" || identity.ActorID != "7" || identity.Endpoint != "createSystemBackupPreflight" || identity.IdempotencyKey != scope.IdempotencyKey() {
					t.Fatal("trusted identity changed")
				}
				if mode == "retained_row" {
					row = q.QueryRow("SELECT 1")
				} else {
					var value int
					if q.QueryRow("SELECT 1").Scan(&value) != nil || value != 1 {
						t.Fatal("query not bound")
					}
				}
				_, err := q.Exec("INSERT INTO model_task VALUES (1)")
				if err != nil && mode != "ignored_sql_error" {
					return read.TaskHeader{}, err
				}
				m := &taskModel{tasks: map[string]read.TaskHeader{}}
				task, err := m.CreateAndEnqueue(createRequest("{}"), read.PreflightTask, "createSystemBackupPreflight", scope.IdempotencyKey(), []byte("{}"))
				if mode == "stage_failure" {
					return read.TaskHeader{}, &Error{"capacity_exceeded"}
				}
				if mode == "wrong_actor" {
					task.ActorID = "99"
				}
				return task, err
			})
			task, err := app.submit(context.Background(), scope, plan, read.PreflightTask, "createSystemBackupPreflight", scope.IdempotencyKey())
			if mode == "success" {
				if err != nil || task.PublicID == "" || state.commits != 1 || state.writes != 1 || state.rollbacks != 0 {
					t.Fatalf("bad commit %#v %v", state, err)
				}
			} else {
				if err == nil || task.PublicID != "" {
					t.Fatal("failure published a task")
				}
				if mode == "commit_unknown" {
					if state.commits != 1 || state.writes != 1 || state.rollbacks != 0 {
						t.Fatal("unknown commit fabricated rollback/retried")
					}
				} else if state.commits != 0 || state.writes != 0 || state.rollbacks != 1 {
					t.Fatalf("failure did not roll back %#v", state)
				}
			}
			before := state.dispatch
			if _, err := retained.Exec("INSERT INTO model_task VALUES (2)"); err == nil || state.dispatch != before {
				t.Fatal("retained SQL remained open")
			}
			if len(state.order) < 3 || state.order[0] != "begin" || state.order[1] != "authorize" || state.order[2] != "stage" {
				t.Fatal("business work preceded A authority", state.order)
			}
		})
	}
}

func TestTaskSQLCapabilityRejectsTransactionControlAndLatchesFailure(t *testing.T) {
	state := &submissionDB{}
	db := sql.OpenDB(submissionConnector{state})
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	q := newTaskSQLCapability(context.Background(), tx)
	for _, query := range []string{"COMMIT", "ROLLBACK", "SET autocommit=1", "START TRANSACTION", "SELECT 1; COMMIT", "/* hidden */ COMMIT"} {
		if _, err := q.Exec(query); err == nil {
			t.Fatal("transaction control accepted", query)
		}
	}
	if state.dispatch != 0 || q.close() {
		t.Fatal("ignored transaction-control error was not latched")
	}
}
