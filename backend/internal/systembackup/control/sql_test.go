package control

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type sqlStep struct {
	contains  string
	rows      [][]driver.Value
	affected  int64
	checkArgs func([]driver.NamedValue)
}
type scriptDB struct {
	t                          *testing.T
	steps                      []sqlStep
	commits, rollbacks, writes int
	loseCommit                 bool
}
type scriptConnector struct{ s *scriptDB }

func (c scriptConnector) Connect(context.Context) (driver.Conn, error) { return &scriptConn{c.s}, nil }
func (c scriptConnector) Driver() driver.Driver                        { return scriptDriver{c.s} }

type scriptDriver struct{ s *scriptDB }

func (d scriptDriver) Open(string) (driver.Conn, error) { return &scriptConn{d.s}, nil }

type scriptConn struct{ s *scriptDB }

func (c *scriptConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (c *scriptConn) Close() error                                                 { return nil }
func (c *scriptConn) Begin() (driver.Tx, error)                                    { return c, nil }
func (c *scriptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c, nil }
func (c *scriptConn) Commit() error {
	c.s.commits++
	if c.s.loseCommit {
		c.s.loseCommit = false
		return errors.New("commit reply lost")
	}
	return nil
}
func (c *scriptConn) Rollback() error { c.s.rollbacks++; return nil }
func (c *scriptConn) step(query string) (sqlStep, error) {
	if len(c.s.steps) == 0 || !strings.Contains(query, c.s.steps[0].contains) {
		c.s.t.Errorf("unexpected SQL statement: %s", query)
		return sqlStep{}, errors.New("unexpected SQL")
	}
	p := c.s.steps[0]
	c.s.steps = c.s.steps[1:]
	return p, nil
}
func (c *scriptConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	p, e := c.step(q)
	if p.checkArgs != nil {
		p.checkArgs(args)
	}
	return &scriptRows{rows: p.rows}, e
}
func (c *scriptConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	p, e := c.step(q)
	if p.checkArgs != nil {
		p.checkArgs(args)
	}
	if e == nil {
		c.s.writes++
	}
	return driver.RowsAffected(p.affected), e
}

type scriptRows struct{ rows [][]driver.Value }

func (r *scriptRows) Columns() []string {
	n := 13
	if len(r.rows) > 0 {
		n = len(r.rows[0])
	}
	out := make([]string, n)
	for i := range out {
		out[i] = "field"
	}
	return out
}
func (r *scriptRows) Close() error { return nil }
func (r *scriptRows) Next(out []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(out, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}
func taskRow(t Task) []driver.Value {
	b, _ := json.Marshal(t.Request)
	return []driver.Value{t.ID, int64(t.Actor), b, t.Status, t.CanCancel, t.RowVersion, t.Generation, t.Owner, t.LeaseUntil, t.CreatedAt, t.Deadline, t.FailureCode, t.ProfileRevision}
}
func scriptStore(t *testing.T, steps ...sqlStep) (SQLStore, *scriptDB) {
	t.Helper()
	s := &scriptDB{t: t, steps: steps}
	database := sql.OpenDB(scriptConnector{s})
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		database.Close()
		if len(s.steps) > 0 {
			t.Errorf("unconsumed SQL steps: %d", len(s.steps))
		}
	})
	return SQLStore{database}, s
}
func TestSQLCreateAdmissionIdempotencyAndLostCommit(t *testing.T) {
	request := testTask().Request
	profile, _ := json.Marshal(Profile{ID: "fixture", Revision: strings.Repeat("a", 64), Kinds: []string{"backup"}, Ready: true})
	steps := []sqlStep{{contains: "WHERE actor_id=? AND idempotency_key=? FOR UPDATE"}, {contains: "system_backup_profiles", rows: [][]driver.Value{{profile, true}}}, {contains: "SELECT " + dbNow, rows: [][]driver.Value{{int64(1000)}}}, {contains: "INSERT INTO system_backup_tasks", affected: 1}, {contains: "INSERT INTO system_backup_v2_events", affected: 1}}
	store, script := scriptStore(t, steps...)
	script.loseCommit = true
	if _, e := store.Create(context.Background(), 1, "request-1", request, time.Hour); !errors.Is(e, ErrNotReady) {
		t.Fatal("uncertain commit reported success", e)
	}
	existing := testTask()
	existing.ID = "sb-persisted"
	existing.Status = "capturing"
	// The server committed despite a lost reply. Repeating the key finds the
	// original task before inspecting current dependency health or inserting.
	script.steps = append(script.steps, sqlStep{contains: "WHERE actor_id=? AND idempotency_key=? FOR UPDATE", rows: [][]driver.Value{taskRow(existing)}})
	task, e := store.Create(context.Background(), 1, "request-1", request, time.Hour)
	if e != nil || task.ID != existing.ID || script.writes != 2 {
		t.Fatal("idempotent replay duplicated task", e)
	}
	script.steps = append(script.steps, sqlStep{contains: "WHERE actor_id=? AND idempotency_key=? FOR UPDATE", rows: [][]driver.Value{taskRow(existing)}})
	changed := request
	changed.Profile = "different"
	if _, e = store.Create(context.Background(), 1, "request-1", changed, time.Hour); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestSQLAdmissionRejectsStaleControllerBeforeInsert(t *testing.T) {
	store, script := scriptStore(t, sqlStep{contains: "idempotency_key=? FOR UPDATE"}, sqlStep{contains: "system_backup_profiles", rows: [][]driver.Value{{[]byte(`{}`), false}}})
	if _, e := store.Create(context.Background(), 1, "request", testTask().Request, time.Hour); !errors.Is(e, ErrNotReady) || script.writes != 0 {
		t.Fatal(e)
	}
}
func TestSQLMutationPermitCannotEnterClosedGate(t *testing.T) {
	store, script := scriptStore(t, sqlStep{contains: "SELECT closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE", rows: [][]driver.Value{{true}}})
	if release, e := store.Enter(context.Background(), "api-request"); !errors.Is(e, ErrConflict) || release != nil || script.writes != 0 {
		t.Fatal("closed gate admitted writer")
	}
}
func TestSQLMutationPermitPersistsUntilActualCompletion(t *testing.T) {
	store, script := scriptStore(t, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{{false}}}, sqlStep{contains: "INSERT INTO system_backup_mutations", affected: 1}, sqlStep{contains: "DELETE FROM system_backup_mutations WHERE token=?", affected: 1})
	release, e := store.Enter(context.Background(), "async-operation")
	if e != nil || script.commits != 1 || script.writes != 1 {
		t.Fatal(e)
	}
	if e = release(); e != nil || script.writes != 2 {
		t.Fatal("permit not released after completion", e)
	}
}
func TestSQLTerminalRejectsUnrecoveredSource(t *testing.T) {
	task := testTask()
	task.Owner = "controller"
	task.Generation = 1
	task.Status = "publishing"
	task.LeaseUntil = 10000
	store, script := scriptStore(t, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{int64(1000)}}}, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT (SELECT COUNT(*) FROM system_backup_pauses", rows: [][]driver.Value{{int64(1)}}})
	if _, e := store.Advance(context.Background(), task, "succeeded", ""); !errors.Is(e, ErrConflict) || script.writes != 0 {
		t.Fatal("stranded source marked successful", e)
	}
}
func TestSQLExpiredOwnerCannotCommitOrChangeResources(t *testing.T) {
	task := testTask()
	task.Owner = "controller"
	task.Generation = 1
	task.LeaseUntil = 999
	store, script := scriptStore(t, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{int64(1000)}}})
	if _, e := store.Advance(context.Background(), task, "preparing", ""); !errors.Is(e, ErrFence) || script.writes != 0 {
		t.Fatal("expired owner wrote", e)
	}
}

func TestSQLTerminalRequiresIdentityAndCredentialCleanup(t *testing.T) {
	for _, table := range []string{"system_backup_credentials WHERE task_id=? AND removed=FALSE", "system_backup_identities WHERE task_id=? AND deleted=FALSE"} {
		task, _, _ := grantFixture()
		task.Status = "verifying"
		steps := append(workerCommit(task), sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: table, rows: [][]driver.Value{{int64(1)}}})
		store, script := scriptStore(t, steps...)
		if _, e := store.Advance(context.Background(), task, "succeeded", ""); e != ErrConflict || script.writes != 0 {
			t.Fatal("task completed with outstanding credentials", e)
		}
	}
}
