package kube

// Tests execute the mapped SQL adapter through database/sql with a transactional
// test driver. No network, migration or real control database is involved.
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type journalSQLState struct {
	records             map[string][]driver.Value
	commits, rollbacks  int
	loseCommit, failCAS bool
}
type journalConnector struct{ s *journalSQLState }

func (c journalConnector) Connect(context.Context) (driver.Conn, error) {
	return &journalConn{s: c.s}, nil
}
func (c journalConnector) Driver() driver.Driver { return journalDriver{} }

type journalDriver struct{}

func (journalDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type journalConn struct {
	s       *journalSQLState
	pending map[string][]driver.Value
}

func (c *journalConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *journalConn) Close() error { return nil }
func (c *journalConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction required")
}
func (c *journalConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelSerializable) {
		return nil, errors.New("wrong transaction")
	}
	c.pending = map[string][]driver.Value{}
	for k, v := range c.s.records {
		c.pending[k] = append([]driver.Value(nil), v...)
	}
	return journalTx{c}, nil
}

type journalTx struct{ c *journalConn }

func (t journalTx) Commit() error {
	t.c.s.records = t.c.pending
	t.c.pending = nil
	t.c.s.commits++
	if t.c.s.loseCommit {
		t.c.s.loseCommit = false
		return errors.New("commit reply lost")
	}
	return nil
}
func (t journalTx) Rollback() error { t.c.pending = nil; t.c.s.rollbacks++; return nil }
func journalKey(args []driver.NamedValue) string {
	var values []string
	for _, a := range args {
		values = append(values, a.Value.(string))
	}
	return strings.Join(values, "/")
}

type journalResultRows struct {
	data []driver.Value
	done bool
}

func (r *journalResultRows) Columns() []string {
	return []string{"owner", "hash", "request", "revision", "dispatched", "uid", "rv", "lifecycle"}
}
func (r *journalResultRows) Close() error { return nil }
func (r *journalResultRows) Next(dst []driver.Value) error {
	if r.done || r.data == nil {
		return io.EOF
	}
	r.done = true
	copy(dst, r.data)
	return nil
}
func (c *journalConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.pending == nil || !strings.HasSuffix(q, " FOR UPDATE") || len(args) != 4 {
		return nil, errors.New("unlocked read")
	}
	return &journalResultRows{data: c.pending[journalKey(args)]}, nil
}
func (c *journalConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.pending == nil {
		return nil, errors.New("write without transaction")
	}
	if strings.HasPrefix(q, "INSERT INTO ") && len(args) == 12 {
		key := journalKey(args[:4])
		if c.pending[key] != nil {
			return driver.RowsAffected(0), nil
		}
		var values []driver.Value
		for _, a := range args[4:] {
			values = append(values, a.Value)
		}
		c.pending[key] = values
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, "UPDATE ") && len(args) == 11 {
		key := journalKey(args[5:9])
		v := c.pending[key]
		if c.s.failCAS || v == nil || v[3] != args[9].Value || v[1] != args[10].Value {
			return driver.RowsAffected(0), nil
		}
		for idx, a := range args[:5] {
			v[3+idx] = a.Value
		}
		c.pending[key] = v
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unexpected SQL")
}
func journalColumns() ResourceColumns {
	return ResourceColumns{Scope: "task_scope", Kind: "kind", Namespace: "namespace", Name: "name", Owner: "owner", RequestHash: "request_hash", RequestJSON: "request_json", Revision: "row_version", Dispatched: "dispatch_intent", UID: "uid", ResourceVersion: "resource_version", Lifecycle: "lifecycle"}
}
func sqlJournalFixture(t *testing.T) (SQLJournal, *journalSQLState, ResourceIntent) {
	t.Helper()
	s := &journalSQLState{records: map[string][]driver.Value{}}
	db := sql.OpenDB(journalConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	rows, err := NewMappedResourceRows("drill/task-1", "fixture_resource_projection", "created", journalColumns())
	if err != nil {
		t.Fatal(err)
	}
	j := SQLJournal{DB: db, Rows: rows, Fence: func(context.Context, *sql.Tx) error { return nil }}
	_, _, _, job := runnerFixture(t)
	i, _, err := freeze("Job", job)
	if err != nil {
		t.Fatal(err)
	}
	return j, s, i
}
func TestSQLJournalReopensCASAndKeepsImmutableIntent(t *testing.T) {
	j, s, i := sqlJournalFixture(t)
	ctx := context.Background()
	r, err := j.Prepare(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.records) != 1 || r.Revision != 1 {
		t.Fatal("intent not persisted")
	}
	if _, err = j.Observe(ctx, r, "uid", "1"); err == nil {
		t.Fatal("observed without dispatch")
	}
	created, err := j.RecordCreate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.RecordCreate(ctx, r); err == nil {
		t.Fatal("stale revision accepted")
	}
	// A new journal/session uses the same authoritative rows, not process state.
	db2 := sql.OpenDB(journalConnector{s})
	defer db2.Close()
	j2 := SQLJournal{DB: db2, Rows: j.Rows, Fence: j.Fence}
	r, err = j2.Prepare(ctx, i)
	if err != nil || !sameRecord(r, created) {
		t.Fatal("restart lost intent", err)
	}
	r, err = j2.Observe(ctx, r, "uid", "2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j2.Observe(ctx, r, "replacement", "3"); err == nil {
		t.Fatal("UID replacement accepted")
	}
	r, err = j2.RecordDelete(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = j2.RecordAbsent(ctx, r); err != nil {
		t.Fatal(err)
	}
	r, err = j2.Prepare(ctx, i)
	if err != nil || !r.Deleted {
		t.Fatal("cleanup not durable", err)
	}
	if _, err = j2.RecordCreate(ctx, r); err == nil {
		t.Fatal("deleted resource recreated")
	}
	i.RequestJSON = append([]byte(nil), i.RequestJSON...)
	i.RequestJSON[0] = '['
	if _, err = j2.Prepare(ctx, i); err == nil {
		t.Fatal("invalid request accepted")
	}
}
func TestSQLJournalFenceAndCASFailuresRollback(t *testing.T) {
	j, s, i := sqlJournalFixture(t)
	ctx := context.Background()
	calls := 0
	j.Fence = func(context.Context, *sql.Tx) error {
		calls++
		if calls == 2 {
			return errors.New("lost")
		}
		return nil
	}
	if _, err := j.Prepare(ctx, i); err == nil {
		t.Fatal("lost fence committed")
	}
	if len(s.records) != 0 || s.rollbacks != 1 {
		t.Fatal("journal write did not roll back")
	}
	j.Fence = func(context.Context, *sql.Tx) error { return nil }
	r, err := j.Prepare(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	s.failCAS = true
	if _, err = j.RecordCreate(ctx, r); err == nil {
		t.Fatal("CAS conflict ignored")
	}
	s.failCAS = false
	n, err := j.Prepare(ctx, i)
	if err != nil || !sameRecord(n, r) {
		t.Fatal("CAS conflict changed row")
	}
	r, err = j.RecordCreate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.RecordAbsent(ctx, r); !errors.Is(err, ErrPending) {
		t.Fatal("uncertain create marked absent")
	}
}
func TestSQLJournalLostCommitReplyReconciles(t *testing.T) {
	j, s, i := sqlJournalFixture(t)
	ctx := context.Background()
	r, err := j.Prepare(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	r, err = j.RecordCreate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	s.loseCommit = true
	if _, err = j.Observe(ctx, r, "uid", "1"); err == nil {
		t.Fatal("lost response reported success")
	}
	n, err := j.Prepare(ctx, i)
	if err != nil || n.UID != "uid" || n.Revision != r.Revision+1 {
		t.Fatal("cannot reconcile persisted observation", err)
	}
}
func TestSQLJournalRequiresExplicitSafeColumnMapping(t *testing.T) {
	c := journalColumns()
	if _, err := NewMappedResourceRows("task", "bad; DROP TABLE users", "created", c); err == nil {
		t.Fatal("SQL identifier injection")
	}
	c.UID = c.Name
	if _, err := NewMappedResourceRows("task", "fixture", "created", c); err == nil {
		t.Fatal("duplicate mapping")
	}
}
