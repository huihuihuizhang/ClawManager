package systembackupresources

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
)

type countFixture struct {
	engines    map[string]string
	rows       map[string]int64
	auditMaxID driver.Value
	failure    string
	queries    []string
	begin      driver.TxOptions
	commits    int
	rollbacks  int
}

type countConnector struct{ state *countFixture }

func (c countConnector) Connect(context.Context) (driver.Conn, error) {
	return &countConn{c.state}, nil
}
func (c countConnector) Driver() driver.Driver { return countDriver{c.state} }

type countDriver struct{ state *countFixture }

func (d countDriver) Open(string) (driver.Conn, error) { return &countConn{d.state}, nil }

type countConn struct{ state *countFixture }

func (c *countConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *countConn) Close() error              { return nil }
func (c *countConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected Begin") }
func (c *countConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.state.begin = opts
	return countTx{c.state}, nil
}
func (c *countConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.queries = append(c.state.queries, query)
	if strings.Contains(query, "information_schema.TABLES") {
		if len(args) != 1 {
			return nil, errors.New("engine query must bind one table")
		}
		table, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("invalid engine table argument")
		}
		if c.state.failure == "engine:"+table {
			return nil, errors.New("injected engine query failure")
		}
		engine, ok := c.state.engines[table]
		if !ok {
			return &countRows{columns: []string{"ENGINE"}}, nil
		}
		return &countRows{columns: []string{"ENGINE"}, values: [][]driver.Value{{engine}}}, nil
	}
	if query == "SELECT COUNT(*), MAX(id) FROM `audit_logs`" {
		if len(args) != 0 {
			return nil, errors.New("audit count query must have no argument")
		}
		if c.state.failure == "count:audit_logs" {
			return nil, errors.New("injected audit count query failure")
		}
		return &countRows{columns: []string{"COUNT(*)", "MAX(id)"}, values: [][]driver.Value{{c.state.rows["audit_logs"], c.state.auditMaxID}}}, nil
	}
	for table, rows := range c.state.rows {
		if query == "SELECT COUNT(*) FROM `"+table+"`" {
			if len(args) != 0 {
				return nil, errors.New("count query must have no argument")
			}
			if c.state.failure == "count:"+table {
				return nil, errors.New("injected count query failure")
			}
			return &countRows{columns: []string{"COUNT(*)"}, values: [][]driver.Value{{rows}}}, nil
		}
	}
	return nil, fmt.Errorf("unexpected query %q", query)
}

type countTx struct{ state *countFixture }

func (t countTx) Commit() error {
	t.state.commits++
	if t.state.failure == "commit" {
		return errors.New("injected commit failure")
	}
	return nil
}
func (t countTx) Rollback() error { t.state.rollbacks++; return nil }

type countRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *countRows) Columns() []string { return r.columns }
func (r *countRows) Close() error      { return nil }
func (r *countRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

func newCountFixture() *countFixture {
	f := &countFixture{engines: map[string]string{}, rows: map[string]int64{}, auditMaxID: int64(1)}
	for table := range resourceTables {
		f.engines[table] = "InnoDB"
		f.rows[table] = 1
	}
	return f
}

func countDatabase(t *testing.T, state *countFixture) *sql.DB {
	t.Helper()
	db := sql.OpenDB(countConnector{state})
	t.Cleanup(func() { db.Close() })
	return db
}

func frozenRegistryBytes(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(frozenFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSQLCountCollectorReadsOneCompleteSnapshot(t *testing.T) {
	state := newCountFixture()
	state.rows["audit_logs"] = 100000
	state.auditMaxID = int64(100005)
	snapshot, err := (SQLCountCollector{DB: countDatabase(t, state)}).CollectSnapshot(context.Background(), frozenRegistryBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	counts := snapshot.Tables
	if len(counts) != len(resourceTables) || counts[0] != (TableCount{Table: "audit_logs", Rows: 100000}) {
		t.Fatalf("unexpected redacted counts: %+v", counts)
	}
	if snapshot.AuditMaxID == nil || *snapshot.AuditMaxID != 100005 {
		t.Fatalf("audit cutoff not captured in source snapshot: %+v", snapshot)
	}
	if state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !state.begin.ReadOnly {
		t.Fatalf("not a read-only repeatable-read snapshot: %+v", state.begin)
	}
	if state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 2*len(resourceTables) {
		t.Fatalf("incomplete snapshot: commits=%d rollbacks=%d queries=%d", state.commits, state.rollbacks, len(state.queries))
	}
	for _, query := range state.queries {
		if !strings.HasPrefix(query, "SELECT ") || strings.Contains(query, "system_backup_") {
			t.Fatalf("out-of-scope query: %s", query)
		}
	}
	gotTables := make([]string, 0, len(counts))
	for _, count := range counts {
		gotTables = append(gotTables, count.Table)
	}
	wantTables, _ := CaptureTableAllowlist(frozenRegistryBytes(t))
	if !reflect.DeepEqual(gotTables, wantTables) {
		t.Fatalf("table order=%v, want=%v", gotTables, wantTables)
	}
}

func TestSQLCountCollectorEmptyAuditHasNoCutoff(t *testing.T) {
	state := newCountFixture()
	state.rows["audit_logs"] = 0
	state.auditMaxID = nil
	snapshot, err := (SQLCountCollector{DB: countDatabase(t, state)}).CollectSnapshot(context.Background(), frozenRegistryBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AuditMaxID != nil || snapshot.Tables[0] != (TableCount{Table: "audit_logs", Rows: 0}) {
		t.Fatalf("empty audit snapshot has a cutoff: %+v", snapshot)
	}
}

func TestSQLCountCollectorRejectsDraftBeforeDatabaseAccess(t *testing.T) {
	state := newCountFixture()
	data, err := json.Marshal(currentRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	counts, err := (SQLCountCollector{DB: countDatabase(t, state)}).Collect(context.Background(), data)
	if err == nil || counts != nil || len(state.queries) != 0 {
		t.Fatalf("draft admitted: counts=%v err=%v queries=%v", counts, err, state.queries)
	}
}

func TestSQLCountCollectorRejectsPendingSchemaEvidenceBeforeDatabaseAccess(t *testing.T) {
	state := newCountFixture()
	document := frozenFixture(t)
	document["schema_hash"].(map[string]any)["status"] = "pending_live_evidence"
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := (SQLCountCollector{DB: countDatabase(t, state)}).Collect(context.Background(), data)
	if err == nil || counts != nil || len(state.queries) != 0 || state.commits != 0 || state.rollbacks != 0 {
		t.Fatalf("pending schema evidence reached database: counts=%v err=%v queries=%v", counts, err, state.queries)
	}
}

func TestSQLCountCollectorFailsWithoutPartialCounts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*countFixture)
	}{
		{"nontransactional", func(f *countFixture) { f.engines["audit_logs"] = "MyISAM" }},
		{"missing table", func(f *countFixture) { delete(f.engines, "audit_logs") }},
		{"negative count", func(f *countFixture) { f.rows["audit_logs"] = -1 }},
		{"nonempty audit without cutoff", func(f *countFixture) { f.auditMaxID = nil }},
		{"empty audit with cutoff", func(f *countFixture) { f.rows["audit_logs"] = 0 }},
		{"negative audit cutoff", func(f *countFixture) { f.auditMaxID = int64(-1) }},
		{"count failure", func(f *countFixture) { f.failure = "count:audit_logs" }},
		{"commit failure", func(f *countFixture) { f.failure = "commit" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newCountFixture()
			tc.alter(state)
			counts, err := (SQLCountCollector{DB: countDatabase(t, state)}).Collect(context.Background(), frozenRegistryBytes(t))
			if err == nil || counts != nil {
				t.Fatalf("invalid snapshot returned counts=%v err=%v", counts, err)
			}
			if tc.name != "commit failure" && state.commits != 0 {
				t.Fatalf("partial snapshot committed: %d", state.commits)
			}
		})
	}
}
