package domain

// This deliberately small SQL driver exercises the actual database/sql paths,
// parameter bindings and transaction boundaries without a network connection.
// It is not a substitute for the separately documented MySQL 8 integration gate.
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
)

type memoryDB struct {
	wildcardGrants                             bool // explicit fixture default: partial_revokes=ON
	tables                                     []Table
	name, uuid, grants, failInsert             string
	writes, commits, rollbacks, readOnlyBegins int
}
type connector struct{ s *memoryDB }

func (c connector) Connect(context.Context) (driver.Conn, error) { return &memoryConn{s: c.s}, nil }
func (c connector) Driver() driver.Driver                        { return testDriver{} }

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type memoryConn struct {
	s              *memoryDB
	before         []Table
	inTx, readOnly bool
}

func (c *memoryConn) Close() error                          { return nil }
func (c *memoryConn) Prepare(q string) (driver.Stmt, error) { return &memoryStmt{c, q}, nil }
func (c *memoryConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *memoryConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.inTx = true
	c.readOnly = o.ReadOnly
	if o.ReadOnly {
		c.s.readOnlyBegins++
	}
	c.before = copyTables(c.s.tables)
	return memoryTx{c}, nil
}
func copyTables(tables []Table) []Table {
	out := append([]Table(nil), tables...)
	for i := range out {
		out[i].Rows = nil
		for _, r := range tables[i].Rows {
			out[i].Rows = append(out[i].Rows, cloneRow(r))
		}
	}
	return out
}

type memoryTx struct{ c *memoryConn }

func (t memoryTx) Commit() error { t.c.inTx = false; t.c.s.commits++; return nil }
func (t memoryTx) Rollback() error {
	t.c.s.tables = t.c.before
	t.c.inTx = false
	t.c.s.rollbacks++
	return nil
}

type memoryRows struct {
	columns []string
	data    [][]driver.Value
	offset  int
}

func (r *memoryRows) Columns() []string { return r.columns }
func (r *memoryRows) Close() error      { return nil }
func (r *memoryRows) Next(dest []driver.Value) error {
	if r.offset >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.offset])
	r.offset++
	return nil
}
func rows(columns []string, data ...[]driver.Value) driver.Rows {
	return &memoryRows{columns: columns, data: data}
}
func (c *memoryConn) table(name string) *Table {
	for i := range c.s.tables {
		if c.s.tables[i].Name == name {
			return &c.s.tables[i]
		}
	}
	return nil
}
func one(n int) driver.Rows { return rows([]string{"n"}, []driver.Value{int64(n)}) }
func (c *memoryConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case q == "SELECT @@GLOBAL.partial_revokes":
		if c.s.wildcardGrants {
			return one(0), nil
		}
		return one(1), nil
	case q == "SELECT DATABASE(), @@server_uuid":
		return rows([]string{"database", "uuid"}, []driver.Value{c.s.name, c.s.uuid}), nil
	case q == "SHOW GRANTS FOR CURRENT_USER":
		return rows([]string{"grant"}, []driver.Value{c.s.grants}), nil
	case strings.HasPrefix(q, "SELECT TABLE_NAME,"):
		var data [][]driver.Value
		for _, t := range c.s.tables {
			data = append(data, []driver.Value{t.Name, t.Engine})
		}
		return rows([]string{"table", "engine"}, data...), nil
	case strings.HasPrefix(q, "SELECT COLUMN_NAME, COLUMN_TYPE"):
		t := c.table(args[0].Value.(string))
		var data [][]driver.Value
		for _, col := range t.Columns {
			nullable := "NO"
			if col.Nullable {
				nullable = "YES"
			}
			var def driver.Value
			if col.Default != nil {
				def = *col.Default
			}
			data = append(data, []driver.Value{col.Name, col.Type, nullable, def, col.Extra})
		}
		return rows([]string{"name", "type", "nullable", "default", "extra"}, data...), nil
	case strings.HasPrefix(q, "SELECT COLUMN_NAME, CONSTRAINT_NAME"):
		t := c.table(args[0].Value.(string))
		var data [][]driver.Value
		for _, pk := range t.PrimaryKey {
			data = append(data, []driver.Value{pk, "PRIMARY", nil, nil})
		}
		for _, fk := range t.ForeignKeys {
			data = append(data, []driver.Value{fk.Column, "fk", fk.Table, fk.Reference})
		}
		return rows([]string{"column", "constraint", "ref_table", "ref_column"}, data...), nil
	case strings.HasPrefix(q, "SELECT INDEX_NAME, COLUMN_NAME"):
		var data [][]driver.Value
		for _, key := range c.table(args[0].Value.(string)).UniqueKeys {
			for i, col := range key.Columns {
				data = append(data, []driver.Value{key.Name, col, int64(i + 1), nil})
			}
		}
		return rows([]string{"name", "column", "sequence", "prefix"}, data...), nil
	case strings.Contains(q, "information_schema.TRIGGERS"):
		return one(0), nil
	case q == "SELECT COUNT(*) FROM `users` WHERE username = 'admin' AND role = 'admin'":
		n := 0
		for _, r := range c.table("users").Rows {
			if r["username"].String() == "admin" && r["role"].String() == "admin" {
				n++
			}
		}
		return one(n), nil
	case strings.HasPrefix(q, "SELECT COUNT(*) FROM `user_quotas` q"):
		n := 0
		for _, r := range c.table("user_quotas").Rows {
			found := false
			for _, u := range c.table("users").Rows {
				if u["id"].String() == r["user_id"].String() && u["username"].String() == "admin" && u["role"].String() == "admin" {
					found = true
				}
			}
			if !found {
				n++
			}
		}
		return one(n), nil
	case strings.HasPrefix(q, "SELECT COUNT(*) FROM "):
		n := strings.Trim(strings.TrimPrefix(q, "SELECT COUNT(*) FROM "), "`")
		table := c.table(n)
		if table == nil {
			return nil, errors.New("missing table")
		}
		return one(len(table.Rows)), nil
	case strings.HasPrefix(q, "SELECT `"):
		parts := strings.SplitN(strings.TrimPrefix(q, "SELECT "), " FROM ", 2)
		if len(parts) != 2 {
			return nil, errors.New("query")
		}
		tableName := strings.Split(parts[1], " ")[0]
		t := c.table(strings.Trim(tableName, "`"))
		if t == nil {
			return nil, errors.New("table")
		}
		names := strings.Split(parts[0], ",")
		for i := range names {
			names[i] = strings.Trim(names[i], "`")
		}
		var data [][]driver.Value
		ordered := append([]Row(nil), t.Rows...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i]["id"].String() < ordered[j]["id"].String() })
		for _, r := range ordered {
			var values []driver.Value
			for _, n := range names {
				v := r[n]
				if v.Null {
					values = append(values, nil)
				} else {
					values = append(values, append([]byte{}, v.Bytes...))
				}
			}
			data = append(data, values)
		}
		return rows(names, data...), nil
	default:
		return nil, fmt.Errorf("unsupported fixture query: %s", q)
	}
}
func (c *memoryConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !c.inTx || c.readOnly {
		return nil, errors.New("write outside restore transaction")
	}
	c.s.writes++
	if strings.HasPrefix(q, "DELETE FROM ") {
		name := strings.Trim(strings.TrimPrefix(q, "DELETE FROM "), "`")
		c.table(name).Rows = nil
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, "INSERT INTO ") {
		name := strings.Trim(strings.Split(strings.TrimPrefix(q, "INSERT INTO "), " ")[0], "`")
		if name == c.s.failInsert {
			return nil, errors.New("injected insert failure; sensitive values must not escape")
		}
		t := c.table(name)
		start := strings.Index(q, "(")
		end := strings.Index(q, ")")
		names := strings.Split(q[start+1:end], ",")
		r := Row{}
		for _, col := range t.Columns {
			if col.Default != nil {
				r[col.Name] = Text(*col.Default)
			} else {
				r[col.Name] = Cell{Null: true}
			}
		}
		for i, n := range names {
			v, e := rawCell(args[i].Value)
			if e != nil {
				return nil, e
			}
			r[strings.Trim(n, "`")] = v
		}
		for _, fk := range t.ForeignKeys {
			v := r[fk.Column]
			if v.Null {
				continue
			}
			found := false
			for _, ref := range c.table(fk.Table).Rows {
				if ref[fk.Reference].String() == v.String() {
					found = true
				}
			}
			if !found {
				return nil, errors.New("fixture foreign key failure")
			}
		}
		t.Rows = append(t.Rows, r)
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unexpected mutation")
}

type memoryStmt struct {
	c *memoryConn
	q string
}

func (s *memoryStmt) Close() error  { return nil }
func (s *memoryStmt) NumInput() int { return -1 }
func (s *memoryStmt) Exec(args []driver.Value) (driver.Result, error) {
	var named []driver.NamedValue
	for i, v := range args {
		named = append(named, driver.NamedValue{Ordinal: i + 1, Value: v})
	}
	return s.c.ExecContext(context.Background(), s.q, named)
}
func (s *memoryStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, errors.New("unsupported")
}
func database(s *memoryDB) *sql.DB { db := sql.OpenDB(connector{s}); db.SetMaxOpenConns(1); return db }
func isolatedTarget(tables []Table) *memoryDB {
	s := &memoryDB{tables: copyTables(tables), name: "cm_drill_fixture", uuid: "fixture-server", grants: "GRANT SELECT ON `cm_drill_fixture`.* TO 'verifier'@'localhost'"}
	for i := range s.tables {
		s.tables[i].Rows = nil
	}
	for i := range s.tables {
		if s.tables[i].Name == "users" {
			r := cloneRow(tables[i].Rows[0])
			r["id"] = Text("99")
			r["password_hash"] = Text("bootstrap-hash")
			if hasColumn(s.tables[i], "auth_provider") {
				r["auth_provider"] = Text("local")
			}
			s.tables[i].Rows = []Row{r}
		}
	}
	return s
}
func targetProof() DrillTarget {
	return DrillTarget{Database: "cm_drill_fixture", ServerUUID: "fixture-server", CheckIsolation: func(context.Context) error { return nil }}
}

func TestMySQLCaptureIsReadOnlyAndLossless(t *testing.T) {
	s, _, _ := fixture()
	state := &memoryDB{tables: copyTables(s.Tables)}
	db := database(state)
	defer db.Close()
	got, e := Capture(context.Background(), db, Limits{100, 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if state.writes != 0 || state.readOnlyBegins != 1 || find(got, "users").Rows[0]["password_hash"].String() != "synthetic-source-hash" {
		t.Fatal("capture mutated source or lost hash")
	}
	if _, e = Capture(context.Background(), db, Limits{1, 1 << 20}); !errors.Is(e, ErrCapacity) {
		t.Fatal("limit not enforced")
	}
	if state.rollbacks != 1 {
		t.Fatal("failed snapshot not rolled back")
	}
}
func TestMySQLRestoreAdminTransactionAndReadOnlyVerify(t *testing.T) {
	s, target, p := fixture()
	for i := range target {
		if target[i].Name == "instances" || target[i].Name == "user_quotas" {
			target[i].ForeignKeys = []ForeignKey{{"user_id", "users", "id"}}
		}
	}
	state := isolatedTarget(target)
	db := database(state)
	defer db.Close()
	plan, e := RestoreDrill(context.Background(), db, targetProof(), s, p)
	if e != nil {
		t.Fatal(e)
	}
	users := find(Snapshot{Tables: state.tables}, "users")
	if len(users.Rows) != 2 || users.Rows[0]["id"].String() != "1" || users.Rows[0]["password_hash"].String() != "synthetic-source-hash" || state.commits != 1 {
		t.Fatal("admin replacement failed")
	}
	verifier := database(state)
	defer verifier.Close()
	if e = VerifyDrill(context.Background(), verifier, targetProof(), plan); e != nil {
		t.Fatal(e)
	}
	state.grants = "GRANT ALL PRIVILEGES ON `cm_drill_fixture`.* TO 'writer'@'localhost'"
	if e = VerifyDrill(context.Background(), verifier, targetProof(), plan); !errors.Is(e, ErrIsolation) {
		t.Fatal("writer used as verifier")
	}
}
func TestMySQLRestoreRollbackAndNonemptyTarget(t *testing.T) {
	for _, mode := range []string{"insert-failure", "nonempty", "source-target", "bad-isolation"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := fixture()
			state := isolatedTarget(target)
			proof := targetProof()
			switch mode {
			case "insert-failure":
				state.failInsert = "instances"
			case "nonempty":
				state.tables[2].Rows = []Row{cloneRow(s.Tables[2].Rows[0])}
			case "source-target":
				state.name = "clawmanager"
			case "bad-isolation":
				proof.CheckIsolation = func(context.Context) error { return errors.New("wrong UID") }
			}
			before, _ := Digest(Snapshot{Tables: state.tables})
			db := database(state)
			defer db.Close()
			if _, e := RestoreDrill(context.Background(), db, proof, s, p); e == nil {
				t.Fatal("unsafe restore succeeded")
			}
			after, _ := Digest(Snapshot{Tables: state.tables})
			if before != after {
				t.Fatal("rollback lost bootstrap data")
			}
			if mode != "insert-failure" && state.writes > 0 {
				t.Fatal("wrote before preflight")
			}
		})
	}
}
