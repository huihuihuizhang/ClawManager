package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

type fieldSQLFixture struct {
	base           *countFixture
	tables         []restoreFieldTable // nil preserves the original reader fixture
	failure        string
	target         string
	zone           string
	closeHook      func()
	opened, closed int
}
type fieldSQLConnector struct{ state *fieldSQLFixture }

func (c fieldSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &fieldSQLConn{countConn: &countConn{c.state.base}, state: c.state}, nil
}
func (c fieldSQLConnector) Driver() driver.Driver { return countDriver{c.state.base} }

type fieldSQLConn struct {
	*countConn
	state *fieldSQLFixture
}

func (c *fieldSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.state
	f.base.queries = append(f.base.queries, query)
	if query == "SELECT @@session.time_zone" {
		if f.failure == "zone_query" {
			return nil, errors.New("private-secret")
		}
		return &countRows{columns: []string{"zone"}, values: [][]driver.Value{{f.zone}}}, nil
	}
	if strings.Contains(query, "information_schema.TABLES") {
		if len(args) != 1 {
			return nil, errors.New("missing bound table")
		}
		if args[0].Value == f.target && f.failure == "engine_query" {
			return nil, errors.New("private-secret")
		}
		engine := "InnoDB"
		if args[0].Value == f.target && f.failure == "engine" {
			engine = "MyISAM"
		}
		return &countRows{columns: []string{"ENGINE"}, values: [][]driver.Value{{engine}}}, nil
	}
	definitions := restoreFieldColumns()
	if strings.Contains(query, "information_schema.COLUMNS") {
		if len(args) != 1 {
			return nil, errors.New("missing bound table")
		}
		name := args[0].Value.(string)
		if name == f.target && f.failure == "schema_query" {
			return nil, errors.New("private-secret")
		}
		columns := definitions[name]
		var values [][]driver.Value
		for _, column := range columns {
			values = append(values, []driver.Value{column})
		}
		if name == f.target {
			switch f.failure {
			case "schema_missing":
				values = values[1:]
			case "schema_extra":
				values = append(values, []driver.Value{"extra"})
			case "schema_duplicate":
				values[0] = values[1]
			}
		}
		f.opened++
		return &fieldSQLRows{state: f, columns: []string{"COLUMN_NAME"}, values: values, phase: "schema", table: name}, nil
	}
	for name, columns := range definitions {
		if !strings.Contains(query, " FROM `"+name+"` ORDER BY `id` LIMIT ") {
			continue
		}
		if len(args) != 0 || !strings.HasPrefix(query, "SELECT CAST(`id` AS CHAR CHARACTER SET utf8mb4) AS `id`") {
			return nil, errors.New("wrong projection")
		}
		for _, column := range columns {
			if !strings.Contains(query, "CAST(`"+column+"` AS CHAR CHARACTER SET utf8mb4) AS `"+column+"`") {
				return nil, errors.New("missing projection")
			}
		}
		limit, err := strconv.ParseInt(strings.TrimSuffix(query[strings.LastIndex(query, " LIMIT ")+7:], " FOR UPDATE"), 10, 64)
		if err != nil || limit <= 0 {
			return nil, errors.New("missing bound")
		}
		if name == f.target && f.failure == "data_query" {
			return nil, errors.New("private-secret")
		}
		var values [][]driver.Value
		for _, id := range []string{"1", "2"} {
			row := make([]driver.Value, len(columns))
			for i, column := range columns {
				row[i] = []byte("v")
				if column == "id" {
					row[i] = []byte(id)
				}
				if column == "created_at" {
					row[i] = []byte("2026-10-23 01:02:03.000001")
				}
				if column == "lite_cpu_cores" {
					row[i] = []byte("2.00")
				}
				if column == "details" {
					row[i] = nil
				}
			}
			values = append(values, row)
		}
		if f.tables != nil {
			values = nil
			for _, table := range f.tables {
				if table.Name != name {
					continue
				}
				for _, source := range table.Rows {
					row := make([]driver.Value, len(columns))
					for i, column := range columns {
						if source[column] != nil {
							row[i] = []byte(*source[column])
						}
					}
					values = append(values, row)
				}
			}
		}
		if name == f.target {
			switch f.failure {
			case "id":
				values[0][0] = []byte("01")
			case "duplicate_id":
				values[1][0] = values[0][0]
			case "native_number":
				values[0][1] = float64(2)
			case "projection":
				columns = append([]string(nil), columns...)
				columns[0] = "other"
			case "empty":
				values = nil
			}
		}
		if int64(len(values)) > limit {
			values = values[:int(limit)]
		}
		f.opened++
		return &fieldSQLRows{state: f, columns: columns, values: values, phase: "data", table: name}, nil
	}
	return nil, errors.New("unexpected query")
}

type fieldSQLRows struct {
	state        *fieldSQLFixture
	columns      []string
	values       [][]driver.Value
	phase, table string
	closed       bool
}

func (r *fieldSQLRows) Columns() []string { return r.columns }
func (r *fieldSQLRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		if r.table == r.state.target && r.state.failure == r.phase+"_next" {
			return errors.New("private-secret")
		}
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (r *fieldSQLRows) Close() error {
	if !r.closed {
		r.closed = true
		r.state.closed++
		if r.phase == "data" && r.table == r.state.target && r.state.closeHook != nil {
			r.state.closeHook()
		}
	}
	if r.table == r.state.target && r.state.failure == r.phase+"_close" {
		return errors.New("private-secret")
	}
	return nil
}
func fieldSQLTx(t *testing.T, f *fieldSQLFixture, ctx context.Context) *sql.Tx {
	t.Helper()
	f.base = newCountFixture()
	db := sql.OpenDB(fieldSQLConnector{f})
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx
}
func TestRestoreFieldsSQLCompleteSnapshot(t *testing.T) {
	f := &fieldSQLFixture{zone: "+00:00", target: "audit_logs"}
	tx := fieldSQLTx(t, f, context.Background())
	got, err := readRestoreFieldRows(context.Background(), tx, fieldTestBudget)
	if err != nil || len(got) != 9 {
		t.Fatalf("read failed %v", err)
	}
	if f.base.commits != 0 || f.base.rollbacks != 0 || !f.base.begin.ReadOnly || f.base.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatal("transaction ownership changed")
	}
	if f.opened != 18 || f.closed != 18 || len(f.base.queries) != 28 {
		t.Fatalf("incomplete reads: %+v", f)
	}
	if err := compareRestoreFields(context.Background(), got, got, fieldTestBudget); err != nil {
		t.Fatal(err)
	}
	if fieldTable(got, "audit_logs").Rows[0]["details"] != nil {
		t.Fatal("SQL NULL lost")
	}
	if *fieldTable(got, "northbound_admin_settings").Rows[0]["lite_cpu_cores"] != "2.00" {
		t.Fatal("DECIMAL scale lost")
	}
	if *fieldTable(got, "audit_logs").Rows[0]["created_at"] != "2026-10-23 01:02:03.000001" {
		t.Fatal("timestamp fraction lost")
	}
	if *fieldTable(got, "audit_logs").Rows[0]["id"] != "1" || *fieldTable(got, "audit_logs").Rows[1]["id"] != "2" {
		t.Fatal("driver row buffers aliased")
	}
}
func TestRestoreFieldsSQLFailuresDiscardAllRows(t *testing.T) {
	for _, failure := range []string{"zone_query", "engine_query", "engine", "schema_query", "schema_missing", "schema_extra", "schema_duplicate", "schema_next", "schema_close", "data_query", "data_next", "data_close", "projection", "native_number", "id", "duplicate_id"} {
		t.Run(failure, func(t *testing.T) {
			f := &fieldSQLFixture{zone: "+00:00", target: "system_image_settings", failure: failure}
			tx := fieldSQLTx(t, f, context.Background())
			got, err := readRestoreFieldRows(context.Background(), tx, fieldTestBudget)
			if err == nil || got != nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe partial result: %v", err)
			}
			if f.opened != f.closed {
				t.Fatal("cursor leaked")
			}
			if f.base.commits != 0 {
				t.Fatal("reader committed")
			}
		})
	}
}
func TestRestoreFieldsSQLBoundsUTCAndCancellation(t *testing.T) {
	for _, zone := range []string{"SYSTEM", "UTC", "+08:00", ""} {
		f := &fieldSQLFixture{zone: zone}
		tx := fieldSQLTx(t, f, context.Background())
		if got, err := readRestoreFieldRows(context.Background(), tx, fieldTestBudget); got != nil || err == nil || len(f.base.queries) != 1 {
			t.Fatal("non-explicit UTC accepted")
		}
	}
	for _, budget := range []restoreFieldBudget{{0, 1}, {1, 0}, {-1, 1}, {9223372036854775807, 1}, {17, 100000}, {100, 1}} {
		f := &fieldSQLFixture{zone: "+00:00"}
		tx := fieldSQLTx(t, f, context.Background())
		if got, err := readRestoreFieldRows(context.Background(), tx, budget); got != nil || err == nil {
			t.Fatal("invalid/exhausted budget accepted")
		}
		if f.opened != f.closed {
			t.Fatal("over-budget cursor leaked")
		}
	}
	if got, err := readRestoreFieldRows(context.Background(), nil, fieldTestBudget); err == nil || got != nil {
		t.Fatal("nil transaction accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fieldSQLFixture{zone: "+00:00", target: "system_image_settings", closeHook: cancel}
	tx := fieldSQLTx(t, f, ctx)
	if got, err := readRestoreFieldRows(ctx, tx, fieldTestBudget); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation ignored %v", err)
	}
}
func TestRestoreFieldsSQLEmptyTableAndExactBudget(t *testing.T) {
	f := &fieldSQLFixture{zone: "+00:00", target: "audit_logs", failure: "empty"}
	tx := fieldSQLTx(t, f, context.Background())
	got, err := readRestoreFieldRows(context.Background(), tx, fieldTestBudget)
	if err != nil {
		t.Fatal(err)
	}
	if len(fieldTable(got, "audit_logs").Rows) != 0 || len(fieldTable(got, "audit_logs").Columns) != 8 {
		t.Fatal("empty schema omitted")
	}
	var totalRows, totalBytes int64
	for _, table := range got {
		for _, row := range table.Rows {
			totalRows++
			for _, v := range row {
				if v != nil {
					totalBytes += int64(len(*v))
				}
			}
		}
	}
	// The same transaction can be read again; there is no hidden commit.
	if _, err := readRestoreFieldRows(context.Background(), tx, restoreFieldBudget{totalRows, totalBytes}); err != nil {
		t.Fatalf("exact budget rejected: %v", err)
	}
}
