package domain

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func countFixture(tables []Table) *memoryDB {
	state := &memoryDB{tables: copyTables(tables)}
	state.sourceQuery = func(q string) (driver.Rows, bool, error) {
		if !strings.HasPrefix(q, "SELECT (SELECT COUNT(*) FROM ") {
			return nil, false, nil
		}
		terms := strings.Split(strings.TrimPrefix(q, "SELECT "), ",")
		var columns []string
		var values []driver.Value
		for i, term := range terms {
			parts := strings.Split(term, "`")
			if len(parts) != 3 || term != fmt.Sprintf("(SELECT COUNT(*) FROM `%s`) AS c%d", parts[1], i) {
				return nil, true, errors.New("unexpected exact count query")
			}
			found := false
			for _, table := range state.tables {
				if table.Name == parts[1] {
					columns = append(columns, fmt.Sprintf("c%d", i))
					values = append(values, int64(len(table.Rows)))
					found = true
				}
			}
			if !found {
				return nil, true, errors.New("missing counted table")
			}
		}
		return rows(columns, values), true, nil
	}
	return state
}

func rowCountTables(n int) []Table {
	var out []Table
	for _, name := range BusinessCaptureTables() {
		out = append(out, Table{Name: name, Engine: "InnoDB", Columns: []Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}})
		if len(out) == n {
			break
		}
	}
	return out
}

func TestSourceRowCountsBatchAndGuardBoundaries(t *testing.T) {
	for _, n := range []int{1, 64, 65} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			tables := rowCountTables(n)
			if len(tables) != n {
				t.Fatal("fixture lacks reviewed tables")
			}
			state := countFixture(tables)
			db := database(state)
			defer db.Close()
			calls := 0
			counts, err := captureSourceRowCounts(context.Background(), db, tables, func() error { calls++; return nil })
			if err != nil || len(counts) != n || calls != 6*((n+63)/64) || len(state.queries) != (n+63)/64 {
				t.Fatal("bounded exact census", err, calls)
			}
			for _, table := range tables {
				if counts[table.Name] != 0 {
					t.Fatal("empty count")
				}
			}
			for revoke := 1; revoke <= calls; revoke++ {
				seen := 0
				got, err := captureSourceRowCounts(context.Background(), db, tables, func() error {
					seen++
					if seen >= revoke {
						return errors.New("revoked")
					}
					return nil
				})
				if err == nil || got != nil {
					t.Fatalf("boundary %d exposed census", revoke)
				}
			}
		})
	}
}

func TestSourceRowCountsMalformedResultsReject(t *testing.T) {
	for _, mode := range []string{"null", "negative", "fraction", "overflow", "columns", "missing", "extra", "query-error", "next-error"} {
		t.Run(mode, func(t *testing.T) {
			state := &memoryDB{}
			state.sourceQuery = func(string) (driver.Rows, bool, error) {
				var v driver.Value = []byte("0")
				switch mode {
				case "null":
					v = nil
				case "negative":
					v = []byte("-1")
				case "fraction":
					v = []byte("1.1")
				case "overflow":
					v = []byte("18446744073709551616")
				case "columns":
					return rows([]string{"wrong"}, []driver.Value{v}), true, nil
				case "missing":
					return rows([]string{"c0"}), true, nil
				case "extra":
					return rows([]string{"c0"}, []driver.Value{v}, []driver.Value{v}), true, nil
				case "query-error":
					return nil, true, errors.New("query failed")
				case "next-error":
					return countErrorRows{}, true, nil
				}
				return rows([]string{"c0"}, []driver.Value{v}), true, nil
			}
			db := database(state)
			defer db.Close()
			got, err := readSourceRowCounts(context.Background(), db, "test", []string{"c0"}, nil)
			if err == nil || got != nil {
				t.Fatal("malformed census accepted", mode)
			}
		})
	}
}

type countErrorRows struct{}

func (countErrorRows) Columns() []string         { return []string{"c0"} }
func (countErrorRows) Close() error              { return nil }
func (countErrorRows) Next([]driver.Value) error { return errors.New("read failure") }

func TestSourceRowCountsCaptureDifferentialAndDDL(t *testing.T) {
	seed, _, _ := fixture()
	for i := range seed.Tables {
		if seed.Tables[i].Name != "users" {
			seed.Tables[i].Rows = nil
		}
	}
	run := func(fast bool, mutate bool, guard func() error) (Snapshot, *memoryDB, error) {
		state := countFixture(seed.Tables)
		db := database(state)
		defer db.Close()
		reads := 0
		catalog := func(ctx context.Context, q queryer, check func() error) ([]Table, error) {
			reads++
			if mutate && reads == 2 {
				state.tables[1].Columns = append([]Column(nil), state.tables[1].Columns...)
				state.tables[1].Columns[0].Extra = "VIRTUAL GENERATED"
			}
			return catalogBusinessGuarded(ctx, q, check)
		}
		got, err := captureWithCatalogMode(context.Background(), db, Limits{MaxRows: 100, MaxBytes: 1 << 20}, nil, catalog, fast, guard)
		return got, state, err
	}
	want, _, err := run(false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	got, state, err := run(true, false, func() error { calls++; return nil })
	if err != nil || !reflect.DeepEqual(want, got) || state.readOnlyBegins != 1 || state.commits != 1 || state.writes != 0 {
		t.Fatal("full capture differs", err)
	}
	dataReads := 0
	for _, q := range state.queries {
		if strings.HasPrefix(q, "SELECT `") {
			dataReads++
		}
	}
	if dataReads != 1 {
		t.Fatal("empty tables were read again", dataReads)
	}
	bad, state, err := run(true, true, nil)
	if err == nil || len(bad.Tables) != 0 || state.commits != 0 || state.rollbacks != 1 {
		t.Fatal("DDL hidden by empty census", err)
	}
	for revoke := 1; revoke <= calls; revoke++ {
		seen := 0
		bad, _, err := run(true, false, func() error {
			seen++
			if seen >= revoke {
				return errors.New("revoked")
			}
			return nil
		})
		if err == nil || len(bad.Tables) != 0 {
			t.Fatalf("capture boundary %d leaked", revoke)
		}
	}
}

func TestSourceRowCountsCancelCapacityAndMismatch(t *testing.T) {
	seed, _, _ := fixture()
	for _, mode := range []string{"cancel", "rows", "bytes", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			state := countFixture(seed.Tables)
			if mode == "mismatch" {
				original := state.sourceQuery
				state.sourceQuery = func(q string) (driver.Rows, bool, error) {
					if strings.HasPrefix(q, "SELECT (SELECT COUNT(*) FROM ") {
						values := make([]driver.Value, len(seed.Tables))
						columns := make([]string, len(values))
						for i := range values {
							values[i] = int64(99)
							columns[i] = fmt.Sprintf("c%d", i)
						}
						return rows(columns, values), true, nil
					}
					return original(q)
				}
			}
			db := database(state)
			defer db.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			limits := Limits{MaxRows: 100, MaxBytes: 1 << 20}
			if mode == "cancel" {
				cancel()
			}
			if mode == "rows" {
				limits.MaxRows = 1
			}
			if mode == "bytes" {
				limits.MaxBytes = 1
			}
			got, err := captureWithCatalogMode(ctx, db, limits, nil, catalogBusinessGuarded, true)
			if err == nil || len(got.Tables) != 0 || state.commits != 0 {
				t.Fatal("failure accepted", mode, err)
			}
		})
	}
}

func TestSourceRowCountsRejectInvalidScopeAndChangedCatalog(t *testing.T) {
	base := rowCountTables(1)
	for _, mode := range []string{"unknown", "duplicate", "engine", "columns", "key"} {
		t.Run(mode, func(t *testing.T) {
			tables := copyTables(base)
			switch mode {
			case "unknown":
				tables[0].Name = "system_backup_v2_tasks"
			case "duplicate":
				tables = append(tables, tables[0])
			case "engine":
				tables[0].Engine = "MyISAM"
			case "columns":
				tables[0].Columns = nil
			case "key":
				tables[0].PrimaryKey = []string{"missing"}
			}
			state := countFixture(tables)
			db := database(state)
			defer db.Close()
			got, err := captureSourceRowCounts(context.Background(), db, tables, nil)
			if err == nil || got != nil || len(state.queries) != 0 {
				t.Fatal("unreviewed census SQL issued", mode, err)
			}
		})
	}
	for _, change := range []func(*Table){
		func(t *Table) { t.Name += "_changed" },
		func(t *Table) { t.Engine = "MyISAM" },
		func(t *Table) { t.Columns[0].Type = "int" },
		func(t *Table) { t.Columns[0].Nullable = true },
		func(t *Table) { t.Columns[0].Default = strptr("1") },
		func(t *Table) { t.Columns[0].Extra = "STORED GENERATED" },
		func(t *Table) { t.PrimaryKey = []string{"other"} },
		func(t *Table) { t.ForeignKeys = []ForeignKey{{Column: "id", Table: "users", Reference: "id"}} },
		func(t *Table) { t.UniqueKeys = []UniqueKey{{Name: "unique_id", Columns: []string{"id"}}} },
	} {
		changed := copyTables(base)
		changed[0].Columns = append([]Column(nil), changed[0].Columns...)
		change(&changed[0])
		if sameSourceCatalog(base, changed) {
			t.Fatal("changed original schema accepted")
		}
	}
}
