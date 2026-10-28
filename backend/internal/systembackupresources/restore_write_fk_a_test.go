package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This wrapper executes the real Go writer against the existing storing driver,
// adding the two migration-063 job FKs, DELETE CASCADE, and zero affected rows
// for a missing UPDATE target. It is not an actual MySQL/FK attestation.
type aWriteFKState struct {
	base     *writeState
	cascaded int
}
type aWriteFKConnector struct{ s *aWriteFKState }

func (c aWriteFKConnector) Driver() driver.Driver { return countDriver{c.s.base.readback.field.base} }
func (c aWriteFKConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := (writeConnector{c.s.base}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aWriteFKConn{writeConn: conn.(*writeConn), fk: c.s}, nil
}

type aWriteFKConn struct {
	*writeConn
	fk *aWriteFKState
}

func aWriteFKTable(tables []restoreFieldTable, name string) *restoreFieldTable {
	for i := range tables {
		if tables[i].Name == name {
			return &tables[i]
		}
	}
	panic("missing complete test table")
}

func aWriteFKHasRow(table *restoreFieldTable, id string) bool {
	for _, row := range table.Rows {
		if *row["id"] == id {
			return true
		}
	}
	return false
}

func (c *aWriteFKConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	parts := strings.Split(query, "`")
	if len(parts) < 3 {
		return nil, errors.New("invalid test mutation")
	}
	name := parts[1]
	tables := c.fk.base.readback.field.tables
	columns := restoreFieldColumns()[name]
	update, deletion := strings.HasPrefix(query, "UPDATE "), strings.HasPrefix(query, "DELETE FROM ")
	if update || deletion {
		idArg := 0
		if update {
			idArg = len(columns) - 1
		}
		if !aWriteFKHasRow(aWriteFKTable(tables, name), args[idArg].Value.(string)) {
			return driver.RowsAffected(0), nil
		}
	}
	if !deletion && (name == "security_scan_job_items" || name == "security_scan_reports") {
		arg := 0
		for _, column := range columns {
			if update && column == "id" {
				continue
			}
			if column == "job_id" && !aWriteFKHasRow(aWriteFKTable(tables, "security_scan_jobs"), args[arg].Value.(string)) {
				return nil, errors.New("scan child has no job parent")
			}
			arg++
		}
	}
	result, err := c.writeConn.ExecContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	if deletion && name == "security_scan_jobs" {
		for _, child := range []string{"security_scan_job_items", "security_scan_reports"} {
			table := aWriteFKTable(tables, child)
			kept := table.Rows[:0]
			for _, row := range table.Rows {
				if *row["job_id"] == args[0].Value.(string) {
					c.fk.cascaded++
				} else {
					kept = append(kept, row)
				}
			}
			table.Rows = kept
		}
	}
	return result, nil
}

func aWriteFKPlan(mode string) ([]restoreFieldTable, []restoreFieldTable) {
	before := readbackExpected()
	for i := range before {
		table := &before[i]
		switch table.Name {
		case "security_scan_jobs":
			table.Rows = table.Rows[:1]
		case "security_scan_job_items", "security_scan_reports":
			if mode == "items" && table.Name == "security_scan_reports" || mode == "reports" && table.Name == "security_scan_job_items" {
				table.Rows = nil
				continue
			}
			table.Rows = table.Rows[:1]
			if table.Name == "security_scan_job_items" {
				table.Rows[0]["id"] = fieldString("7")
			} else {
				table.Rows[0]["id"] = fieldString("9")
			}
			table.Rows[0]["job_id"] = fieldString("1")
		default:
			table.Rows = nil
		}
	}
	after := cloneRestoreFieldTables(before)
	aWriteFKTable(after, "security_scan_jobs").Rows[0]["id"] = fieldString("2")
	for _, child := range []string{"security_scan_job_items", "security_scan_reports"} {
		for _, row := range aWriteFKTable(after, child).Rows {
			row["job_id"] = fieldString("2")
		}
	}
	if mode == "existing_parent" {
		job := cloneRestoreFieldTables(after)
		aWriteFKTable(before, "security_scan_jobs").Rows = append(aWriteFKTable(before, "security_scan_jobs").Rows, aWriteFKTable(job, "security_scan_jobs").Rows[0])
	}
	return before, after
}

func aWriteFKDB(t *testing.T, before []restoreFieldTable) (*sql.DB, *aWriteFKState) {
	t.Helper()
	baseDB, base := writeDB(t, before)
	baseDB.Close()
	s := &aWriteFKState{base: base}
	db := sql.OpenDB(aWriteFKConnector{s})
	t.Cleanup(func() { db.Close() })
	return db, s
}

func aWriteFKRollback(t *testing.T, tx *sql.Tx, s *aWriteFKState, before []restoreFieldTable) {
	t.Helper()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if s.base.readback.field.base.commits != 0 || compareRestoreFields(context.Background(), before, s.base.readback.field.tables, fieldTestBudget) != nil {
		t.Fatal("common rollback did not restore all rows")
	}
}

func TestARestoreWriterReparentsBeforeParentDeletion(t *testing.T) {
	for _, mode := range []string{"items", "reports", "both", "existing_parent"} {
		t.Run(mode, func(t *testing.T) {
			before, after := aWriteFKPlan(mode)
			db, s := aWriteFKDB(t, before)
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := applyRestoreWriteInTransaction(context.Background(), tx, frozenRegistryBytes(t), before, after, fieldTestBudget, writeProofs()); err != nil {
				t.Fatalf("FK-valid reparent failed; cascaded=%d: %v", s.cascaded, err)
			}
			if s.cascaded != 0 || compareRestoreFields(context.Background(), after, s.base.readback.field.tables, fieldTestBudget) != nil {
				t.Fatal("retained children were lost or not moved")
			}
			last := s.base.mutations[len(s.base.mutations)-1]
			if last != "DELETE FROM `security_scan_jobs` WHERE `id`=?" {
				t.Fatal("old job was not deleted after its retained children moved")
			}
			aWriteFKRollback(t, tx, s, before)
		})
	}
}

func TestARestoreWriterDeletesChildrenExplicitly(t *testing.T) {
	before, after := aWriteFKPlan("both")
	for i := range after {
		after[i].Rows = nil
	}
	db, s := aWriteFKDB(t, before)
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := applyRestoreWriteInTransaction(context.Background(), tx, frozenRegistryBytes(t), before, after, fieldTestBudget, writeProofs()); err != nil {
		t.Fatal(err)
	}
	if s.cascaded != 0 || len(s.base.mutations) != 3 || compareRestoreFields(context.Background(), after, s.base.readback.field.tables, fieldTestBudget) != nil {
		t.Fatal("removed children relied on an implicit cascade")
	}
	aWriteFKRollback(t, tx, s, before)
}

func TestARestoreWriterReparentFailureRollsBack(t *testing.T) {
	for _, mode := range []string{"sql", "affected", "final", "cancel"} {
		steps := 4
		if mode == "final" || mode == "cancel" {
			steps = 1
		}
		for step := 1; step <= steps; step++ {
			t.Run(fmt.Sprintf("%s/%d", mode, step), func(t *testing.T) {
				before, after := aWriteFKPlan("both")
				db, s := aWriteFKDB(t, before)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				proof := writeProofs()
				switch mode {
				case "sql":
					s.base.failAt = step
				case "affected":
					s.base.affectedAt = step
				case "final":
					proof.Final = func(context.Context, *sql.Tx) error { return errors.New("private-secret") }
				case "cancel":
					// Cancel the work without asking database/sql to race an automatic
					// rollback; the common transaction owner still performs rollback.
					proof.Final = func(context.Context, *sql.Tx) error { cancel(); return nil }
				}
				if err := applyRestoreWriteInTransaction(ctx, tx, frozenRegistryBytes(t), before, after, fieldTestBudget, proof); err == nil || strings.Contains(err.Error(), "private-secret") {
					t.Fatal("late failure succeeded or leaked private detail")
				}
				aWriteFKRollback(t, tx, s, before)
			})
		}
	}
}
