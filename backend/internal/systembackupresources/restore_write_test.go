package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// This driver stores pending row mutations, so readback observes executed
// arguments rather than a preloaded expected answer. Rollback restores the
// initial rows. It remains a synthetic driver, not MySQL/FK/grants evidence.
type writeState struct {
	readback             *readbackState
	initial              []restoreFieldTable
	locks, mutations     []string
	failAt, affectedAt   int
	corruptAt            int
	lockError, lockExtra bool
	staleSnapshot        bool
	mutationHook         func()
}

type writeConnector struct{ state *writeState }

func (c writeConnector) Connect(context.Context) (driver.Conn, error) {
	s := c.state.readback
	return &writeConn{readbackConn: &readbackConn{fieldSQLConn: &fieldSQLConn{countConn: &countConn{s.field.base}, state: s.field}, readback: s}, state: c.state}, nil
}
func (c writeConnector) Driver() driver.Driver { return countDriver{c.state.readback.field.base} }

type writeConn struct {
	*readbackConn
	state *writeState
}

func (c *writeConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.readbackConn.BeginTx(ctx, opts)
	return writeTx{Tx: tx, state: c.state}, err
}

type writeTx struct {
	driver.Tx
	state *writeState
}

func (tx writeTx) Rollback() error {
	tx.state.readback.field.tables = cloneRestoreFieldTables(tx.state.initial)
	return tx.Tx.Rollback()
}

func (c *writeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.state.staleSnapshot && strings.HasPrefix(query, "SELECT CAST(") && !strings.HasSuffix(query, " FOR UPDATE") {
		// Model a consistent snapshot established by an earlier B read. Current
		// locking reads below still see the later committed target change.
		current := c.state.readback.field.tables
		c.state.readback.field.tables = c.state.initial
		defer func() { c.state.readback.field.tables = current }()
		return c.readbackConn.QueryContext(ctx, query, args)
	}
	if strings.HasPrefix(query, "SELECT `id` FROM ") && strings.HasSuffix(query, " FOR UPDATE") {
		if c.state.lockError {
			return nil, errors.New("private-secret")
		}
		for _, table := range c.state.readback.field.tables {
			prefix := "SELECT `id` FROM `" + table.Name + "` ORDER BY `id` LIMIT "
			if !strings.HasPrefix(query, prefix) {
				continue
			}
			if len(args) != 0 {
				return nil, errors.New("unexpected lock arguments")
			}
			limit, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(query, prefix), " FOR UPDATE"))
			if err != nil || limit <= 0 {
				return nil, errors.New("unbounded lock")
			}
			c.state.locks = append(c.state.locks, table.Name)
			var values [][]driver.Value
			for _, row := range table.Rows {
				id, _ := strconv.ParseInt(*row["id"], 10, 64)
				values = append(values, []driver.Value{id})
			}
			if c.state.lockExtra {
				values = append(values, []driver.Value{int64(999)})
			}
			if len(values) > limit {
				values = values[:limit]
			}
			return &countRows{columns: []string{"id"}, values: values}, nil
		}
		return nil, errors.New("unexpected lock table")
	}
	return c.readbackConn.QueryContext(ctx, query, args)
}

func (c *writeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	s := c.state
	if len(s.locks) != 9 || s.readback.probes != 35 {
		return nil, errors.New("mutation before full preflight")
	}
	for _, forbidden := range []string{"private-secret", "REPLACE", "IGNORE", "FOREIGN_KEY_CHECKS", "TRUNCATE"} {
		if strings.Contains(query, forbidden) {
			return nil, errors.New("unsafe query")
		}
	}
	parts := strings.Split(query, "`")
	if len(parts) < 3 {
		return nil, errors.New("no closed table")
	}
	tableName := parts[1]
	s.mutations = append(s.mutations, query)
	if s.failAt == len(s.mutations) {
		return nil, errors.New("private-secret")
	}
	for i := range s.readback.field.tables {
		table := &s.readback.field.tables[i]
		if table.Name != tableName {
			continue
		}
		columns := restoreFieldColumns()[tableName]
		switch {
		case strings.HasPrefix(query, "DELETE FROM "):
			id := args[0].Value.(string)
			for j, row := range table.Rows {
				if *row["id"] == id {
					table.Rows = append(table.Rows[:j], table.Rows[j+1:]...)
					break
				}
			}
		case strings.HasPrefix(query, "INSERT INTO "):
			if len(args) != len(columns) {
				return nil, errors.New("incomplete insert")
			}
			row := restoreFieldRow{}
			for j, column := range columns {
				row[column] = writeTestValue(args[j].Value)
			}
			table.Rows = append(table.Rows, row)
		case strings.HasPrefix(query, "UPDATE "):
			idIndex := len(columns) - 1
			id := args[idIndex].Value.(string)
			for _, row := range table.Rows {
				if *row["id"] != id {
					continue
				}
				if tableName == "northbound_admin_settings" && (!strings.HasSuffix(query, " AND `version`=?") || len(args) != len(columns)+1 || args[idIndex+1].Value != *row["version"]) {
					return nil, errors.New("missing version CAS")
				}
				j := 0
				for _, column := range columns {
					if column != "id" {
						row[column] = writeTestValue(args[j].Value)
						j++
					}
				}
			}
		default:
			return nil, errors.New("unexpected mutation")
		}
		if s.corruptAt == len(s.mutations) && len(table.Rows) > 0 {
			table.Rows[0]["created_at"] = fieldString("server-coerced")
		}
		if s.mutationHook != nil {
			s.mutationHook()
		}
		if s.affectedAt == len(s.mutations) {
			return driver.RowsAffected(0), nil
		}
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unknown table")
}

func writeTestValue(value any) *string {
	if value == nil {
		return nil
	}
	return fieldString(value.(string))
}

func writeDB(t *testing.T, before []restoreFieldTable) (*sql.DB, *writeState) {
	t.Helper()
	s := &writeState{readback: &readbackState{field: &fieldSQLFixture{base: newCountFixture(), zone: "+00:00", tables: cloneRestoreFieldTables(before)}}, initial: cloneRestoreFieldTables(before)}
	db := sql.OpenDB(writeConnector{s})
	t.Cleanup(func() { db.Close() })
	return db, s
}

func writePlan() ([]restoreFieldTable, []restoreFieldTable) {
	before := readbackExpected()
	after := cloneRestoreFieldTables(before)
	for i := range after {
		row := &after[i]
		// Every table exercises delete, update, insert and lossless NULL/text.
		row.Rows[0]["created_at"] = fieldString("2026-10-23 01:02:04.000001")
		row.Rows[1]["id"] = fieldString("3")
		if row.Name == "audit_logs" {
			row.Rows[0]["details"] = fieldString("private-secret '; DROP TABLE users; --")
			row.Rows[1]["details"] = fieldString("")
		}
	}
	return before, after
}

func writeProofs() restoreWriteProofs {
	return restoreWriteProofs{
		Target:    func(context.Context, *sql.Tx) error { return nil },
		Candidate: func(context.Context, *sql.Tx, []restoreFieldTable, []restoreFieldTable) error { return nil },
		Final:     func(context.Context, *sql.Tx) error { return nil },
	}
}

func TestRestoreWriteCommonTransaction(t *testing.T) {
	ctx := context.Background()
	before, after := writePlan()
	db, s := writeDB(t, before)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	proof := writeProofs()
	var calls []string
	proof.Target = func(_ context.Context, exact *sql.Tx) error {
		if exact != tx || len(s.locks) != 0 {
			t.Fatal("target proof order/transaction")
		}
		calls = append(calls, "target")
		return nil
	}
	proof.Candidate = func(_ context.Context, exact *sql.Tx, old, next []restoreFieldTable) error {
		if exact != tx || compareRestoreFields(ctx, before, old, fieldTestBudget) != nil || compareRestoreFields(ctx, after, next, fieldTestBudget) != nil {
			t.Fatal("candidate binding")
		}
		// Proof input mutation must not change the frozen write plan.
		old[0].Rows[0]["id"] = fieldString("999")
		next[0].Rows[0]["id"] = fieldString("999")
		calls = append(calls, "candidate")
		return nil
	}
	proof.Final = func(_ context.Context, exact *sql.Tx) error {
		if exact != tx || s.readback.probes != 70 || compareRestoreFields(ctx, after, s.readback.field.tables, fieldTestBudget) != nil {
			t.Fatal("final before complete readback")
		}
		calls = append(calls, "final")
		return nil
	}
	if err := applyRestoreWriteInTransaction(ctx, tx, frozenRegistryBytes(t), before, after, fieldTestBudget, proof); err != nil {
		t.Fatal(err)
	}
	if len(s.mutations) != 27 || !reflect.DeepEqual(s.locks, restoreWriteTableOrder()) || strings.Join(calls, ",") != "target,candidate,final" || s.readback.field.base.commits != 0 || s.readback.field.base.rollbacks != 0 {
		t.Fatal("wrong common transaction boundary")
	}
	// A later B stage can still roll back all D changes; D did not commit.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if compareRestoreFields(ctx, before, s.readback.field.tables, fieldTestBudget) != nil {
		t.Fatal("rollback lost original rows")
	}
}

func TestRestoreWriteMutationFailuresRollBack(t *testing.T) {
	for _, mode := range []string{"sql", "affected"} {
		for step := 1; step <= 27; step++ {
			t.Run(fmt.Sprintf("%s/%d", mode, step), func(t *testing.T) {
				before, after := writePlan()
				db, s := writeDB(t, before)
				if mode == "sql" {
					s.failAt = step
				} else {
					s.affectedAt = step
				}
				tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				err = applyRestoreWriteInTransaction(context.Background(), tx, frozenRegistryBytes(t), before, after, fieldTestBudget, writeProofs())
				if err == nil || strings.Contains(err.Error(), "private-secret") || len(s.mutations) != step {
					t.Fatal("failure continued or leaked data", err)
				}
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
				if s.readback.field.base.commits != 0 || compareRestoreFields(context.Background(), before, s.readback.field.tables, fieldTestBudget) != nil {
					t.Fatal("partial mutation escaped")
				}
			})
		}
	}
}

func TestRestoreWriteRejectsInvalidAndLateFacts(t *testing.T) {
	for _, mode := range []string{"target", "candidate", "final", "nil_target", "nil_candidate", "nil_final", "draft_registry", "missing_table", "bad_budget", "changed_target", "lock_error", "lock_budget", "schema", "control_before", "control_after", "coercion", "cancel_before", "cancel_after", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before, after := writePlan()
			if mode == "empty" {
				for i := range before {
					before[i].Rows = nil
					after[i].Rows = nil
				}
			}
			db, s := writeDB(t, before)
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			proof, registry, budget := writeProofs(), frozenRegistryBytes(t), fieldTestBudget
			denied := func(context.Context, *sql.Tx) error { return errors.New("private-secret") }
			switch mode {
			case "target":
				proof.Target = denied
			case "candidate":
				proof.Candidate = func(context.Context, *sql.Tx, []restoreFieldTable, []restoreFieldTable) error {
					return errors.New("private-secret")
				}
			case "final":
				proof.Final = denied
			case "nil_target":
				proof.Target = nil
			case "nil_candidate":
				proof.Candidate = nil
			case "nil_final":
				proof.Final = nil
			case "draft_registry":
				registry = []byte(`{}`)
			case "missing_table":
				after = after[1:]
			case "bad_budget":
				budget.Bytes = 1
			case "changed_target":
				s.staleSnapshot = true
				s.readback.field.tables[0].Rows[0]["created_at"] = fieldString("changed")
			case "lock_error":
				s.lockError = true
			case "lock_budget":
				budget.Rows = 18
				s.lockExtra = true
			case "schema":
				s.readback.field.target = "system_image_settings"
				s.readback.field.failure = "schema_extra"
			case "control_before":
				s.readback.nonempty = "system_backup_v2_backups"
			case "control_after":
				s.mutationHook = func() { s.readback.nonempty = "system_backup_v2_backups" }
			case "coercion":
				s.corruptAt = 27
			case "cancel_before":
				cancel()
			case "cancel_after":
				proof.Final = func(context.Context, *sql.Tx) error { cancel(); return nil }
			}
			err = applyRestoreWriteInTransaction(ctx, tx, registry, before, after, budget, proof)
			if mode == "empty" {
				if err != nil || len(s.mutations) != 0 || s.readback.probes != 70 {
					t.Fatal("empty complete plan failed", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatal("unsafe success/diagnostic", err)
			}
			if s.readback.field.base.commits != 0 {
				t.Fatal("writer committed caller transaction")
			}
		})
	}
}
