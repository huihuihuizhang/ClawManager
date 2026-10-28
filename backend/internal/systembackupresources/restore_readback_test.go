package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type readbackState struct {
	field                         *fieldSQLFixture
	begins, probes                int
	nonempty, controlError        string
	beginFailure, rollbackFailure bool
	afterCommit                   func()
}
type readbackConnector struct{ state *readbackState }

func (c readbackConnector) Connect(context.Context) (driver.Conn, error) {
	return &readbackConn{fieldSQLConn: &fieldSQLConn{countConn: &countConn{c.state.field.base}, state: c.state.field}, readback: c.state}, nil
}
func (c readbackConnector) Driver() driver.Driver { return countDriver{c.state.field.base} }

type readbackConn struct {
	*fieldSQLConn
	readback *readbackState
}

func (c *readbackConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	s := c.readback
	s.begins++
	if s.beginFailure {
		return nil, errors.New("private-secret")
	}
	tx, err := c.countConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return readbackTx{Tx: tx, state: s}, nil
}
func (c *readbackConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	for table := range controlExclusionTables {
		if query == "SELECT 1 FROM `"+table+"` LIMIT 1" {
			s := c.readback
			s.probes++
			s.field.base.queries = append(s.field.base.queries, query)
			if len(args) != 0 {
				return nil, errors.New("unexpected control arguments")
			}
			if s.controlError == table {
				return nil, errors.New("private-secret")
			}
			var values [][]driver.Value
			if s.nonempty == table {
				values = [][]driver.Value{{int64(1)}}
			}
			return &countRows{columns: []string{"1"}, values: values}, nil
		}
	}
	return c.fieldSQLConn.QueryContext(ctx, query, args)
}

type readbackTx struct {
	driver.Tx
	state *readbackState
}

func (tx readbackTx) Commit() error {
	err := tx.Tx.Commit()
	if tx.state.afterCommit != nil {
		tx.state.afterCommit()
	}
	return err
}
func (tx readbackTx) Rollback() error {
	err := tx.Tx.Rollback()
	if tx.state.rollbackFailure {
		return errors.New("private-secret")
	}
	return err
}
func readbackDB(t *testing.T) (*sql.DB, *readbackState) {
	t.Helper()
	s := &readbackState{field: &fieldSQLFixture{base: newCountFixture(), zone: "+00:00"}}
	db := sql.OpenDB(readbackConnector{s})
	t.Cleanup(func() { db.Close() })
	return db, s
}
func readbackExpected() []restoreFieldTable {
	var result []restoreFieldTable
	for name, columns := range restoreFieldColumns() {
		table := restoreFieldTable{Name: name, Columns: columns}
		for _, id := range []string{"1", "2"} {
			row := restoreFieldRow{}
			for _, column := range columns {
				row[column] = fieldString("v")
				switch column {
				case "id":
					row[column] = fieldString(id)
				case "created_at":
					row[column] = fieldString("2026-10-23 01:02:03.000001")
				case "lite_cpu_cores":
					row[column] = fieldString("2.00")
				case "details":
					row[column] = nil
				}
			}
			table.Rows = append(table.Rows, row)
		}
		result = append(result, table)
	}
	return result
}
func readbackProofs() restoreReadbackProofs {
	return restoreReadbackProofs{Target: fixtureTargetProof{}, Candidate: func(context.Context, *sql.Tx, []restoreFieldTable) error { return nil }, Final: func(context.Context, *sql.Tx) error { return nil }}
}

func TestRestoreReadbackSingleTransaction(t *testing.T) {
	db, s := readbackDB(t)
	expected := readbackExpected()
	proof := readbackProofs()
	var exact *sql.Tx
	calls := []string{}
	proof.Target = controlCompletionProof(func(_ context.Context, tx *sql.Tx) error {
		exact = tx
		calls = append(calls, "target")
		if len(s.field.base.queries) != 0 {
			t.Fatal("read before target proof")
		}
		return nil
	})
	proof.Candidate = func(ctx context.Context, tx *sql.Tx, arg []restoreFieldTable) error {
		if exact != tx || compareRestoreFields(ctx, expected, arg, fieldTestBudget) != nil {
			t.Fatal("wrong candidate proof transaction/input")
		}
		calls = append(calls, "candidate")
		return nil
	}
	proof.Final = func(_ context.Context, tx *sql.Tx) error {
		if exact != tx || s.probes != 35 || s.field.closed != 18 {
			t.Fatal("final proof skipped complete reads")
		}
		calls = append(calls, "final")
		return nil
	}
	if err := verifyRestoreReadback(context.Background(), db, frozenRegistryBytes(t), expected, fieldTestBudget, proof); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "target,candidate,final" || s.begins != 1 || s.field.base.commits != 1 || s.field.base.rollbacks != 0 || !s.field.base.begin.ReadOnly || s.field.base.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || len(s.field.base.queries) != 98 {
		t.Fatal("wrong transaction/authority boundary")
	}
	for _, query := range s.field.base.queries {
		if !strings.HasPrefix(query, "SELECT ") || strings.Contains(query, "schema_migrations") || strings.Contains(query, "COUNT(*)") {
			t.Fatal("unbounded or out-of-scope read", query)
		}
	}
}
func TestRestoreReadbackPreflightDoesNotBegin(t *testing.T) {
	for _, mode := range []string{"nil_database", "nil_target", "typed_nil_target", "nil_candidate", "nil_final", "bad_rows", "bad_bytes", "row_overflow", "missing_table", "draft_registry", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			db, s := readbackDB(t)
			proof := readbackProofs()
			expected := readbackExpected()
			budget := fieldTestBudget
			registry := frozenRegistryBytes(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "nil_database":
				db = nil
			case "nil_target":
				proof.Target = nil
			case "typed_nil_target":
				var missing *resourcesProofPointer
				proof.Target = missing
			case "nil_candidate":
				proof.Candidate = nil
			case "nil_final":
				proof.Final = nil
			case "bad_rows":
				budget.Rows = 0
			case "bad_bytes":
				budget.Bytes = 0
			case "row_overflow":
				budget.Rows = 9223372036854775807
			case "missing_table":
				expected = expected[1:]
			case "draft_registry":
				registry, _ = json.Marshal(currentRegistry(t))
			case "canceled":
				cancel()
			}
			if err := verifyRestoreReadback(ctx, db, registry, expected, budget, proof); err == nil || s.begins != 0 || len(s.field.base.queries) != 0 {
				t.Fatal("invalid preflight reached database", mode, err)
			}
		})
	}
}
func TestRestoreReadbackRejectsAllControlTables(t *testing.T) {
	for table := range controlExclusionTables {
		t.Run(table, func(t *testing.T) {
			db, s := readbackDB(t)
			s.nonempty = table
			proof := readbackProofs()
			finalCalls := 0
			proof.Final = func(context.Context, *sql.Tx) error { finalCalls++; return nil }
			if err := verifyRestoreReadback(context.Background(), db, frozenRegistryBytes(t), readbackExpected(), fieldTestBudget, proof); err == nil || s.field.base.commits != 0 || s.field.base.rollbacks != 1 || s.field.opened != 0 || finalCalls != 0 {
				t.Fatal("source control row escaped complete boundary", table, err)
			}
		})
	}
}
func TestRestoreReadbackFailures(t *testing.T) {
	for _, mode := range []string{"begin", "target_proof", "candidate_proof", "final_proof", "control_query", "control_engine_query", "control_engine", "field_query", "field_iteration", "field_close", "field_mismatch", "field_row_budget", "field_byte_budget", "commit", "rollback", "target_committed", "final_committed"} {
		t.Run(mode, func(t *testing.T) {
			db, s := readbackDB(t)
			proof := readbackProofs()
			expected := readbackExpected()
			budget := fieldTestBudget
			secret := errors.New("private-secret")
			switch mode {
			case "begin":
				s.beginFailure = true
			case "target_proof":
				proof.Target = fixtureTargetProof{err: secret}
			case "candidate_proof":
				proof.Candidate = func(context.Context, *sql.Tx, []restoreFieldTable) error { return secret }
			case "final_proof":
				proof.Final = func(context.Context, *sql.Tx) error { return secret }
			case "control_query":
				s.controlError = "system_backup_v2_restore_drills"
			case "control_engine_query":
				s.field.target = "system_backup_v2_restore_drills"
				s.field.failure = "engine_query"
			case "control_engine":
				s.field.target = "system_backup_v2_restore_drills"
				s.field.failure = "engine"
			case "field_query":
				s.field.target = "system_image_settings"
				s.field.failure = "data_query"
			case "field_iteration":
				s.field.target = "system_image_settings"
				s.field.failure = "data_next"
			case "field_close":
				s.field.target = "system_image_settings"
				s.field.failure = "data_close"
			case "field_mismatch":
				fieldTable(expected, "system_image_settings").Rows[0]["image"] = fieldString("private-secret")
			case "field_row_budget":
				fieldTable(expected, "system_image_settings").Rows = fieldTable(expected, "system_image_settings").Rows[:1]
				budget.Rows = 17
			case "field_byte_budget":
				for _, table := range expected {
					for _, row := range table.Rows {
						for column := range row {
							if column != "id" {
								row[column] = fieldString("")
							}
						}
					}
				}
				budget.Bytes = 40
			case "commit":
				s.field.base.failure = "commit"
			case "rollback":
				s.rollbackFailure = true
				proof.Target = fixtureTargetProof{err: secret}
			case "target_committed":
				proof.Target = controlCompletionProof(func(_ context.Context, tx *sql.Tx) error { return tx.Commit() })
			case "final_committed":
				proof.Final = func(_ context.Context, tx *sql.Tx) error { return tx.Commit() }
			}
			err := verifyRestoreReadback(context.Background(), db, frozenRegistryBytes(t), expected, budget, proof)
			if err == nil || strings.Contains(err.Error(), "private-secret") || s.field.opened != s.field.closed {
				t.Fatal("unsafe or incomplete failure", mode, err)
			}
			if mode == "rollback" && !strings.Contains(err.Error(), "rollback outcome is unknown") {
				t.Fatal("rollback outcome hidden", err)
			}
			if mode == "commit" && (s.field.base.commits != 1 || s.field.base.rollbacks != 0) {
				t.Fatal("claimed rollback after commit attempt")
			}
		})
	}
}
func TestRestoreReadbackProofMutationIsolation(t *testing.T) {
	for _, mode := range []string{"proof_argument", "caller_argument", "registry_argument"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := readbackDB(t)
			proof := readbackProofs()
			expected := readbackExpected()
			registry := frozenRegistryBytes(t)
			if mode != "registry_argument" {
				fieldTable(expected, "system_image_settings").Rows[0]["image"] = fieldString("mismatch")
			}
			proof.Candidate = func(_ context.Context, _ *sql.Tx, arg []restoreFieldTable) error {
				switch mode {
				case "proof_argument":
					fieldTable(arg, "system_image_settings").Rows[0]["image"] = fieldString("v")
				case "caller_argument":
					fieldTable(expected, "system_image_settings").Rows[0]["image"] = fieldString("v")
				case "registry_argument":
					for i := range registry {
						registry[i] = ' '
					}
				}
				return nil
			}
			err := verifyRestoreReadback(context.Background(), db, registry, expected, fieldTestBudget, proof)
			if (mode == "registry_argument") != (err == nil) {
				t.Fatal("proof mutation changed frozen comparison/registry", mode, err)
			}
		})
	}
}
func TestRestoreReadbackLateCancellation(t *testing.T) {
	for _, mode := range []string{"after_target", "after_candidate", "after_final", "after_commit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db, s := readbackDB(t)
			proof := readbackProofs()
			switch mode {
			case "after_target":
				proof.Target = controlCompletionProof(func(context.Context, *sql.Tx) error { cancel(); return nil })
			case "after_candidate":
				proof.Candidate = func(context.Context, *sql.Tx, []restoreFieldTable) error { cancel(); return nil }
			case "after_final":
				proof.Final = func(context.Context, *sql.Tx) error { cancel(); return nil }
			case "after_commit":
				s.afterCommit = cancel
			}
			if err := verifyRestoreReadback(ctx, db, frozenRegistryBytes(t), readbackExpected(), fieldTestBudget, proof); !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation became success", mode, err)
			}
			if mode == "after_commit" && (s.field.base.commits != 1 || s.field.base.rollbacks != 0) {
				t.Fatal("changed completion classification")
			}
		})
	}
}
