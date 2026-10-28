//go:build systembackup_mysql

package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func restoreMySQLWriteAfter(before []restoreFieldTable) []restoreFieldTable {
	after := cloneRestoreFieldTables(before)
	columns := map[string]string{
		"audit_logs": "action", "egress_private_exceptions": "description", "northbound_settings_audit": "action",
		"security_scan_configs": "quick_timeout_seconds", "security_scan_jobs": "current_item_name",
		"security_scan_job_items": "summary", "security_scan_reports": "summary_json", "system_image_settings": "display_name",
	}
	for _, table := range after {
		for _, row := range table.Rows {
			switch table.Name {
			case "northbound_admin_settings":
				version, _ := strconv.ParseInt(*row["version"], 10, 64)
				row["version"] = fieldString(strconv.FormatInt(version+1, 10))
			case "security_scan_configs":
				row[columns[table.Name]] = fieldString("42")
			case "security_scan_reports":
				row[columns[table.Name]] = fieldString(`{}`)
			default:
				row[columns[table.Name]] = fieldString("restore_storage_probe")
			}
		}
	}
	return after
}

func TestDResourcesWriteMySQLSeed(t *testing.T) {
	before := restoreMySQLExpected(t)
	after := restoreMySQLWriteAfter(before)
	if _, err := indexRestoreFields(context.Background(), before, fieldTestBudget); err != nil {
		t.Fatal("invalid write source shape")
	}
	if _, err := indexRestoreFields(context.Background(), after, fieldTestBudget); err != nil {
		t.Fatal("invalid write candidate shape")
	}
	for i := range before {
		if len(before[i].Rows) == 0 || restoreWriteRowsEqual(before[i].Columns, before[i].Rows[0], after[i].Rows[0]) {
			t.Fatal("each storage table must change")
		}
	}
	t.Log("PASS resources-write-mysql-seed tables=9 cases=9 actual_mysql=not_run synthetic_proofs=yes production=no")
}

// Synthetic writable fixture identity, not B's target/capture authority or a
// production permission decision. The real run stays within the existing
// namespace/UID/server and run-owned database checks and SELECT-only reader.
func (f *restoreMySQLFixture) writeProofs(t *testing.T, before, after []restoreFieldTable) restoreWriteProofs {
	t.Helper()
	var account string
	restoreMySQLOK(t, f.writer.QueryRowContext(f.ctx, "SELECT CURRENT_USER()").Scan(&account))
	old, next := cloneRestoreFieldTables(before), cloneRestoreFieldTables(after)
	target := func(ctx context.Context, tx *sql.Tx) error {
		var user, database, server, role, zone, isolation, mode, uid, ownerServer string
		var readOnly int
		if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),DATABASE(),@@server_uuid,CURRENT_ROLE(),@@session.time_zone,@@transaction_isolation,@@transaction_read_only,@@session.sql_mode").
			Scan(&user, &database, &server, &role, &zone, &isolation, &readOnly, &mode) != nil ||
			user != account || database != f.database || server != f.server || role != "NONE" || zone != "+00:00" || isolation != "REPEATABLE-READ" || readOnly != 0 ||
			(!strings.Contains(mode, "STRICT_TRANS_TABLES") && !strings.Contains(mode, "STRICT_ALL_TABLES")) {
			return errors.New("synthetic writer identity differs")
		}
		if tx.QueryRowContext(ctx, "SELECT uid,server_uuid FROM resources_probe_owner").Scan(&uid, &ownerServer) != nil || uid != f.uid || ownerServer != f.server {
			return errors.New("synthetic writer owner differs")
		}
		return nil
	}
	return restoreWriteProofs{Target: target, Candidate: func(ctx context.Context, _ *sql.Tx, a, b []restoreFieldTable) error {
		if compareRestoreFields(ctx, old, a, fieldTestBudget) != nil || compareRestoreFields(ctx, next, b, fieldTestBudget) != nil {
			return errors.New("synthetic writer plan differs")
		}
		return nil
	}, Final: target}
}

func (f *restoreMySQLFixture) writeSnapshot(t *testing.T) []restoreFieldTable {
	t.Helper()
	tx, err := f.reader.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	restoreMySQLOK(t, err)
	defer tx.Rollback()
	restoreMySQLOK(t, (restoreMySQLTargetProof{f}).VerifyReadOnlyTarget(f.ctx, tx))
	rows, err := readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
	restoreMySQLOK(t, err)
	restoreMySQLOK(t, tx.Commit())
	return rows
}

func (f *restoreMySQLFixture) beginWrite(t *testing.T) *sql.Tx {
	t.Helper()
	tx, err := f.writer.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	restoreMySQLOK(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

func TestDResourcesWriteMySQL(t *testing.T) {
	f := newRestoreMySQLFixture(t)
	reset := func(t *testing.T) ([]restoreFieldTable, []restoreFieldTable) {
		f.seed(t, restoreMySQLExpected(t))
		before := f.writeSnapshot(t) // Preserve the server's actual SQL text form.
		return before, restoreMySQLWriteAfter(before)
	}
	apply := func(t *testing.T, tx *sql.Tx, before, after []restoreFieldTable) {
		t.Helper()
		restoreMySQLOK(t, applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, f.writeProofs(t, before, after)))
	}
	readback := func(t *testing.T, expected []restoreFieldTable) {
		t.Helper()
		restoreMySQLOK(t, verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()))
	}
	t.Run("commit_updates_then_select_only_readback", func(t *testing.T) {
		before, after := reset(t)
		tx := f.beginWrite(t)
		apply(t, tx, before, after)
		restoreMySQLOK(t, tx.Commit())
		readback(t, after)
	})
	t.Run("insert_into_complete_empty_target", func(t *testing.T) {
		_, after := reset(t)
		empty := restoreMySQLEmpty()
		f.seed(t, empty)
		tx := f.beginWrite(t)
		apply(t, tx, empty, after)
		restoreMySQLOK(t, tx.Commit())
		readback(t, after)
	})
	t.Run("delete_complete_row_set", func(t *testing.T) {
		before, _ := reset(t)
		empty := restoreMySQLEmpty()
		tx := f.beginWrite(t)
		apply(t, tx, before, empty)
		restoreMySQLOK(t, tx.Commit())
		readback(t, empty)
	})
	t.Run("later_common_stage_rollback", func(t *testing.T) {
		before, after := reset(t)
		tx := f.beginWrite(t)
		apply(t, tx, before, after)
		restoreMySQLOK(t, tx.Rollback())
		readback(t, before)
	})
	t.Run("final_authority_failure_rollback", func(t *testing.T) {
		before, after := reset(t)
		tx := f.beginWrite(t)
		proof := f.writeProofs(t, before, after)
		proof.Final = func(context.Context, *sql.Tx) error { return errors.New("synthetic revocation") }
		if applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, proof) == nil {
			t.Fatal("late denial accepted")
		}
		restoreMySQLOK(t, tx.Rollback())
		readback(t, before)
	})
	t.Run("late_sql_failure_rollback", func(t *testing.T) {
		before, after := reset(t)
		for _, table := range after {
			if table.Name == "system_image_settings" {
				table.Rows[0]["display_name"] = nil
			}
		}
		tx := f.beginWrite(t)
		if applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, f.writeProofs(t, before, after)) == nil {
			t.Fatal("NOT NULL failure accepted")
		}
		// Earlier tables must actually have been changed before the last table
		// fails; an unrelated early rejection is not evidence of SQL rollback.
		var action string
		restoreMySQLOK(t, tx.QueryRowContext(f.ctx, "SELECT action FROM audit_logs ORDER BY id LIMIT 1").Scan(&action))
		if action != "restore_storage_probe" {
			t.Fatal("late SQL fault not reached")
		}
		restoreMySQLOK(t, tx.Rollback())
		readback(t, before)
	})
	t.Run("old_rr_snapshot_rejects_current_drift", func(t *testing.T) {
		before, after := reset(t)
		tx := f.beginWrite(t)
		old, err := readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
		restoreMySQLOK(t, err)
		restoreMySQLOK(t, compareRestoreFields(f.ctx, before, old, fieldTestBudget))
		_, err = f.writer.ExecContext(f.ctx, "UPDATE northbound_admin_settings SET version=version+100 WHERE id=1")
		restoreMySQLOK(t, err)
		old, err = readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
		restoreMySQLOK(t, err)
		restoreMySQLOK(t, compareRestoreFields(f.ctx, before, old, fieldTestBudget))
		if applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, f.writeProofs(t, before, after)) == nil {
			t.Fatal("old snapshot hid current target change")
		}
		restoreMySQLOK(t, tx.Rollback())
		current := f.writeSnapshot(t)
		for _, table := range current {
			if table.Name == "audit_logs" && *table.Rows[0]["action"] == "restore_storage_probe" {
				t.Fatal("drift rejection mutated target")
			}
		}
		if compareRestoreFields(f.ctx, before, current, fieldTestBudget) == nil {
			t.Fatal("concurrent commit not visible")
		}
	})
	for _, empty := range []bool{false, true} {
		name := "existing_primary_row_lock"
		if empty {
			name = "empty_primary_range_lock"
		}
		t.Run(name, func(t *testing.T) {
			before, after := reset(t)
			if empty {
				before, after = restoreMySQLEmpty(), restoreMySQLEmpty()
				f.seed(t, before)
			}
			tx := f.beginWrite(t)
			apply(t, tx, before, after)
			other, err := f.writer.Conn(f.ctx)
			restoreMySQLOK(t, err)
			defer other.Close()
			_, err = other.ExecContext(f.ctx, "SET SESSION innodb_lock_wait_timeout=1")
			restoreMySQLOK(t, err)
			query := "UPDATE audit_logs SET action='blocked_writer_probe' ORDER BY id LIMIT 1"
			if empty {
				query = "INSERT INTO audit_logs(id,action,resource_type,created_at) VALUES(1,'blocked_writer_probe','user',CURRENT_TIMESTAMP)"
			}
			_, err = other.ExecContext(f.ctx, query)
			var me *mysql.MySQLError
			if !errors.As(err, &me) || me.Number != 1205 {
				t.Fatal("competing writer not blocked with lock timeout")
			}
			restoreMySQLOK(t, tx.Rollback())
			readback(t, before)
		})
	}
	t.Log("PASS resources-write-mysql cases=9 tables=9 independent_select_only=yes synthetic_proofs=yes foreign_key_proof=no ddl_freeze_proof=no production=no")
}
