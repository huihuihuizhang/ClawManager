//go:build systembackup_mysql

package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// Storage/transaction experiment only. No C domain approval or production proof.
func aMySQLFKPlan(t *testing.T, mode string) ([]restoreFieldTable, []restoreFieldTable) {
	before := restoreMySQLExpected(t)
	for i := range before {
		table := &before[i]
		switch table.Name {
		case "security_scan_jobs":
		case "security_scan_job_items", "security_scan_reports":
			if mode == "items" && table.Name == "security_scan_reports" || mode == "reports" && table.Name == "security_scan_job_items" {
				table.Rows = nil
			}
		default:
			table.Rows = nil
		}
	}
	after := cloneRestoreFieldTables(before)
	aWriteFKTable(after, "security_scan_jobs").Rows[0]["id"] = fieldString("2")
	for _, name := range []string{"security_scan_job_items", "security_scan_reports"} {
		for _, row := range aWriteFKTable(after, name).Rows {
			row["job_id"] = fieldString("2")
		}
	}
	if mode == "existing_parent" {
		copy := cloneRestoreFieldTables(after)
		jobs := aWriteFKTable(before, "security_scan_jobs")
		jobs.Rows = append(jobs.Rows, aWriteFKTable(copy, "security_scan_jobs").Rows[0])
	}
	return before, after
}

func TestAResourcesWriteFKMySQLSeed(t *testing.T) {
	for _, mode := range []string{"items", "reports", "both", "existing_parent"} {
		before, after := aMySQLFKPlan(t, mode)
		_, err := indexRestoreFields(context.Background(), before, fieldTestBudget)
		restoreMySQLOK(t, err)
		_, err = indexRestoreFields(context.Background(), after, fieldTestBudget)
		restoreMySQLOK(t, err)
		if compareRestoreFields(context.Background(), before, after, fieldTestBudget) == nil {
			t.Fatal("FK seed must move retained children")
		}
	}
	t.Log("PASS a-resources-write-fk-mysql-seed modes=4 cases=10 actual_mysql=not_run")
}

// Reinstall only the two declared migration-063 relationships after checking
// canonical and cloned information_schema definitions. No foreign_key_checks=0.
func aMySQLInstallJobFK(t *testing.T, f *restoreMySQLFixture) {
	t.Helper()
	for _, schema := range []string{"clawmanager", f.database} {
		for _, table := range []string{"security_scan_job_items", "security_scan_reports"} {
			if schema == f.database {
				_, err := f.writer.ExecContext(f.ctx, "ALTER TABLE `"+table+"` ADD FOREIGN KEY (`job_id`) REFERENCES `security_scan_jobs` (`id`) ON DELETE CASCADE")
				restoreMySQLOK(t, err)
			}
			rows, err := f.admin.QueryContext(f.ctx, `SELECT k.COLUMN_NAME,k.REFERENCED_TABLE_SCHEMA,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.DELETE_RULE,r.UPDATE_RULE
FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r
ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME AND r.TABLE_NAME=k.TABLE_NAME
WHERE k.TABLE_SCHEMA=? AND k.TABLE_NAME=? AND k.REFERENCED_TABLE_NAME IS NOT NULL`, schema, table)
			restoreMySQLOK(t, err)
			count := 0
			for rows.Next() {
				var col, targetSchema, target, targetCol, deletion, update string
				restoreMySQLOK(t, rows.Scan(&col, &targetSchema, &target, &targetCol, &deletion, &update))
				if col != "job_id" || targetSchema != schema || target != "security_scan_jobs" || targetCol != "id" || deletion != "CASCADE" || update != "NO ACTION" && update != "RESTRICT" {
					t.Fatal("declared scan FK differs")
				}
				count++
			}
			restoreMySQLOK(t, rows.Err())
			restoreMySQLOK(t, rows.Close())
			if count != 1 {
				t.Fatal("exactly one declared job FK required per child")
			}
		}
	}
	var enabled int
	restoreMySQLOK(t, f.writer.QueryRowContext(f.ctx, "SELECT @@session.foreign_key_checks").Scan(&enabled))
	if enabled != 1 {
		t.Fatal("FK checks disabled")
	}
	t.Log("FK_SCHEMA canonical_and_owned=matched job_relations=2 cascade=yes checks=1")
}

func aMySQLFKSeed(t *testing.T, f *restoreMySQLFixture, tables []restoreFieldTable) {
	t.Helper()
	order := restoreWriteTableOrder()
	for i := len(order) - 1; i >= 0; i-- {
		_, err := f.writer.ExecContext(f.ctx, "DELETE FROM `"+order[i]+"`")
		restoreMySQLOK(t, err)
	}
	var sorted []restoreFieldTable
	for _, name := range order {
		sorted = append(sorted, *aWriteFKTable(tables, name))
	}
	// The existing seeder's unordered DELETE is safe now: all tables are empty.
	f.seed(t, sorted)
}

func TestAResourcesWriteFKMySQL(t *testing.T) {
	f := newRestoreMySQLFixture(t)
	aMySQLInstallJobFK(t, f)
	begin := func(t *testing.T) *sql.Tx {
		t.Helper()
		tx := f.beginWrite(t)
		var enabled int
		restoreMySQLOK(t, tx.QueryRowContext(f.ctx, "SELECT @@session.foreign_key_checks").Scan(&enabled))
		if enabled != 1 {
			t.Fatal("actual work transaction has FK checks disabled")
		}
		return tx
	}
	reset := func(t *testing.T, mode string) ([]restoreFieldTable, []restoreFieldTable) {
		before, _ := aMySQLFKPlan(t, mode)
		aMySQLFKSeed(t, f, before)
		before = f.writeSnapshot(t)
		after := cloneRestoreFieldTables(before)
		jobs := aWriteFKTable(after, "security_scan_jobs")
		if mode == "existing_parent" {
			jobs.Rows = jobs.Rows[1:]
		} else {
			jobs.Rows[0]["id"] = fieldString("2")
		}
		for _, name := range []string{"security_scan_job_items", "security_scan_reports"} {
			for _, row := range aWriteFKTable(after, name).Rows {
				row["job_id"] = fieldString("2")
			}
		}
		return before, after
	}
	verify := func(t *testing.T, expected []restoreFieldTable) {
		t.Helper()
		restoreMySQLOK(t, verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()))
	}
	apply := func(t *testing.T, tx *sql.Tx, before, after []restoreFieldTable) {
		t.Helper()
		restoreMySQLOK(t, applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, f.writeProofs(t, before, after)))
	}
	for _, mode := range []string{"items", "reports", "both", "existing_parent"} {
		t.Run("reparent_"+mode, func(t *testing.T) {
			before, after := reset(t, mode)
			tx := begin(t)
			apply(t, tx, before, after)
			restoreMySQLOK(t, tx.Commit())
			verify(t, after)
		})
	}
	t.Run("delete_children_and_parent", func(t *testing.T) {
		before, _ := reset(t, "both")
		after := restoreMySQLEmpty()
		tx := begin(t)
		apply(t, tx, before, after)
		restoreMySQLOK(t, tx.Commit())
		verify(t, after)
	})
	t.Run("server_cascade_control_rollback", func(t *testing.T) {
		before, _ := reset(t, "both")
		tx := begin(t)
		_, err := tx.ExecContext(f.ctx, "DELETE FROM security_scan_jobs WHERE id=1")
		restoreMySQLOK(t, err)
		for _, name := range []string{"security_scan_job_items", "security_scan_reports"} {
			var count int
			restoreMySQLOK(t, tx.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM `"+name+"`").Scan(&count))
			if count != 0 {
				t.Fatal("server did not cascade")
			}
		}
		restoreMySQLOK(t, tx.Rollback())
		verify(t, before)
	})
	t.Run("server_rejects_orphan_1452", func(t *testing.T) {
		before, _ := reset(t, "both")
		tx := begin(t)
		_, err := tx.ExecContext(f.ctx, "UPDATE security_scan_job_items SET job_id=99 WHERE id=1")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1452 {
			t.Fatal("missing actual FK error 1452")
		}
		restoreMySQLOK(t, tx.Rollback())
		verify(t, before)
	})
	t.Run("late_common_failure_rollback", func(t *testing.T) {
		before, after := reset(t, "both")
		tx := begin(t)
		apply(t, tx, before, after)
		restoreMySQLOK(t, tx.Rollback())
		verify(t, before)
	})
	t.Run("final_denial_after_reparent_rollback", func(t *testing.T) {
		before, after := reset(t, "both")
		tx := begin(t)
		proof := f.writeProofs(t, before, after)
		observed := false
		proof.Final = func(ctx context.Context, tx *sql.Tx) error {
			rows, err := readRestoreFieldRowsMode(ctx, tx, fieldTestBudget, true)
			if err == nil && compareRestoreFields(ctx, after, rows, fieldTestBudget) == nil {
				observed = true
			}
			return errors.New("synthetic revoked authority")
		}
		if applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, proof) == nil || !observed {
			t.Fatal("must reach moved rows before final denial")
		}
		restoreMySQLOK(t, tx.Rollback())
		verify(t, before)
	})
	t.Run("unique_conflict_after_new_parent_rollback", func(t *testing.T) {
		before, after := reset(t, "both")
		items := aWriteFKTable(after, "security_scan_job_items")
		copy := cloneRestoreFieldTables(after)
		duplicate := aWriteFKTable(copy, "security_scan_job_items").Rows[0]
		duplicate["id"] = fieldString("2")
		items.Rows = append(items.Rows, duplicate)
		tx := begin(t)
		if applyRestoreWriteInTransaction(f.ctx, tx, f.registry, before, after, fieldTestBudget, f.writeProofs(t, before, after)) == nil {
			t.Fatal("unique conflict accepted")
		}
		var parents, moved int
		restoreMySQLOK(t, tx.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM security_scan_jobs").Scan(&parents))
		restoreMySQLOK(t, tx.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM security_scan_job_items WHERE job_id=2").Scan(&moved))
		if parents != 2 || moved != 1 {
			t.Fatal("unique failure must follow parent insertion and first child move")
		}
		_, err := tx.ExecContext(f.ctx, "INSERT INTO security_scan_job_items(id,job_id,asset_type,asset_id,asset_name) SELECT 2,job_id,asset_type,asset_id,asset_name FROM security_scan_job_items WHERE id=1")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1062 {
			t.Fatal("actual UNIQUE enforcement did not return 1062")
		}
		restoreMySQLOK(t, tx.Rollback())
		verify(t, before)
	})
	t.Log("PASS a-resources-write-fk-mysql cases=10 declared_job_fks=2 checks=1 synthetic_proofs=yes production=no")
}
