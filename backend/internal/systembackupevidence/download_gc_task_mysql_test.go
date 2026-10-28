//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Component probe only: actual published task rows, CHECKs/FKs and RR locks.
// The scope is synthetic. No Collect, worker grant, provider, or role approval.
var dGCTaskMySQLCases = []string{
	"backup", "drill", "preflight", "artifact_verify",
	"active_drill", "active_preflight", "active_artifact_verify",
	"prune_reference", "owner_deadline_not_expired",
	"backup_row_lock", "dependent_row_lock",
	"empty_drill_range", "empty_preflight_range", "empty_artifact_verify_range", "empty_prune_range",
	"late_owner_fact", "late_dependent_fact", "late_prune_reference",
}

const dGCTaskPruneRunSQL = `INSERT INTO system_backup_v2_prune_runs(public_id,origin_installation_id,create_actor_type,create_actor_id,create_endpoint,create_idempotency_key,create_request_hash,config_version,older_than,started_at,created_at) VALUES(? ,?,'admin','42','createSystemBackupPruneDryRun','gc-task-prune-run-seed',REPEAT('a',64),1,?,?,?)`
const dGCTaskPruneItemSQL = `INSERT INTO system_backup_v2_prune_items(public_id,origin_installation_id,prune_run_id,artifact_public_id,item_type,status,canonical_location_key,canonical_location_size_bytes,canonical_location_hash,immutable_version,artifact_plan_hash,planned_backup_status,planned_backup_finished_at,planned_artifact_state,planned_prune_guard_version) VALUES(?,?,?,?,'object_version','planned',?,?,?,'gc-task-version',REPEAT('c',64),'failed',?,'committed',1)`

func dGCTaskPruneItemArgs(installation, backup string, run int64, finished time.Time) []any {
	location := []byte("isolated-gc-task-prune-object")
	return []any{"spi_88888888-8888-4888-8888-888888888888", installation, run, backup, location, len(location), hash(location), finished}
}

func TestDDownloadGCTaskMySQLSeed(t *testing.T) {
	t.Run("case_catalog", func(t *testing.T) {
		seen := map[string]bool{}
		for _, name := range dGCTaskMySQLCases {
			if seen[name] || !regexp.MustCompile(`^[a-z_]+$`).MatchString(name) {
				t.Fatal("GC task case identity")
			}
			seen[name] = true
		}
		if len(seen) != 18 {
			t.Fatal("GC task case count")
		}
	})
	t.Run("task_rows", func(t *testing.T) {
		input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
		mustSQL(t, err)
		p := aDownloadMFAPinnedFixture(t, input)
		created, deadline := time.Unix(10000, 0).UTC(), time.Unix(20000, 0).UTC()
		for _, row := range aTaskOwnerSQLSeeds(p.initial.Manifest.Identity.Installation, created, deadline, p.db.config.CanonicalJSON()) {
			if strings.Count(row.statement, "?") != len(row.args) || row.args[6] != deadline || row.args[7] != created || !strings.HasPrefix(row.statement, "INSERT INTO "+taskTable(row.kind)+"(") {
				t.Fatal("published task SQL seed binding", row.kind)
			}
		}
	})
	t.Run("prune_rows", func(t *testing.T) {
		args := dGCTaskPruneItemArgs("installation_gc_task", "sbk_11111111-2222-4333-8444-555555555555", 1, time.Unix(20000, 0))
		if strings.Count(dGCTaskPruneRunSQL, "?") != 5 || strings.Count(dGCTaskPruneItemSQL, "?") != len(args) || args[6] != hash(args[4].([]byte)) || !strings.Contains(dGCTaskPruneItemSQL, "'object_version','planned'") {
			t.Fatal("published prune SQL seed binding")
		}
	})
	t.Run("query_shapes", func(t *testing.T) {
		for _, kind := range []string{"drill", "preflight", "artifact_verify"} {
			q := downloadGCTaskDependentSQL(kind)
			if !strings.HasSuffix(q, " FROM "+taskTable(kind)+" WHERE source_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE") {
				t.Fatal("GC task source range narrowed", kind)
			}
		}
		if downloadGCTaskPruneDependencySQL != "SELECT id FROM system_backup_v2_prune_items WHERE artifact_public_id=? LIMIT 1 FOR UPDATE" {
			t.Fatal("GC task prune range narrowed")
		}
	})
	t.Log("PASS GC task seed cases=18 actual_mysql=not_run full_gc=not_run role_approval=no production_approval=no")
}

type dGCTaskMySQLFixture struct {
	ctx           context.Context
	db            *sql.DB
	service       *SQLDownloadGCTaskEligibility
	scope         DownloadRetentionGCScope
	rows          map[string]aTaskOwnerSQLSeed
	backup        string
	now, finished time.Time
	pruneRun      int64
}

func newDGCTaskMySQLFixture(t *testing.T, input aDownloadMFAInputs, owner string) *dGCTaskMySQLFixture {
	t.Helper()
	ctx, db, _, identity := aDownloadMFADatabase(t, input)
	p := aDownloadMFAPinnedFixture(t, input)
	installation := p.initial.Manifest.Identity.Installation
	_, err := db.ExecContext(ctx, "INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'gc-task-probe','gc-task@example.invalid','synthetic-unused-password-hash','admin',TRUE)")
	mustSQL(t, err)
	cells := aDownloadMFAConfigCells(p)
	columns, err := db.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' ORDER BY ORDINAL_POSITION")
	mustSQL(t, err)
	var names []string
	var args []any
	for columns.Next() {
		var name string
		mustSQL(t, columns.Scan(&name))
		if v, ok := cells[name]; ok {
			names, args = append(names, name), append(args, v)
		}
	}
	mustSQL(t, columns.Err())
	mustSQL(t, columns.Close())
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(names, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	mustSQL(t, err)
	now := aDownloadMFANow(t, ctx, db)
	f := &dGCTaskMySQLFixture{ctx: ctx, db: db, rows: map[string]aTaskOwnerSQLSeed{}, now: now, finished: now.Add(-3 * time.Hour)}
	for _, row := range aTaskOwnerSQLSeeds(installation, now.Add(-4*time.Hour), now.Add(-2*time.Hour), p.db.config.CanonicalJSON()) {
		_, err = db.ExecContext(ctx, row.statement, row.args...)
		mustSQL(t, err)
		_, err = db.ExecContext(ctx, "UPDATE "+row.table+" SET status='failed',can_cancel=FALSE,failure_category='validation_failed',started_at=created_at,finished_at=? WHERE public_id=?", f.finished, row.id)
		mustSQL(t, err)
		f.rows[row.kind] = row
	}
	f.backup = f.rows["backup"].id
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET artifact_state='deleted',artifact_unusable_reason='deleted' WHERE public_id=?", f.backup)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_restore_drills SET cleanup_status='succeeded' WHERE public_id=?", f.rows["drill"].id)
	mustSQL(t, err)
	result, err := db.ExecContext(ctx, dGCTaskPruneRunSQL, "spr_88888888-8888-4888-8888-888888888888", installation, now.Add(-time.Hour), now, now)
	mustSQL(t, err)
	f.pruneRun, err = result.LastInsertId()
	mustSQL(t, err)
	f.service, err = NewSQLDownloadGCTaskEligibility(DownloadGCTaskEligibilityConfig{Database: identity, Installation: installation})
	mustSQL(t, err)
	i := p.initial.Manifest.Identity
	i.OwnerType, i.OwnerID = owner, f.rows[owner].id
	f.scope = DownloadRetentionGCScope{Database: identity, Installation: installation, WorkerOperation: "sop_11111111-2222-4333-8444-555555555555", PrincipalSHA256: strings.Repeat("b", 64), Operation: "sop_66666666-7777-4888-8999-aaaaaaaaaaaa", RequestHash: strings.Repeat("c", 64), Evidence: i, OperationID: 1, EvidenceID: 1, ActorID: 42, EvidenceRowVersion: 1, IntentAuditID: 1, ResultAuditID: 2, AdmittedAt: now.Add(-time.Hour), RetainUntil: now.Add(-time.Minute), MinimumRetainUntil: now.Add(-time.Minute)}
	return f
}

// Hash complete rows, including the original config-bound task bytes. Nothing
// from those rows is printed; the same pristine snapshot must survive rollback.
func (f *dGCTaskMySQLFixture) fingerprint(t *testing.T) string {
	t.Helper()
	var snapshot []any
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_prune_runs", "system_backup_v2_prune_items", "system_backup_v2_operations", "audit_logs", "system_backup_v2_strong_auth_nonces", "system_backup_v2_download_admission_receipts", "system_backup_v2_download_result_receipts", "system_backup_v2_compact_tombstones"} {
		rows, err := f.db.QueryContext(f.ctx, "SELECT * FROM "+table+" ORDER BY 1")
		mustSQL(t, err)
		columns, err := rows.Columns()
		mustSQL(t, err)
		data := []any{table, columns}
		for rows.Next() {
			if len(data) > 34 {
				t.Fatal("unexpected GC probe row count")
			}
			values, pointers := make([]any, len(columns)), make([]any, len(columns))
			for n := range values {
				pointers[n] = &values[n]
			}
			mustSQL(t, rows.Scan(pointers...))
			data = append(data, values)
		}
		mustSQL(t, rows.Err())
		mustSQL(t, rows.Close())
		snapshot = append(snapshot, data)
	}
	return hash(canonical(snapshot))
}

func (f *dGCTaskMySQLFixture) plan(t *testing.T, kind string) {
	t.Helper()
	q, table := downloadGCTaskDependentSQL(kind), taskTable(kind)
	if kind == "prune" {
		q, table = downloadGCTaskPruneDependencySQL, "system_backup_v2_prune_items"
	}
	var raw []byte
	mustSQL(t, f.db.QueryRowContext(f.ctx, "EXPLAIN FORMAT=JSON "+q, f.backup).Scan(&raw))
	var plan any
	mustSQL(t, json.Unmarshal(raw, &plan))
	seen := 0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, next := range x {
				walk(next)
			}
		case map[string]any:
			if name, ok := x["table_name"].(string); ok {
				access, _ := x["access_type"].(string)
				key, _ := x["key"].(string)
				if name != table || access == "" {
					t.Fatal("unexpected GC query plan table/access")
				}
				seen++
				t.Logf("PLAN gc_task kind=%s table=%s access=%s key=%s sha256=%s", kind, name, access, key, hash(raw))
			}
			for _, next := range x {
				walk(next)
			}
		}
	}
	walk(plan)
	if seen != 1 {
		t.Fatal("GC query plan was not observed")
	}
}

func (f *dGCTaskMySQLFixture) lock(t *testing.T) (*sql.Tx, *DownloadGCTaskEligibilityGuard, error) {
	t.Helper()
	tx, err := f.db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	g, err := f.service.Lock(f.ctx, tx, f.scope, aDownloadMFANow(t, f.ctx, f.db))
	if err != nil {
		mustSQL(t, tx.Rollback())
	}
	return tx, g, err
}

// Require the exact holder/writer connection pair, RECORD lock, table, index,
// and WAITING/GRANTED states. A timeout or a parent-table FK wait is not proof.
func (f *dGCTaskMySQLFixture) blockedWrite(t *testing.T, hold *sql.Tx, table, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 12*time.Second)
	defer cancel()
	var holderID, writerID int64
	mustSQL(t, hold.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&holderID))
	peer, err := f.db.Conn(ctx)
	mustSQL(t, err)
	defer peer.Close()
	mustSQL(t, peer.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&writerID))
	writer, err := peer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer writer.Rollback()
	done := make(chan error, 1)
	go func() {
		_, e := writer.ExecContext(ctx, query, args...)
		if e == nil {
			e = writer.Rollback()
		}
		done <- e
	}()
	drained := false
	defer func() {
		hold.Rollback()
		cancel()
		if !drained {
			<-done
		}
	}()
	index, mode := "", ""
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		err = f.db.QueryRowContext(ctx, `SELECT r.INDEX_NAME,r.LOCK_MODE FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
JOIN performance_schema.threads p ON p.THREAD_ID=r.THREAD_ID
JOIN performance_schema.threads h ON h.THREAD_ID=b.THREAD_ID
WHERE r.OBJECT_SCHEMA=? AND b.OBJECT_SCHEMA=r.OBJECT_SCHEMA AND r.OBJECT_NAME=? AND b.OBJECT_NAME=r.OBJECT_NAME
AND r.LOCK_TYPE='RECORD' AND b.LOCK_TYPE='RECORD' AND r.LOCK_STATUS='WAITING' AND b.LOCK_STATUS='GRANTED'
AND r.INDEX_NAME=b.INDEX_NAME AND p.PROCESSLIST_ID=? AND h.PROCESSLIST_ID=? LIMIT 1`, f.scope.Database.Database, table, writerID, holderID).Scan(&index, &mode)
		if err == nil {
			break
		}
		if err != sql.ErrNoRows {
			mustSQL(t, err)
		}
		select {
		case e := <-done:
			drained = true
			t.Fatal("GC competing writer completed before release", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if index == "" || mode == "" {
		t.Fatal("exact GC task RECORD wait not observed; a parent FK wait does not qualify")
	}
	mustSQL(t, hold.Rollback())
	err = <-done
	drained = true
	mustSQL(t, err)
	t.Logf("OBSERVED gc_task_lock table=%s index=%s requesting_mode=%s holder=%d writer=%d writer_rolled_back=yes", table, index, mode, holderID, writerID)
}

type dGCTaskSQLLockFact struct{ Index, Mode, Data string }

func (f *dGCTaskMySQLFixture) pruneLocks(t *testing.T, tx *sql.Tx) []dGCTaskSQLLockFact {
	t.Helper()
	var connection int64
	mustSQL(t, tx.QueryRowContext(f.ctx, "SELECT CONNECTION_ID()").Scan(&connection))
	rows, err := f.db.QueryContext(f.ctx, `SELECT COALESCE(l.INDEX_NAME,''),l.LOCK_MODE,COALESCE(l.LOCK_DATA,'')
FROM performance_schema.data_locks l JOIN performance_schema.threads p ON p.THREAD_ID=l.THREAD_ID
WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_prune_items' AND l.LOCK_TYPE='RECORD'
AND l.LOCK_STATUS='GRANTED' AND p.PROCESSLIST_ID=? ORDER BY BINARY l.INDEX_NAME,BINARY l.LOCK_MODE,BINARY l.LOCK_DATA`, f.scope.Database.Database, connection)
	mustSQL(t, err)
	facts := []dGCTaskSQLLockFact{}
	for rows.Next() {
		var fact dGCTaskSQLLockFact
		mustSQL(t, rows.Scan(&fact.Index, &fact.Mode, &fact.Data))
		if len(facts) >= 10000 || fact.Index == "" || !strings.HasPrefix(fact.Mode, "X") {
			t.Fatal("unexpected GC prune record-lock footprint")
		}
		facts = append(facts, fact)
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	if len(facts) == 0 {
		t.Fatal("GC component held no observable prune RECORD locks")
	}
	return facts
}

func (f *dGCTaskMySQLFixture) pruneRange(t *testing.T, component *sql.Tx, args []any) {
	t.Helper()
	// A real prune INSERT may first wait for the component's backup FK row.
	// Observe the component's ACTUAL prune locks, then isolate its exact query
	// so an unrelated parent wait cannot masquerade as range-lock evidence.
	full := f.pruneLocks(t, component)
	mustSQL(t, component.Rollback())
	isolated, err := f.db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer isolated.Rollback()
	var found int64
	if isolated.QueryRowContext(f.ctx, downloadGCTaskPruneDependencySQL, f.backup).Scan(&found) != sql.ErrNoRows {
		t.Fatal("isolated prune predicate was not empty")
	}
	if !reflect.DeepEqual(full, f.pruneLocks(t, isolated)) {
		t.Fatal("isolated prune predicate did not reproduce component locks")
	}
	f.blockedWrite(t, isolated, "system_backup_v2_prune_items", dGCTaskPruneItemSQL, args...)
	t.Logf("OBSERVED gc_task_prune_lock_equivalence component_and_predicate=same record_locks=%d sha256=%s parent_fk_wait_excluded=yes", len(full), hash(canonical(full)))
}

func TestDDownloadGCTaskMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("GC task capsule pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, name := range dGCTaskMySQLCases {
		t.Run(name, func(t *testing.T) {
			owner := "backup"
			if oneOf(name, "drill", "preflight", "artifact_verify") {
				owner = name
			}
			f := newDGCTaskMySQLFixture(t, input, owner)
			if strings.HasPrefix(name, "active_") {
				kind := strings.TrimPrefix(name, "active_")
				row := f.rows[kind]
				status := "running"
				if kind == "drill" {
					status = "restoring"
				}
				_, err = f.db.ExecContext(f.ctx, "UPDATE "+row.table+" SET status=?,can_cancel=TRUE,failure_category='none',finished_at=NULL WHERE public_id=?", status, row.id)
				mustSQL(t, err)
			}
			if name == "owner_deadline_not_expired" {
				_, err = f.db.ExecContext(f.ctx, "UPDATE system_backup_v2_backups SET deadline_at=UTC_TIMESTAMP(6)+INTERVAL 1 HOUR WHERE public_id=?", f.backup)
				mustSQL(t, err)
			}
			pruneArgs := dGCTaskPruneItemArgs(f.scope.Installation, f.backup, f.pruneRun, f.finished)
			if name == "prune_reference" {
				_, err = f.db.ExecContext(f.ctx, dGCTaskPruneItemSQL, pruneArgs...)
				mustSQL(t, err)
			}
			if strings.HasPrefix(name, "empty_") && name != "empty_prune_range" {
				kind := strings.TrimSuffix(strings.TrimPrefix(name, "empty_"), "_range")
				row := f.rows[kind]
				_, err = f.db.ExecContext(f.ctx, "DELETE FROM "+row.table+" WHERE public_id=?", row.id)
				mustSQL(t, err)
				f.plan(t, kind)
			}
			if name == "backup" {
				for _, kind := range []string{"drill", "preflight", "artifact_verify", "prune"} {
					f.plan(t, kind)
				}
			}
			if name == "empty_prune_range" {
				f.plan(t, "prune")
			}
			before := f.fingerprint(t)
			defer func() {
				if f.fingerprint(t) != before {
					t.Error("GC task probe changed original rows outside its rollback")
				}
			}()
			tx, g, lockErr := f.lock(t)
			defer tx.Rollback()
			if strings.HasPrefix(name, "active_") || name == "prune_reference" || name == "owner_deadline_not_expired" {
				if lockErr == nil || g != nil {
					t.Fatal("protected actual task/reference admitted")
				}
				return
			}
			mustSQL(t, lockErr)
			mustSQL(t, g.Recheck(f.ctx, tx, f.scope, aDownloadMFANow(t, f.ctx, f.db)))
			switch {
			case name == "backup_row_lock":
				f.blockedWrite(t, tx, "system_backup_v2_backups", "UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?", f.backup)
			case name == "dependent_row_lock":
				row := f.rows["preflight"]
				f.blockedWrite(t, tx, row.table, "UPDATE "+row.table+" SET row_version=row_version+1 WHERE public_id=?", row.id)
			case name == "empty_prune_range":
				f.pruneRange(t, tx, pruneArgs)
			case strings.HasPrefix(name, "empty_"):
				kind := strings.TrimSuffix(strings.TrimPrefix(name, "empty_"), "_range")
				row := f.rows[kind]
				f.blockedWrite(t, tx, row.table, row.statement, row.args...)
			case strings.HasPrefix(name, "late_"):
				copyGuard := *g
				if name == "late_prune_reference" {
					_, err = tx.ExecContext(f.ctx, dGCTaskPruneItemSQL, pruneArgs...)
				} else {
					row := f.rows["backup"]
					if name == "late_dependent_fact" {
						row = f.rows["preflight"]
					}
					_, err = tx.ExecContext(f.ctx, "UPDATE "+row.table+" SET row_version=row_version+1 WHERE public_id=?", row.id)
				}
				mustSQL(t, err)
				if g.Recheck(f.ctx, tx, f.scope, aDownloadMFANow(t, f.ctx, f.db)) != ErrDenied {
					t.Fatal("late actual fact/reference accepted")
				}
				if name == "late_prune_reference" {
					_, err = tx.ExecContext(f.ctx, "DELETE FROM system_backup_v2_prune_items WHERE public_id=?", pruneArgs[0])
				} else {
					row := f.rows["backup"]
					if name == "late_dependent_fact" {
						row = f.rows["preflight"]
					}
					_, err = tx.ExecContext(f.ctx, "UPDATE "+row.table+" SET row_version=row_version-1 WHERE public_id=?", row.id)
				}
				mustSQL(t, err)
				if copyGuard.Recheck(f.ctx, tx, f.scope, aDownloadMFANow(t, f.ctx, f.db)) != ErrDenied {
					t.Fatal("actual failed guard copy revived after fact restoration")
				}
			}
		})
	}
	if len(dGCTaskMySQLCases) != 18 {
		t.Fatal("GC task case inventory")
	}
	if t.Failed() {
		return
	}
	t.Log("PASS actual SQL GC task component cases=18 scope=synthetic full_gc=not_run role_approval=no production_approval=no")
}
