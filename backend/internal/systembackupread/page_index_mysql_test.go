//go:build systembackup_mysql

package systembackupread

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// This is an isolated, synthetic load review, not a production performance
// approval. CREATE TABLE LIKE preserves columns/indexes/CHECKs, but not FKs.
// The exact production page SQL is reused; auth and HTTP costs are excluded.
func TestDAdminReadIndexCandidateMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := indexProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	indexMust(t, err)
	source, err := sql.Open("mysql", cfg.FormatDSN())
	indexMust(t, err)
	defer source.Close()
	var gotRun, gotUID, pinnedUUID, actualUUID, version string
	indexMust(t, source.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	indexMust(t, source.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION()").Scan(&actualUUID, &version))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("index probe is outside the pinned run-owned MySQL")
	}
	for _, filename := range []string{"097_backup_v2_add_system_backup_config_and_operations.sql", "098_backup_v2_add_system_backup_task_execution_core.sql"} {
		var n int
		indexMust(t, source.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE filename=?", filename).Scan(&n))
		if n != 1 {
			t.Fatal("fresh migration missing", filename)
		}
	}
	ddl, err := os.ReadFile(os.Getenv("D_ADMIN_INDEX_DDL"))
	indexMust(t, err)
	hash := sha256.Sum256(ddl)
	if hex.EncodeToString(hash[:]) != os.Getenv("D_ADMIN_INDEX_DDL_SHA256") || len(ddl) < 500 {
		t.Fatal("index candidate DDL is not pinned")
	}
	variant := os.Getenv("D_ADMIN_INDEX_VARIANT")
	appliedDDL, err := indexVariantDDL(string(ddl), variant)
	indexMust(t, err)
	var nonce [12]byte
	_, err = rand.Read(nonce[:])
	indexMust(t, err)
	name := "didx_" + hex.EncodeToString(nonce[:])
	_, err = source.ExecContext(ctx, "CREATE DATABASE `"+name+"`")
	indexMust(t, err)
	// Cleanup uses a fresh timeout even after a failed/canceled measurement.
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if _, e := source.ExecContext(cleanup, "DROP DATABASE `"+name+"`"); e != nil {
			t.Errorf("CLEANUP_PENDING D admin index run-owned database=%s", name)
		} else {
			t.Log("CLEANED D admin index run-owned database", name)
		}
	}()
	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	indexMust(t, err)
	defer db.Close()
	const rowCount = 12000
	tables := []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_operations"}
	sourceHashes := make(map[string]string)
	for _, table := range tables {
		sourceHashes[table] = indexSchemaHash(t, ctx, source, table)
		_, err = db.ExecContext(ctx, "CREATE TABLE `"+table+"` LIKE clawmanager.`"+table+"`")
		indexMust(t, err)
		tx, e := db.BeginTx(ctx, nil)
		indexMust(t, e)
		func() {
			defer tx.Rollback()
			stmt, e := tx.PrepareContext(ctx, indexSeedSQL(table))
			indexMust(t, e)
			defer stmt.Close()
			for i := 1; i <= rowCount; i++ {
				_, e = stmt.ExecContext(ctx, indexSeedArgs(table, i)...)
				indexMust(t, e)
			}
			indexMust(t, tx.Commit())
		}()
		_, err = db.ExecContext(ctx, indexFailedSQL(table)+" WHERE MOD(id,7)=0")
		indexMust(t, err)
	}
	scope := map[string]any{"kind": "scope", "mysql": version, "run": run, "namespace_uid": uid, "database": name,
		"measurement_version": 2,
		"ddl_sha256":          hex.EncodeToString(hash[:]), "rows_per_table": rowCount, "synthetic": true,
		"foreign_keys_cloned": false, "authorization_http_measured": false, "source_schema_sha256": sourceHashes}
	if variant != "" {
		appliedHash := sha256.Sum256([]byte(appliedDDL))
		scope["index_variant"], scope["applied_ddl"], scope["applied_ddl_sha256"] = variant, appliedDDL, hex.EncodeToString(appliedHash[:])
	}
	emitIndexReview(t, scope)
	baselines := make(map[string]string)
	for _, phase := range []string{"before", "after"} {
		if phase == "after" {
			indexWriterBaseline(t, ctx, db, tables, rowCount, "before")
			indexApplyWithWriter(t, ctx, db, appliedDDL, tables, rowCount)
			indexWriterBaseline(t, ctx, db, tables, rowCount, "after")
		}
		for _, table := range tables {
			indexAnalyze(t, ctx, db, table)
			indexMeasureTable(t, ctx, db, table, phase, rowCount, baselines)
		}
	}
	for _, table := range tables {
		if indexSchemaHash(t, ctx, source, table) != sourceHashes[table] {
			t.Fatal("source schema changed", table)
		}
	}
	t.Log("PASS D admin page index isolated measurements; production approval remains pending")
}

// The supplied full candidate must still match the reviewed nine-index shape.
// Subsets are generated from a closed table/index list, never arbitrary SQL.
// Status-only intentionally leaves operations unchanged: it has no status page.
func indexVariantDDL(full, variant string) (string, error) {
	if variant == "" {
		variant = "all"
	}
	if variant != "all" && variant != "page" && variant != "status" {
		return "", ErrInvalid
	}
	tables := []struct{ table, prefix string }{
		{"system_backup_v2_backups", "idx_sb_backup"}, {"system_backup_v2_restore_drills", "idx_sb_drill"},
		{"system_backup_v2_preflights", "idx_sb_preflight"}, {"system_backup_v2_artifact_verifications", "idx_sb_verify"},
		{"system_backup_v2_operations", "idx_sb_operation"},
	}
	build := func(group string) string {
		var statements []string
		for _, row := range tables {
			var indexes []string
			if group != "status" {
				indexes = append(indexes, "ADD INDEX "+row.prefix+"_admin_page (origin_installation_id, id)")
			}
			if group != "page" && row.table != "system_backup_v2_operations" {
				indexes = append(indexes, "ADD INDEX "+row.prefix+"_admin_status_page (origin_installation_id, status, id)")
			}
			if len(indexes) > 0 {
				statements = append(statements, "ALTER TABLE "+row.table+" "+strings.Join(indexes, ", ")+";")
			}
		}
		return strings.Join(statements, "\n") + "\n"
	}
	var lines []string
	for _, line := range strings.Split(full, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	if strings.Join(strings.Fields(strings.Join(lines, "\n")), " ") != strings.Join(strings.Fields(build("all")), " ") {
		return "", ErrInvalid
	}
	if variant == "all" {
		return full, nil
	}
	return build(variant), nil
}

type indexWriteSpan struct {
	table      string
	begin, end time.Time
}
type indexWriterResult struct {
	samples []int64
	spans   []indexWriteSpan
	err     error
}
type indexWriterDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// The no-DDL baselines and DDL background writer share the exact same
// autocommit insert/delete loop, table rotation and extra fixture IDs.
func indexRunWriter(ctx context.Context, db indexWriterDB, tables []string, count, limit int, stop <-chan struct{}, started chan<- struct{}) indexWriterResult {
	out := indexWriterResult{}
	if len(tables) == 0 || count < 1 || limit < 1 || limit > 10000 {
		out.err = ErrInvalid
		return out
	}
	for offset := 0; offset < limit; offset++ {
		select {
		case <-ctx.Done():
			out.err = ctx.Err()
			return out
		case <-stop:
			return out
		default:
		}
		table := tables[offset%len(tables)]
		i := count + 1000 + offset
		begin := time.Now()
		_, out.err = db.ExecContext(ctx, indexSeedSQL(table), indexSeedArgs(table, i)...)
		if out.err != nil {
			return out
		}
		_, out.err = db.ExecContext(ctx, "DELETE FROM "+table+" WHERE public_id=?", indexSeedArgs(table, i)[0])
		if out.err != nil {
			return out
		}
		end := time.Now()
		out.samples = append(out.samples, end.Sub(begin).Microseconds())
		out.spans = append(out.spans, indexWriteSpan{table, begin, end})
		if len(out.samples) == 1 && started != nil {
			close(started)
		}
	}
	return out
}

func indexWriterCounts(spans []indexWriteSpan, tables []string) map[string]int {
	counts := make(map[string]int, len(tables))
	for _, table := range tables {
		counts[table] = 0
	}
	for _, span := range spans {
		counts[span.table]++
	}
	return counts
}

func indexOverlappingWrites(spans []indexWriteSpan, begin, end time.Time) ([]indexWriteSpan, []int64) {
	selected, samples := []indexWriteSpan{}, []int64{}
	for _, span := range spans {
		if span.begin.Before(end) && span.end.After(begin) {
			selected = append(selected, span)
			samples = append(samples, span.end.Sub(span.begin).Microseconds())
		}
	}
	return selected, samples
}

func indexResetExtraRows(t *testing.T, ctx context.Context, db *sql.DB, tables []string, count int) {
	t.Helper()
	for _, table := range tables {
		_, err := db.ExecContext(ctx, "DELETE FROM "+table+" WHERE id>?", count)
		indexMust(t, err)
		_, err = db.ExecContext(ctx, "ALTER TABLE "+table+" AUTO_INCREMENT="+fmt.Sprint(count+1))
		indexMust(t, err)
	}
}

func indexWriterBaseline(t *testing.T, ctx context.Context, db *sql.DB, tables []string, count int, phase string) {
	t.Helper()
	result := make(chan indexWriterResult, 1)
	begin := time.Now()
	go func() { result <- indexRunWriter(ctx, db, tables, count, 30, nil, nil) }()
	out := <-result
	indexMust(t, out.err)
	if len(out.samples) != 30 {
		t.Fatal("incomplete no-DDL writer baseline")
	}
	emitIndexReview(t, map[string]any{"kind": "ddl_writer_baseline", "phase": phase, "write_pairs": len(out.samples),
		"table_write_pairs": indexWriterCounts(out.spans, tables), "autocommit": true, "ddl_in_progress": false,
		"elapsed_us": time.Since(begin).Microseconds(), "insert_delete_pair_us": indexPercentiles(out.samples)})
	indexResetExtraRows(t, ctx, db, tables, count)
}

// Measure the candidate ALTERs while a second connection autocommits a bounded
// insert/delete stream. Only extra fixture rows are touched; they are removed
// and the allocator reset before comparing the original page results.
func indexApplyWithWriter(t *testing.T, ctx context.Context, db *sql.DB, ddl string, tables []string, count int) {
	t.Helper()
	started, stop := make(chan struct{}), make(chan struct{})
	result := make(chan indexWriterResult, 1)
	go func() {
		result <- indexRunWriter(ctx, db, tables, count, 10000, stop, started)
	}()
	select {
	case <-started:
	case out := <-result:
		close(stop)
		indexMust(t, out.err)
		t.Fatal("concurrent writer ended before DDL")
	case <-ctx.Done():
		close(stop)
		<-result
		indexMust(t, ctx.Err())
	}
	begin := time.Now()
	_, ddlErr := db.ExecContext(ctx, ddl)
	end := time.Now()
	elapsed := end.Sub(begin).Microseconds()
	close(stop)
	out := <-result
	indexMust(t, ddlErr)
	indexMust(t, out.err)
	overlapSpans, overlapSamples := indexOverlappingWrites(out.spans, begin, end)
	if len(overlapSpans) == 0 {
		t.Fatal("no concurrent write pair overlapped candidate DDL")
	}
	emitIndexReview(t, map[string]any{"kind": "ddl", "elapsed_us": elapsed, "concurrent_writes_measured": true,
		"write_pairs": len(out.samples), "overlapping_write_pairs": len(overlapSpans), "insert_delete_pair_us": indexPercentiles(out.samples), "writer_loop_limit": 10000,
		"table_write_pairs": indexWriterCounts(out.spans, tables), "overlapping_table_write_pairs": indexWriterCounts(overlapSpans, tables),
		"overlapping_insert_delete_pair_us": indexPercentiles(overlapSamples)})
	indexResetExtraRows(t, ctx, db, tables, count)
}

func indexAnalyze(t *testing.T, ctx context.Context, db *sql.DB, table string) {
	t.Helper()
	rows, err := db.QueryContext(ctx, "ANALYZE TABLE `"+table+"`")
	indexMust(t, err)
	defer rows.Close()
	ok := false
	for rows.Next() {
		var name, operation, kind, message string
		indexMust(t, rows.Scan(&name, &operation, &kind, &message))
		if kind == "error" {
			t.Fatal("ANALYZE TABLE failed", table, message)
		}
		if kind == "status" && message == "OK" {
			ok = true
		}
	}
	indexMust(t, rows.Err())
	if !ok {
		t.Fatal("ANALYZE TABLE did not confirm updated statistics", table)
	}
}

func indexProbeConfig(run, uid, host, password string) (*mysql.Config, error) {
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uid) || password == "" {
		return nil, ErrInvalid
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") {
		return nil, ErrInvalid
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "root", password, "tcp", net.JoinHostPort(host, "3306"), "clawmanager"
	c.ParseTime, c.Loc, c.MultiStatements = true, time.UTC, true
	c.Params = map[string]string{"time_zone": "'+00:00'"}
	c.Timeout, c.ReadTimeout, c.WriteTimeout = 5*time.Second, 60*time.Second, 60*time.Second
	return c, nil
}

func indexSchemaHash(t *testing.T, ctx context.Context, db *sql.DB, table string) string {
	t.Helper()
	var name, ddl string
	indexMust(t, db.QueryRowContext(ctx, "SHOW CREATE TABLE `"+table+"`").Scan(&name, &ddl))
	h := sha256.Sum256([]byte(ddl))
	return hex.EncodeToString(h[:])
}

func indexSeedSQL(table string) string {
	if table == "system_backup_v2_operations" {
		return `INSERT INTO system_backup_v2_operations (public_id,origin_installation_id,idempotency_key,created_at,next_reconcile_at,
operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,request_hash,
external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,deadline_at,status)
VALUES (?,?,?,?,?,'control_metadata_gc','system',?,'system','system:controller','IndexProbe',REPEAT('a',64),'[]',2,SHA2('[]',256),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,'pending')`
	}
	common := `INSERT INTO ` + table + ` (public_id,origin_installation_id,idempotency_key,request_id,created_at,next_reconcile_at,
actor_type,actor_id,endpoint,request_hash,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,`
	values := ` VALUES (?,?,?,?,?,?,'admin','1','IndexProbe',REPEAT('a',64),1,'{}',2,SHA2('{}',256),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,`
	switch table {
	case "system_backup_v2_backups":
		return common + `source_orchestrator,source_profile,matrix_key,runner,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id)` + values + `'kubernetes','single-node','k8s-single-node','k8s','mysql',REPEAT('b',64),'fixture-v1',REPEAT('c',64),'fixture-v1','dr-ready-external','','isolated')`
	case "system_backup_v2_restore_drills", "system_backup_v2_preflights":
		extra, value := "cleanup_policy", "delete-on-success"
		if table == "system_backup_v2_preflights" {
			extra, value = "artifact_compatibility", "supported"
		}
		return common + `source_artifact_type,source_public_id,target_profile,restore_target_config_ref,restore_target_config_hash,` + extra + `)` + values + `'backup','sbk_00000000-0000-4000-8000-000000000001','single-node','isolated-target',REPEAT('d',64),'` + value + `')`
	case "system_backup_v2_artifact_verifications":
		return common + `verification_scope,source_artifact_type,source_public_id,artifact_state_before,artifact_state_after,unusable_reason_before,unusable_reason_after)` + values + `'health','backup','sbk_00000000-0000-4000-8000-000000000001','staging','staging','not_committed','not_committed')`
	}
	panic("unrecognized index probe table")
}

func indexSeedArgs(table string, i int) []any {
	prefix := map[string]string{"system_backup_v2_backups": "sbk_", "system_backup_v2_restore_drills": "sdr_", "system_backup_v2_preflights": "spf_", "system_backup_v2_artifact_verifications": "sav_", "system_backup_v2_operations": "sop_"}[table]
	installation := "installation_index_foreign"
	if i%10 < 2 {
		installation = "installation_index_own"
	} else if i%10 == 9 {
		installation = "installation_index_sparse"
	}
	// Non-monotonic time/reconcile columns prevent an accidental time-index
	// correlation from disguising the cost of sorting by id.
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i*7919%86400) * time.Second)
	args := []any{fmt.Sprintf("%s00000000-0000-4000-8000-%012d", prefix, i), installation, fmt.Sprintf("index-probe-key-%012d", i)}
	if table != "system_backup_v2_operations" {
		args = append(args, fmt.Sprintf("index-%d", i))
	}
	args = append(args, created, created.Add(time.Duration(i%17)*time.Minute))
	if table == "system_backup_v2_operations" {
		args = append(args, installation)
	}
	return args
}

func indexFailedSQL(table string) string {
	update := "UPDATE " + table + " SET status='failed',failure_category='internal_error',started_at=UTC_TIMESTAMP(6),finished_at=UTC_TIMESTAMP(6),next_reconcile_at=NULL"
	if table != "system_backup_v2_operations" {
		update += ",can_cancel=FALSE"
	}
	return update
}

func indexMeasureTable(t *testing.T, ctx context.Context, db *sql.DB, table, phase string, count int, baselines map[string]string) {
	t.Helper()
	update := indexFailedSQL(table)
	var total int
	indexMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&total))
	if total != count {
		t.Fatal("index fixture row count drift", table, total)
	}
	distribution, err := db.QueryContext(ctx, "SELECT origin_installation_id,status,COUNT(*) FROM "+table+" GROUP BY origin_installation_id,status ORDER BY origin_installation_id,status")
	indexMust(t, err)
	for distribution.Next() {
		var installation, status string
		var n int
		indexMust(t, distribution.Scan(&installation, &status, &n))
		emitIndexReview(t, map[string]any{"kind": "distribution", "phase": phase, "table": table, "installation": installation, "status": status, "rows": n})
	}
	indexMust(t, distribution.Err())
	indexMust(t, distribution.Close())
	for _, installation := range []string{"installation_index_own", "installation_index_foreign", "installation_index_sparse"} {
		indexMeasureQuery(t, ctx, db, table, phase, "cutoff", "SELECT COALESCE(MAX(id),0) FROM "+table+" WHERE origin_installation_id=?", []any{installation}, baselines)
		for _, upper := range []int{count + 1, count / 2} {
			for _, limit := range []int{51, 501} {
				query := operationPageSQL
				if table != "system_backup_v2_operations" {
					query = taskPageSQL(taskTable{name: table}, false)
				}
				indexMeasureQuery(t, ctx, db, table, phase, "page", query, []any{installation, upper, limit}, baselines)
				if table != "system_backup_v2_operations" {
					for _, status := range []string{"pending", "failed"} {
						indexMeasureQuery(t, ctx, db, table, phase, "status_page", taskPageSQL(taskTable{name: table}, true), []any{installation, upper, status, limit}, baselines)
					}
				}
			}
		}
	}
	var indexPages, pageSize int64
	indexMust(t, db.QueryRowContext(ctx, `SELECT COALESCE(SUM(stat_value),0),@@innodb_page_size FROM mysql.innodb_index_stats WHERE database_name=? AND table_name=? AND stat_name='size' AND index_name <> 'PRIMARY'`, dbName(t, ctx, db), table).Scan(&indexPages, &pageSize))
	emitIndexReview(t, map[string]any{"kind": "storage", "phase": phase, "table": table, "secondary_index_allocated_bytes": indexPages * pageSize})
	insertSamples, updateSamples := []int64{}, []int64{}
	for i := count + 1; i <= count+30; i++ {
		start := time.Now()
		_, err = db.ExecContext(ctx, indexSeedSQL(table), indexSeedArgs(table, i)...)
		indexMust(t, err)
		insertSamples = append(insertSamples, time.Since(start).Microseconds())
		start = time.Now()
		_, err = db.ExecContext(ctx, update+" WHERE id=?", i)
		indexMust(t, err)
		updateSamples = append(updateSamples, time.Since(start).Microseconds())
	}
	emitIndexReview(t, map[string]any{"kind": "write", "phase": phase, "table": table, "samples": 30, "autocommit": true, "insert_us": indexPercentiles(insertSamples), "status_update_us": indexPercentiles(updateSamples)})
	_, err = db.ExecContext(ctx, "DELETE FROM "+table+" WHERE id>?", count)
	indexMust(t, err)
	_, err = db.ExecContext(ctx, "ALTER TABLE "+table+" AUTO_INCREMENT="+fmt.Sprint(count+1))
	indexMust(t, err)
}

func indexMeasureQuery(t *testing.T, ctx context.Context, db *sql.DB, table, phase, kind, query string, args []any, baselines map[string]string) {
	t.Helper()
	var plan string
	indexMust(t, db.QueryRowContext(ctx, "EXPLAIN ANALYZE "+query, args...).Scan(&plan))
	samples := make([]int64, 0, 30)
	keyArgs, err := json.Marshal(args)
	indexMust(t, err)
	key := query + string(keyArgs)
	identityRows, err := db.QueryContext(ctx, query, args...)
	indexMust(t, err)
	resultHash, resultCount, err := indexResult(identityRows)
	indexMust(t, err)
	if prior, ok := baselines[key]; ok && prior != resultHash {
		t.Fatal("page changed across index phases", table, kind)
	}
	baselines[key] = resultHash
	for i := 0; i < 31; i++ {
		start := time.Now()
		rows, err := db.QueryContext(ctx, query, args...)
		indexMust(t, err)
		indexMust(t, indexDrain(rows))
		if i > 0 {
			samples = append(samples, time.Since(start).Microseconds())
		}
	}
	emitIndexReview(t, map[string]any{"kind": kind, "phase": phase, "table": table, "sql": query, "args": args, "explain_analyze": plan, "samples": 30, "result_rows": resultCount, "result_sha256": baselines[key], "warm_cache_us": indexPercentiles(samples)})
}

func indexResult(rows *sql.Rows) (string, int, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "", 0, err
	}
	values := make([]any, len(cols))
	targets := make([]any, len(cols))
	for i := range values {
		targets[i] = &values[i]
	}
	hash := sha256.New()
	n := 0
	for rows.Next() {
		if err = rows.Scan(targets...); err != nil {
			return "", 0, err
		}
		raw, e := json.Marshal(values)
		if e != nil {
			return "", 0, e
		}
		hash.Write(raw)
		hash.Write([]byte{'\n'})
		n++
	}
	if err = rows.Err(); err != nil {
		return "", 0, err
	}
	if err = rows.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

func indexDrain(rows *sql.Rows) error {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	values := make([]any, len(cols))
	targets := make([]any, len(cols))
	for i := range values {
		targets[i] = &values[i]
	}
	for rows.Next() {
		if err = rows.Scan(targets...); err != nil {
			return err
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return rows.Close()
}
func dbName(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var name string
	indexMust(t, db.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&name))
	return name
}
func indexPercentiles(values []int64) map[string]int64 {
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return map[string]int64{"p50": sorted[(len(sorted)*50+99)/100-1], "p95": sorted[(len(sorted)*95+99)/100-1]}
}
func indexMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func emitIndexReview(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	indexMust(t, err)
	t.Log("D_ADMIN_INDEX_REVIEW " + string(raw))
}

// Local checks exercise input rejection, distribution and sample math without
// opening a database. The measured MySQL test is selected only by the harness.
func TestDAdminReadIndexSeed(t *testing.T) {
	t.Run("grouped_candidates_reject_unreviewed_SQL", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "system-backup-d-admin-read-index-candidate-20261012.sql"))
		indexMust(t, err)
		for _, group := range []string{"", "all", "page", "status"} {
			ddl, err := indexVariantDDL(string(raw), group)
			indexMust(t, err)
			want := map[string]int{"": 9, "all": 9, "page": 5, "status": 4}[group]
			if strings.Count(ddl, "ADD INDEX") != want {
				t.Fatal("wrong candidate cardinality", group)
			}
			if group == "page" && strings.Contains(ddl, "status, id") {
				t.Fatal("page group contains status index")
			}
			if group == "status" && (strings.Contains(ddl, "system_backup_v2_operations") || strings.Contains(ddl, "(origin_installation_id, id)")) {
				t.Fatal("status group includes page-only indexes")
			}
		}
		for _, input := range []string{string(raw) + "DROP TABLE users;", strings.Replace(string(raw), "idx_sb_backup_admin_page", "idx_unreviewed", 1), strings.Replace(string(raw), "origin_installation_id, status, id", "origin_installation_id, id, status", 1)} {
			if _, err := indexVariantDDL(input, "page"); err == nil {
				t.Fatal("unreviewed DDL accepted")
			}
		}
		if _, err := indexVariantDDL(string(raw), "custom"); err == nil {
			t.Fatal("unknown group accepted")
		}
	})
	t.Run("writer_baselines_and_ddl_share_bounded_pairs", testIndexWriterStream)
	t.Run("ddl_overlap_excludes_nonoverlapping_pairs", func(t *testing.T) {
		begin := time.Now()
		end := begin.Add(time.Second)
		spans := []indexWriteSpan{
			{"system_backup_v2_backups", begin.Add(-time.Second), begin},
			{"system_backup_v2_restore_drills", end, end.Add(time.Second)},
			{"system_backup_v2_preflights", begin.Add(-time.Millisecond), begin.Add(time.Millisecond)},
			{"system_backup_v2_artifact_verifications", end.Add(-time.Millisecond), end.Add(time.Millisecond)},
		}
		selected, samples := indexOverlappingWrites(spans, begin, end)
		if len(selected) != 2 || len(samples) != 2 || samples[0] != 2000 || samples[1] != 2000 {
			t.Fatal("overlap boundary or latency changed", selected, samples)
		}
	})
	run, uid := "sbk-mig-261014000000-abcd", "11111111-2222-3333-4444-555555555555"
	for _, input := range [][4]string{{"production", uid, "", "secret"}, {run, "bad", "", "secret"}, {run, uid, "mysql.example", "secret"}, {run, uid, "::1", "secret"}, {run, uid, "", ""}} {
		if _, err := indexProbeConfig(input[0], input[1], input[2], input[3]); err == nil {
			t.Fatal("unsafe probe input accepted")
		}
	}
	if _, err := indexProbeConfig(run, uid, "", "secret"); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for i := 1; i <= 12000; i++ {
		counts[indexSeedArgs("system_backup_v2_backups", i)[1].(string)]++
	}
	if counts["installation_index_own"] != 2400 || counts["installation_index_foreign"] != 8400 || counts["installation_index_sparse"] != 1200 {
		t.Fatal("fixture distribution", counts)
	}
	p := indexPercentiles([]int64{10, 2, 4, 8, 6})
	if p["p50"] != 6 || p["p95"] != 10 {
		t.Fatal("percentile", p)
	}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_operations"} {
		if strings.Count(indexSeedSQL(table), "?") != len(indexSeedArgs(table, 1)) {
			t.Fatal("seed parameter count", table)
		}
		migration := "098_backup_v2_add_system_backup_task_execution_core.sql"
		if table == "system_backup_v2_operations" {
			migration = "097_backup_v2_add_system_backup_config_and_operations.sql"
		}
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", migration))
		indexMust(t, err)
		_, body, found := strings.Cut(string(raw), "CREATE TABLE IF NOT EXISTS "+table+" (")
		if !found {
			t.Fatal("seed table missing from migration", table)
		}
		body, _, found = strings.Cut(body, ") ENGINE=InnoDB")
		if !found {
			t.Fatal("seed table has no schema boundary", table)
		}
		_, columns, _ := strings.Cut(indexSeedSQL(table), " (")
		columns, _, _ = strings.Cut(columns, ")")
		for _, column := range strings.Split(columns, ",") {
			column = strings.TrimSpace(column)
			if !regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(column) + `\s+`).MatchString(body) {
				t.Fatal("seed column absent from migrated table", table, column)
			}
		}
	}
	for i := 1; i <= 10; i++ {
		args := indexSeedArgs("system_backup_v2_operations", i)
		if args[1] != args[5] {
			t.Fatal("operation system target must equal installation")
		}
	}
}

// Fake writes validate the common stream's lifecycle and error paths. These
// local assertions do not claim MySQL latency, DDL overlap or cleanup evidence.
type indexWriterFixture struct {
	rows          map[string]map[string]bool
	calls, failAt int
	stopAfterPair func()
}

var indexWriterFixtureTables = []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_operations"}
var errIndexWriterFixture = errors.New("synthetic index writer SQL failure")

func (f *indexWriterFixture) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	f.calls++
	if f.calls == f.failAt {
		return nil, errIndexWriterFixture
	}
	for _, table := range indexWriterFixtureTables {
		if query == indexSeedSQL(table) {
			if len(args) != len(indexSeedArgs(table, 1)) {
				return nil, errors.New("wrong insert projection")
			}
			id, ok := args[0].(string)
			if !ok || f.rows[table][id] {
				return nil, errors.New("duplicate insert or invalid ID")
			}
			f.rows[table][id] = true
			return driver.RowsAffected(1), nil
		}
		if query == "DELETE FROM "+table+" WHERE public_id=?" {
			if len(args) != 1 {
				return nil, errors.New("wrong delete scope")
			}
			id, ok := args[0].(string)
			if !ok || !f.rows[table][id] {
				return nil, errors.New("delete did not match inserted fixture row")
			}
			delete(f.rows[table], id)
			if f.stopAfterPair != nil {
				f.stopAfterPair()
				f.stopAfterPair = nil
			}
			return driver.RowsAffected(1), nil
		}
	}
	return nil, errors.New("writer touched nonfixture SQL")
}
func newIndexWriterFixture() *indexWriterFixture {
	f := &indexWriterFixture{rows: make(map[string]map[string]bool)}
	for _, table := range indexWriterFixtureTables {
		f.rows[table] = make(map[string]bool)
	}
	return f
}
func testIndexWriterStream(t *testing.T) {
	t.Run("complete_balanced_pairs", func(t *testing.T) {
		f := newIndexWriterFixture()
		started := make(chan struct{})
		out := indexRunWriter(context.Background(), f, indexWriterFixtureTables, 12000, 30, nil, started)
		if out.err != nil || len(out.samples) != 30 || len(out.spans) != 30 || f.calls != 60 {
			t.Fatal("incomplete writer pairs", out.err, len(out.samples), f.calls)
		}
		select {
		case <-started:
		default:
			t.Fatal("first complete pair did not signal DDL startup")
		}
		counts := indexWriterCounts(out.spans, indexWriterFixtureTables)
		for _, table := range indexWriterFixtureTables {
			if len(f.rows[table]) != 0 || counts[table] != 6 {
				t.Fatal("writer left rows or changed table distribution", table, counts)
			}
		}
	})
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint("SQL_failure_", failAt), func(t *testing.T) {
			f := newIndexWriterFixture()
			f.failAt = failAt
			out := indexRunWriter(context.Background(), f, indexWriterFixtureTables, 12000, 30, nil, nil)
			if !errors.Is(out.err, errIndexWriterFixture) || f.calls != failAt || len(out.samples) != (failAt-1)/2 {
				t.Fatal("failed pair was retried/counted", out.err, len(out.samples), f.calls)
			}
			if failAt == 2 && len(f.rows[indexWriterFixtureTables[0]]) != 1 {
				t.Fatal("failed delete fixture did not preserve residual for run-owned DB cleanup")
			}
		})
	}
	t.Run("canceled_before_SQL", func(t *testing.T) {
		f := newIndexWriterFixture()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out := indexRunWriter(ctx, f, indexWriterFixtureTables, 12000, 30, nil, nil)
		if !errors.Is(out.err, context.Canceled) || f.calls != 0 {
			t.Fatal("canceled writer touched SQL", out.err, f.calls)
		}
	})
	t.Run("stop_after_complete_pair", func(t *testing.T) {
		f := newIndexWriterFixture()
		stop := make(chan struct{})
		f.stopAfterPair = func() { close(stop) }
		out := indexRunWriter(context.Background(), f, indexWriterFixtureTables, 12000, 10000, stop, nil)
		if out.err != nil || len(out.samples) != 1 || f.calls != 2 || len(f.rows[indexWriterFixtureTables[0]]) != 0 {
			t.Fatal("writer stop lost/deleted a partial pair", out.err, f.calls)
		}
	})
	t.Run("invalid_loop_bounds", func(t *testing.T) {
		for _, limit := range []int{0, -1, 10001} {
			f := newIndexWriterFixture()
			out := indexRunWriter(context.Background(), f, indexWriterFixtureTables, 12000, limit, nil, nil)
			if !errors.Is(out.err, ErrInvalid) || f.calls != 0 {
				t.Fatal("unbounded writer accepted", limit, out.err, f.calls)
			}
		}
	})
}
