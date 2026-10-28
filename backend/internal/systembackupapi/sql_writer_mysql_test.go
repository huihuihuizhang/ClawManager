package systembackupapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	uuidlib "github.com/google/uuid"
)

type realSubmissionSQL struct {
	ctx       context.Context
	tx        *sql.Tx
	failAudit bool
}

func (q realSubmissionSQL) QueryRow(s string, args ...any) TaskRow {
	return q.tx.QueryRowContext(q.ctx, s, args...)
}
func (q realSubmissionSQL) Exec(s string, args ...any) (sql.Result, error) {
	if q.failAudit && strings.Contains(s, "INSERT INTO system_backup_v2_events") {
		return nil, errors.New("injected audit persistence failure")
	}
	return q.tx.ExecContext(q.ctx, s, args...)
}

func submissionMySQL(t *testing.T) (*sql.DB, *SQLTaskWriter) {
	t.Helper()
	port, err := strconv.Atoi(os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT"))
	if err != nil || port < 1024 || port > 65535 {
		t.Skip("requires task-owned loopback MySQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	host := os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	rootCfg := mysql.Config{User: "root", Net: "tcp", Addr: fmt.Sprintf("%s:%d", host, port), ParseTime: true, AllowNativePasswords: true, Params: map[string]string{"time_zone": "'+00:00'"}}
	root, err := sql.Open("mysql", rootCfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	name := "cm_admission_" + strings.ReplaceAll(uuidlib.NewString(), "-", "")
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+name+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := root.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error(err)
		}
	})
	rootCfg.DBName = name
	db, err := sql.Open("mysql", rootCfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var server string
	if err = db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server); err != nil {
		t.Fatal(err)
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if err = appdb.ApplyPinnedMigrations(ctx, db, appdb.MigrationTarget{ServerUUID: server, Database: name, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples struct {
		Request struct {
			Config json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(fixture, &examples) != nil {
		t.Fatal("fixture config")
	}
	var values map[string]any
	dec := json.NewDecoder(bytes.NewReader(examples.Request.Config))
	dec.UseNumber()
	if err = dec.Decode(&values); err != nil {
		t.Fatal(err)
	}
	values["enabled"] = true
	if os.Getenv("NATIVE_BACKUP_PHYSICAL_CAPACITY") == "true" {
		// Small dedicated native volume, with the same production minimum and
		// safety reserve. This is fixture configuration, not a relaxed checker.
		values["capacity"].(map[string]any)["control_metadata_capacity_bytes"] = json.Number("1073741824")
	}
	for _, v := range values["registries"].([]any) {
		r := v.(map[string]any)
		if r["registry_kind"] == "rbac_bindings" {
			r["version"] = "rbac-admission-v1"
			r["sha256"] = digestJSON([]byte(admissionRBAC))
		}
	}
	canonical, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	flat := map[string]any{"origin_installation_id": "installation_admission", "version": 1, "config_sha256": digestJSON(canonical), "config_size_bytes": len(canonical), "canonical_config_json": canonical, "created_by": "1", "change_reason": "synthetic admission test"}
	for _, k := range []string{"enabled", "alert_profile", "minimum_recovery_points"} {
		flat[k] = values[k]
	}
	for _, group := range []string{"durations", "capacity", "concurrency", "preflight_limits"} {
		for key, value := range values[group].(map[string]any) {
			if group == "preflight_limits" {
				key = "preflight_" + key
			}
			flat[key] = value
		}
	}
	for _, v := range values["registries"].([]any) {
		r := v.(map[string]any)
		kind := r["registry_kind"].(string)
		flat[kind+"_registry_version"] = r["version"]
		flat[kind+"_registry_sha256"] = r["sha256"]
	}
	for _, v := range values["references"].([]any) {
		r := v.(map[string]any)
		kind := r["purpose"].(string)
		flat[kind+"_identity_hash"] = r["identity_hash"]
		flat[kind+"_ref_version"] = r["version"]
	}
	columns := []string{}
	for k := range flat {
		columns = append(columns, k)
	}
	sort.Strings(columns)
	args := []any{}
	for _, k := range columns {
		v := flat[k]
		if n, ok := v.(json.Number); ok {
			v = n.String()
		}
		args = append(args, v)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key) VALUES('installation_admission',1,1,UTC_TIMESTAMP(6),'k8s-cluster')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_engine_bindings(scope,engine) VALUES('installation','v2')"); err != nil {
		t.Fatal(err)
	}
	w, err := NewSQLTaskWriter(testExecutionProfile())
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err = db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		t.Fatal(err)
	}
	report, _ := json.Marshal(security.CapacityReport{ServerUUID: server, Database: name, ObservedAt: now, AllocatedBytes: 1 << 20, AvailableBytes: 1 << 42})
	capacityPath := filepath.Join(t.TempDir(), "capacity.json")
	if err = os.WriteFile(capacityPath, report, 0600); err != nil {
		t.Fatal(err)
	}
	w = w.WithCapacityReport(capacityPath)
	if _, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_readiness(origin_installation_id,task_type,config_version,profile_sha256,owner,generation,ready,checked_at,expires_at) VALUES('installation_admission','backup',1,?,'synthetic-runner',1,1,UTC_TIMESTAMP(6),TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)))`, w.hash); err != nil {
		t.Fatal(err)
	}
	return db, w
}

func TestSQLTaskWriterRealMySQLAtomicReplayAndReadiness(t *testing.T) {
	db, w := submissionMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	stage := func(key, body string, fail bool) (read.TaskHeader, error) {
		prepared, err := w.Prepare(ctx, read.BackupTask, "createSystemBackup", json.RawMessage(body))
		if err != nil {
			return read.TaskHeader{}, err
		}
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return read.TaskHeader{}, err
		}
		defer tx.Rollback()
		task, err := prepared.Stage(realSubmissionSQL{ctx, tx, fail}, TaskSubmissionIdentity{"installation_admission", "1", "createSystemBackup", key})
		if err != nil {
			return read.TaskHeader{}, err
		}
		return task, tx.Commit()
	}
	// Audit failure occurs after task + immutable input insertion. Both roll back.
	if _, err := stage("audit-failure-key-001", `{}`, true); err == nil {
		t.Fatal("audit failure accepted")
	}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_execution_inputs", "system_backup_v2_events"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal(table, n, err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan string, 6)
	failures := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task, err := stage("parallel-same-key-001", `{}`, false)
			if err != nil {
				failures <- err
			} else {
				results <- task.PublicID
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	id := ""
	for got := range results {
		if id != "" && id != got {
			t.Fatal("duplicate task")
		}
		id = got
	}
	if id == "" {
		t.Fatal("no task")
	}
	if _, err := stage("parallel-same-key-001", `{"task_purpose":"functional_test"}`, false); err == nil {
		t.Fatal("different body reused key")
	}
	// An expired adapter must not prevent finding an already committed task.
	if _, err := db.Exec("UPDATE system_backup_v2_execution_readiness SET ready=0"); err != nil {
		t.Fatal(err)
	}
	got, err := stage("parallel-same-key-001", `{}`, false)
	if err != nil || got.PublicID != id {
		t.Fatal("lost committed response cannot be replayed", err)
	}
	if _, err = stage("missing-executor-key-001", `{}`, false); err == nil {
		t.Fatal("created task without executor")
	}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_execution_inputs", "system_backup_v2_events"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 1 {
			t.Fatal(table, n, err)
		}
	}
}
