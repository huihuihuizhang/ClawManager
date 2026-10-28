//go:build systembackup_mysql

package systembackupresources

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

//go:embed testdata/restore-readback-mysql-inputs.json
var restoreMySQLInputs []byte

type restoreMySQLCapsule struct {
	Kind       string `json:"kind"`
	Migrations []struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"migrations"`
	Registry json.RawMessage `json:"registry"`
}

func restoreMySQLOK(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		t.Fatalf("resources SQL experiment error=%d (details redacted)", me.Number)
	}
	t.Fatal("resources SQL experiment failed (details redacted)")
}

func TestDResourcesReadbackMySQLSeed(t *testing.T) {
	var capsule restoreMySQLCapsule
	restoreMySQLOK(t, json.Unmarshal(restoreMySQLInputs, &capsule))
	if capsule.Kind != "d_resources_mysql_synthetic_inputs.v1" || len(capsule.Migrations) == 0 {
		t.Fatal("missing pinned test inputs")
	}
	controls, err := ControlExclusionAllowlist(capsule.Registry)
	restoreMySQLOK(t, err)
	if len(controls) != 35 || len(restoreFieldColumns()) != 9 {
		t.Fatal("closed table set differs")
	}
	got, err := normalizeRestoreFive(context.Background(), restoreFiveFixture())
	restoreMySQLOK(t, err)
	if len(got.Tables) != 5 {
		t.Fatal("incomplete composition")
	}
	t.Log("PASS resources-mysql-seed tables=9 controls=35 five_candidates=5 actual_mysql=not_run synthetic_registry=yes production=no")
}

type restoreMySQLFixture struct {
	ctx                                   context.Context
	admin, writer, reader                 *sql.DB
	config                                *mysql.Config
	database, user, password, server, uid string
	ownedDB, ownedUser                    bool
	registry                              []byte
}

func newRestoreMySQLFixture(t *testing.T) *restoreMySQLFixture {
	t.Helper()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(uid) {
		t.Fatal("exact isolated namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	t.Cleanup(cancel)
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") || cfg.Passwd == "" {
		t.Fatal("isolated IPv4 MySQL credentials required")
	}
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "lock_wait_timeout": "3"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	restoreMySQLOK(t, err)
	t.Cleanup(func() { restoreMySQLOK(t, admin.Close()) })
	var markerRun, markerUID, markerServer, server, version string
	restoreMySQLOK(t, admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&markerRun, &markerUID, &markerServer))
	restoreMySQLOK(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION()").Scan(&server, &version))
	if markerRun != run || markerUID != uid || markerServer != server || !strings.HasPrefix(version, "8.4.") {
		t.Fatal("database outside exact MySQL 8.4 test run")
	}
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	restoreMySQLOK(t, err)
	sum := sha256.Sum256(raw)
	if len(raw) > 1048576 || hex.EncodeToString(sum[:]) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || string(raw) != string(restoreMySQLInputs) {
		t.Fatal("binary-pinned capsule differs")
	}
	var capsule restoreMySQLCapsule
	restoreMySQLOK(t, json.Unmarshal(raw, &capsule))
	rows, err := admin.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	restoreMySQLOK(t, err)
	var ledger []string
	for rows.Next() {
		var name string
		restoreMySQLOK(t, rows.Scan(&name))
		ledger = append(ledger, name)
	}
	restoreMySQLOK(t, rows.Err())
	restoreMySQLOK(t, rows.Close())
	var expected []string
	for _, m := range capsule.Migrations {
		expected = append(expected, m.Name)
	}
	if !reflect.DeepEqual(ledger, expected) {
		t.Fatal("formal migration ledger differs")
	}
	var entropy [26]byte
	_, err = rand.Read(entropy[:])
	restoreMySQLOK(t, err)
	nonce := hex.EncodeToString(entropy[:10])
	f := &restoreMySQLFixture{ctx: ctx, admin: admin, config: cfg, database: "drsr_" + nonce, user: "drsr_" + nonce, password: hex.EncodeToString(entropy[10:]), server: server, uid: uid, registry: capsule.Registry}
	t.Cleanup(func() { f.cleanup(t) })
	f.exec(t, "CREATE DATABASE `"+f.database+"`")
	f.ownedDB = true
	f.exec(t, "CREATE TABLE `"+f.database+"`.resources_probe_owner(uid VARCHAR(36) PRIMARY KEY,server_uuid VARCHAR(36)) ENGINE=InnoDB")
	f.exec(t, "INSERT INTO `"+f.database+"`.resources_probe_owner VALUES(?,?)", uid, server)
	controls, err := ControlExclusionAllowlist(f.registry)
	restoreMySQLOK(t, err)
	for name := range restoreFieldColumns() {
		controls = append(controls, name)
	}
	sort.Strings(controls)
	for _, name := range controls {
		f.exec(t, "CREATE TABLE `"+f.database+"`.`"+name+"` LIKE clawmanager.`"+name+"`")
	}
	// LIKE retains real column/index/check definitions, deliberately omits FKs.
	// This suite tests reads and storage representation, never restore FK proof.
	f.exec(t, "CREATE USER '"+f.user+"'@'%' IDENTIFIED BY '"+f.password+"'")
	f.ownedUser = true
	f.exec(t, "GRANT SELECT ON `"+f.database+"`.* TO '"+f.user+"'@'%'")
	f.writer = f.pool(t, "root", cfg.Passwd, f.database)
	f.reader = f.pool(t, f.user, f.password, f.database)
	t.Logf("RESOURCES_FIXTURE mysql=%s migrations=%d tables=44 clone=LIKE foreign_key_proof=no synthetic_registry=yes", version, len(ledger))
	return f
}

func (f *restoreMySQLFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	_, err := f.admin.ExecContext(f.ctx, q, args...)
	restoreMySQLOK(t, err)
}
func (f *restoreMySQLFixture) pool(t *testing.T, user, password, database string) *sql.DB {
	t.Helper()
	cfg := f.config.Clone()
	cfg.User = user
	cfg.Passwd = password
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	restoreMySQLOK(t, err)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(0)
	t.Cleanup(func() { restoreMySQLOK(t, db.Close()) })
	return db
}
func (f *restoreMySQLFixture) cleanup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if f.ownedUser {
		_, err := f.admin.ExecContext(ctx, "DROP USER '"+f.user+"'@'%'")
		restoreMySQLOK(t, err)
	}
	if f.ownedDB {
		var uid, server string
		err := f.admin.QueryRowContext(ctx, "SELECT uid,server_uuid FROM `"+f.database+"`.resources_probe_owner").Scan(&uid, &server)
		if err != nil || uid != f.uid || server != f.server {
			t.Error("CLEANUP_PENDING resources probe owner identity unavailable")
			return
		}
		_, err = f.admin.ExecContext(ctx, "DROP DATABASE `"+f.database+"`")
		restoreMySQLOK(t, err)
	}
	var databases, users int
	restoreMySQLOK(t, f.admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", f.database).Scan(&databases))
	restoreMySQLOK(t, f.admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User=?", f.user).Scan(&users))
	if databases != 0 || users != 0 {
		t.Fatal("CLEANUP_PENDING resources probe account/database")
	}
	t.Log("CLEANED resources-mysql-owned-database-and-user=yes")
}

type restoreMySQLTargetProof struct{ f *restoreMySQLFixture }

func (p restoreMySQLTargetProof) VerifyReadOnlyTarget(ctx context.Context, tx *sql.Tx) error {
	var user, database, server, role string
	err := tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),DATABASE(),@@server_uuid,CURRENT_ROLE()").Scan(&user, &database, &server, &role)
	if err != nil || user != p.f.user+"@%" || database != p.f.database || server != p.f.server || role != "NONE" {
		return errors.New("synthetic target session differs")
	}
	return nil
}
func (f *restoreMySQLFixture) proofs() restoreReadbackProofs {
	return restoreReadbackProofs{Target: restoreMySQLTargetProof{f}, Candidate: func(context.Context, *sql.Tx, []restoreFieldTable) error { return nil }, Final: func(ctx context.Context, tx *sql.Tx) error {
		return (restoreMySQLTargetProof{f}).VerifyReadOnlyTarget(ctx, tx)
	}}
}

func (f *restoreMySQLFixture) seed(t *testing.T, tables []restoreFieldTable) {
	t.Helper()
	for name := range restoreFieldColumns() {
		_, err := f.writer.ExecContext(f.ctx, "DELETE FROM `"+name+"`")
		restoreMySQLOK(t, err)
	}
	for _, table := range tables {
		for _, row := range table.Rows {
			var args []any
			var names, marks []string
			for _, column := range table.Columns {
				names = append(names, "`"+column+"`")
				marks = append(marks, "?")
				if row[column] == nil {
					args = append(args, nil)
				} else {
					args = append(args, *row[column])
				}
			}
			_, err := f.writer.ExecContext(f.ctx, "INSERT INTO `"+table.Name+"` ("+strings.Join(names, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
			restoreMySQLOK(t, err)
		}
	}
}

// Explicit SQL storage fixtures, not C-normalized rows or report acceptance.
func restoreMySQLExpected(t *testing.T) []restoreFieldTable {
	t.Helper()
	five, err := normalizeRestoreFive(context.Background(), restoreFiveFixture())
	restoreMySQLOK(t, err)
	tables := restoreFiveReadbackShape(five.Tables)
	for i := range tables {
		table := &tables[i]
		if !strings.HasPrefix(table.Name, "security_scan_") {
			continue
		}
		row := restoreFieldRow{}
		for _, column := range table.Columns {
			row[column] = fieldString("1")
		}
		for _, column := range []string{"created_at", "updated_at", "started_at", "finished_at"} {
			if _, ok := row[column]; ok {
				row[column] = fieldString("2026-10-22 01:02:03")
			}
		}
		switch table.Name {
		case "security_scan_configs":
			row["default_mode"] = fieldString("quick")
			row["quick_analyzers_json"] = fieldString("[]")
			row["deep_analyzers_json"] = fieldString("[]")
		case "security_scan_jobs":
			row["asset_type"] = fieldString("skill")
			row["scan_mode"] = fieldString("quick")
			row["status"] = fieldString("failed")
			row["scope_json"] = nil
			row["current_item_name"] = fieldString("")
		case "security_scan_job_items":
			row["asset_type"] = fieldString("skill")
			row["asset_name"] = fieldString("synthetic")
			row["status"] = fieldString("failed")
			row["risk_level"] = nil
			row["summary"] = fieldString("")
			row["scan_result_id"] = nil
			row["error_message"] = fieldString("")
		case "security_scan_reports":
			row["summary_json"] = fieldString(`{"synthetic":true}`)
		}
		table.Rows = []restoreFieldRow{row}
	}
	return tables
}

func restoreMySQLEmpty() []restoreFieldTable {
	var empty []restoreFieldTable
	for name, columns := range restoreFieldColumns() {
		empty = append(empty, restoreFieldTable{Name: name, Columns: columns})
	}
	return empty
}

func TestDResourcesReadbackMySQL(t *testing.T) {
	f := newRestoreMySQLFixture(t)
	expected := restoreMySQLExpected(t)
	t.Run("five_candidates_and_nine_storage_tables", func(t *testing.T) {
		f.seed(t, expected)
		restoreMySQLOK(t, verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()))
	})
	t.Run("null_is_not_empty", func(t *testing.T) {
		f.seed(t, expected)
		_, err := f.writer.ExecContext(f.ctx, "UPDATE security_scan_jobs SET scope_json='' WHERE id=1")
		restoreMySQLOK(t, err)
		if verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()) == nil {
			t.Fatal("NULL/empty mismatch accepted")
		}
	})
	t.Run("decimal_scale_and_fractional_time", func(t *testing.T) {
		f.seed(t, expected)
		var decimal, stamp string
		restoreMySQLOK(t, f.reader.QueryRowContext(f.ctx, "SELECT CAST(lite_cpu_cores AS CHAR),CAST(created_at AS CHAR) FROM northbound_admin_settings WHERE id=1").Scan(&decimal, &stamp))
		if decimal != "0.10" || stamp != "2026-10-22 01:02:03.000001" {
			t.Fatal("exact SQL numeric/time representation differs")
		}
	})
	t.Run("readonly_identity_denies_write", func(t *testing.T) {
		_, err := f.reader.ExecContext(f.ctx, "UPDATE northbound_admin_settings SET version=999 WHERE id=1")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1142 {
			t.Fatal("SELECT-only account did not deny UPDATE with 1142")
		}
	})
	t.Run("readonly_transaction_denies_write", func(t *testing.T) {
		tx, err := f.writer.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		restoreMySQLOK(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(f.ctx, "UPDATE northbound_admin_settings SET version=999 WHERE id=1")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1792 {
			t.Fatal("read-only transaction did not deny privileged UPDATE with 1792")
		}
	})
	t.Run("row_budget", func(t *testing.T) {
		f.seed(t, expected)
		tx, err := f.reader.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		restoreMySQLOK(t, err)
		defer tx.Rollback()
		rows, err := readRestoreFieldRows(f.ctx, tx, restoreFieldBudget{Rows: 1, Bytes: fieldTestBudget.Bytes})
		if err == nil || rows != nil {
			t.Fatal("row budget accepted partial result")
		}
	})
	t.Run("byte_budget", func(t *testing.T) {
		tx, err := f.reader.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		restoreMySQLOK(t, err)
		defer tx.Rollback()
		rows, err := readRestoreFieldRows(f.ctx, tx, restoreFieldBudget{Rows: 100, Bytes: 1})
		if err == nil || rows != nil {
			t.Fatal("byte budget accepted partial result")
		}
	})
	t.Run("repeatable_read_concurrent_change", func(t *testing.T) {
		f.seed(t, expected)
		tx, err := f.reader.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		restoreMySQLOK(t, err)
		defer tx.Rollback()
		before, err := readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
		restoreMySQLOK(t, err)
		_, err = f.writer.ExecContext(f.ctx, "UPDATE northbound_admin_settings SET version=99 WHERE id=1")
		restoreMySQLOK(t, err)
		after, err := readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
		restoreMySQLOK(t, err)
		restoreMySQLOK(t, compareRestoreFields(f.ctx, before, after, fieldTestBudget))
		restoreMySQLOK(t, tx.Commit())
		if verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()) == nil {
			t.Fatal("new snapshot missed committed change")
		}
	})
	t.Run("non_utc_session", func(t *testing.T) {
		conn, err := f.reader.Conn(f.ctx)
		restoreMySQLOK(t, err)
		defer conn.Close()
		_, err = conn.ExecContext(f.ctx, "SET SESSION time_zone='+01:00'")
		restoreMySQLOK(t, err)
		tx, err := conn.BeginTx(f.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		restoreMySQLOK(t, err)
		defer tx.Rollback()
		got, err := readRestoreFieldRows(f.ctx, tx, fieldTestBudget)
		if err == nil || got != nil {
			t.Fatal("non-UTC read accepted")
		}
	})
	t.Run("missing_column", func(t *testing.T) {
		f.seed(t, expected)
		f.exec(t, "ALTER TABLE `"+f.database+"`.security_scan_reports RENAME COLUMN summary_json TO wrong_summary")
		defer f.exec(t, "ALTER TABLE `"+f.database+"`.security_scan_reports RENAME COLUMN wrong_summary TO summary_json")
		if verifyRestoreReadback(f.ctx, f.reader, f.registry, expected, fieldTestBudget, f.proofs()) == nil {
			t.Fatal("schema drift accepted")
		}
	})
	t.Run("empty_tables", func(t *testing.T) {
		empty := restoreMySQLEmpty()
		f.seed(t, empty)
		restoreMySQLOK(t, verifyRestoreReadback(f.ctx, f.reader, f.registry, empty, fieldTestBudget, f.proofs()))
	})
	t.Run("control_row_denied", func(t *testing.T) {
		f.exec(t, "INSERT INTO `"+f.database+"`.system_backup_v2_maintenance_locks(origin_installation_id,scope,lock_ttl_seconds) VALUES('installation_resources_probe','installation',300)")
		var count int
		restoreMySQLOK(t, f.reader.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM system_backup_v2_maintenance_locks").Scan(&count))
		if count == 0 {
			t.Fatal("control-row negative fixture missing")
		}
		candidateReached := false
		proof := f.proofs()
		proof.Candidate = func(context.Context, *sql.Tx, []restoreFieldTable) error { candidateReached = true; return nil }
		if verifyRestoreReadback(f.ctx, f.reader, f.registry, restoreMySQLEmpty(), fieldTestBudget, proof) == nil || !candidateReached {
			t.Fatal("control row accepted")
		}
	})
	t.Log("PASS resources-readback-mysql cases=12 five_normalizers=yes nine_storage_tables=yes controls=35 synthetic_proofs=yes foreign_key_proof=no ddl_freeze_proof=no production=no")
}
