package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

type controlPrefixNativeFixture struct {
	db, admin *sql.DB
	schema    string
}

// No application schema/account is reused. The independent server UUID and
// real SAN/TLS 1.3 are verified BEFORE creating a random, exactly owned schema.
// Root alone executes this opt-in fixture and removes test/build artifacts.
func newControlPrefixNativeFixture(t *testing.T, ctx context.Context) controlPrefixNativeFixture {
	t.Helper()
	path, pin := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" {
		t.Skip("requires supervisor disposable SAN/TLS MySQL and independent UUID pin")
	}
	var cred struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable credentials unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&cred)
	tail := decoder.Decode(new(any))
	clear(raw)
	if err != nil || tail != io.EOF || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(pin) || cred.ServerUUID != pin || cred.Host != "127.0.0.1" || cred.Port < 1024 || cred.Port > 65535 || cred.Port == 3306 || cred.User == "" || cred.Password == "" || cred.TLSServerName == "" || !filepath.IsAbs(cred.CAFile) {
		t.Fatal("wrong disposable credentials/UUID pin")
	}
	ca, err := os.ReadFile(cred.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable CA unavailable")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("private fixture nonce")
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "a-current-prefix-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: cred.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("disposable TLS registration")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = cred.User, cred.Password
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc, cfg.InterpolateParams = tlsName, true, time.UTC, true
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("disposable admin connection")
	}
	t.Cleanup(func() { admin.Close() })
	var actual, version string
	if admin.QueryRowContext(ctx, `SELECT @@server_uuid`).Scan(&actual) != nil || actual != pin || admin.QueryRowContext(ctx, `SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'`).Scan(&version) != nil || version != "TLSv1.3" {
		t.Fatal("disposable server/TLS verification failed")
	}
	schema := "ad_a_current_prefix_" + run
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal("exact private schema creation")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var server string
		if admin.QueryRowContext(cleanup, `SELECT @@server_uuid`).Scan(&server) != nil || server != pin || !regexp.MustCompile(`^ad_a_current_prefix_[a-f0-9]{24}$`).MatchString(schema) {
			t.Error("refusing changed fixture cleanup identity")
			return
		}
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE `"+schema+"`"); err != nil {
			t.Error("exact owned prefix schema cleanup failed", err)
		}
	})
	cfg.DBName = schema
	db, err := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd, cred.Password = "", ""
	if err != nil {
		t.Fatal("private prefix schema connection")
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	return controlPrefixNativeFixture{db: db, admin: admin, schema: schema}
}

func seedControlPrefixNative(t *testing.T, ctx context.Context, f controlPrefixNativeFixture) (SQLExecutionAuthority, d.Authority) {
	t.Helper()
	_, a := prefixDataFixture()
	a.MaintenanceOwner = a.TaskPublicID
	ddl := []string{
		`CREATE TABLE system_backup_v2_engine_bindings(scope VARCHAR(80) PRIMARY KEY,engine VARCHAR(16)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_gate(scope VARCHAR(80) PRIMARY KEY,phase VARCHAR(20),owner VARCHAR(128),fencing_token BIGINT UNSIGNED,generation BIGINT UNSIGNED) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(128) PRIMARY KEY,application_scope VARCHAR(80),gate_generation BIGINT UNSIGNED,acquire_token BIGINT UNSIGNED,held_token BIGINT NULL,collectors_stopped_at DATETIME(6) NULL,source_resumed_at DATETIME(6) NULL,acquire_until DATETIME(6),hold_until DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_maintenance_locks(origin_installation_id VARCHAR(128),scope VARCHAR(80),lock_name VARCHAR(80),gate_state VARCHAR(20),lock_owner VARCHAR(128),fencing_token BIGINT UNSIGNED,row_version BIGINT UNSIGNED,lease_expires_at DATETIME(6) NULL,absolute_hold_deadline_at DATETIME(6) NULL,PRIMARY KEY(origin_installation_id,scope,lock_name)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(80),row_version BIGINT UNSIGNED,active_config_version BIGINT UNSIGNED) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128),version BIGINT UNSIGNED,schema_version VARCHAR(80),enabled BOOLEAN,canonical_config_json BLOB,config_sha256 CHAR(64),config_size_bytes BIGINT UNSIGNED,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_backups(public_id VARCHAR(128) PRIMARY KEY,origin_installation_id VARCHAR(128),schema_version VARCHAR(80),task_type VARCHAR(20),request_id VARCHAR(80),status VARCHAR(20),controller_owner VARCHAR(80),row_version BIGINT UNSIGNED,controller_lease_expires_at DATETIME(6),deadline_at DATETIME(6),config_version BIGINT UNSIGNED,config_snapshot_json BLOB,config_snapshot_size_bytes BIGINT UNSIGNED,config_snapshot_sha256 CHAR(64),maintenance_lock_owner VARCHAR(128),maintenance_fencing_token BIGINT UNSIGNED) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type VARCHAR(20),target_public_id VARCHAR(128),attempt_no BIGINT UNSIGNED,phase VARCHAR(20),status VARCHAR(20),row_version BIGINT UNSIGNED,PRIMARY KEY(target_type,target_public_id,phase,attempt_no)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_operations(id BIGINT AUTO_INCREMENT PRIMARY KEY,origin_installation_id VARCHAR(128),target_type VARCHAR(20),target_public_id VARCHAR(128),operation_type VARCHAR(20),status VARCHAR(20),KEY original_cancel(origin_installation_id,target_type,target_public_id,operation_type,status)) ENGINE=InnoDB`,
	}
	for _, statement := range ddl {
		if _, err := f.db.ExecContext(ctx, statement); err != nil {
			t.Fatal("owned prefix table setup", err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	a.DeadlineAt = now.Add(3 * time.Minute)
	config := []byte(`{"source":"original held DATA"}`)
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO system_backup_v2_engine_bindings VALUES('installation','v2')`, nil},
		{`INSERT INTO system_backup_gate VALUES('original-scope','held',?,21,7)`, []any{a.TaskPublicID}},
		{`INSERT INTO system_backup_v2_runtime_captures VALUES(?,'original-scope',7,20,21,NULL,NULL,?,?)`, []any{a.TaskPublicID, now.Add(time.Minute), now.Add(2 * time.Minute)}},
		{`INSERT INTO system_backup_v2_maintenance_locks VALUES(?,?,'system_backup_capture_gate','held',?,7,3,?,?)`, []any{a.InstallationID, CaptureGateScope, a.MaintenanceOwner, now.Add(2 * time.Minute), now.Add(2 * time.Minute)}},
		{`INSERT INTO system_backup_v2_installation_state VALUES(?,'system-backup-installation-state.v1',4,1)`, []any{a.InstallationID}},
		{`INSERT INTO system_backup_v2_configs VALUES(?,1,'system-backup-config.v1',TRUE,?,?,?)`, []any{a.InstallationID, config, a.ConfigSHA256, len(config)}},
		{`INSERT INTO system_backup_v2_backups VALUES(?,?,'system-backup-task.v1','backup',?,'capturing',?,2,?,?,1,?,?,?, ?,7)`, []any{a.TaskPublicID, a.InstallationID, a.RequestID, a.ClaimOwner, now.Add(2 * time.Minute), a.DeadlineAt, config, len(config), a.ConfigSHA256, a.MaintenanceOwner}},
		{`INSERT INTO system_backup_v2_attempts VALUES('backup',?,7,'capture','running',1)`, []any{a.TaskPublicID}},
	}
	for _, query := range queries {
		if _, err := f.db.ExecContext(ctx, query.sql, query.args...); err != nil {
			t.Fatal("owned prefix rows setup", err)
		}
	}
	return SQLExecutionAuthority{DB: f.db, InstallationID: a.InstallationID, ApplicationScope: "original-scope"}, a
}

// DATA/SQL-only differential: no execution owner, permit, task, provider or
// collector is authorized by this fixture. Both paths retain the independent
// clock after complete current rows, including same-transaction own writes.
func TestOriginalHeldControlPrefixCurrentMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fixture := newControlPrefixNativeFixture(t, ctx)
	store, a := seedControlPrefixNative(t, ctx, fixture)
	var explain string
	if err := fixture.db.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+originalHeldControlPrefixQuery, store.ApplicationScope, a.TaskPublicID, store.InstallationID, CaptureGateScope, a.TaskPublicID).Scan(&explain); err != nil || len(explain) > 131072 || !json.Valid([]byte(explain)) {
		t.Fatal("actual dependent prefix execution plan unavailable", err)
	}
	t.Log("held-prefix actual MySQL execution plan DATA", explain)
	// A fresh connection/transaction exercises the candidate FIRST, so the
	// original separate statements cannot pre-acquire locks for this success.
	tx, err := fixture.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.snapshotOriginalHeldControl(ctx, tx, a, nil)
	tx.Rollback()
	if err != nil || !first.heldCapture {
		t.Fatal("fresh candidate prefix SQL failed", err)
	}
	for _, tc := range []struct {
		name, mutation string
		args           []any
		allowed        bool
	}{
		{name: "healthy", allowed: true},
		{name: "engine", mutation: `UPDATE system_backup_v2_engine_bindings SET engine='legacy'`},
		{name: "application-owner", mutation: `UPDATE system_backup_gate SET owner='foreign'`},
		{name: "application-generation", mutation: `UPDATE system_backup_gate SET generation=generation+1`},
		{name: "application-held-token", mutation: `UPDATE system_backup_gate SET fencing_token=fencing_token+1`},
		{name: "capture-epoch", mutation: `UPDATE system_backup_v2_runtime_captures SET gate_generation=gate_generation+1`},
		{name: "capture-scope", mutation: `UPDATE system_backup_v2_runtime_captures SET application_scope='foreign'`},
		{name: "capture-held-token", mutation: `UPDATE system_backup_v2_runtime_captures SET held_token=NULL`},
		{name: "maintenance-fence", mutation: `UPDATE system_backup_v2_maintenance_locks SET fencing_token=fencing_token+1`},
		{name: "maintenance-owner", mutation: `UPDATE system_backup_v2_maintenance_locks SET lock_owner='foreign'`},
		{name: "maintenance-version", mutation: `UPDATE system_backup_v2_maintenance_locks SET row_version=0`},
		{name: "maintenance-expiry", mutation: `UPDATE system_backup_v2_maintenance_locks SET lease_expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 MICROSECOND`},
		{name: "hold-expiry", mutation: `UPDATE system_backup_v2_maintenance_locks SET absolute_hold_deadline_at=UTC_TIMESTAMP(6)-INTERVAL 1 MICROSECOND`},
		{name: "state-schema", mutation: `UPDATE system_backup_v2_installation_state SET schema_version='foreign'`},
		{name: "state-version", mutation: `UPDATE system_backup_v2_installation_state SET row_version=0`},
		{name: "active-config", mutation: `UPDATE system_backup_v2_installation_state SET active_config_version=2`},
		{name: "disabled", mutation: `UPDATE system_backup_v2_configs SET enabled=FALSE`},
		{name: "config-schema", mutation: `UPDATE system_backup_v2_configs SET schema_version='foreign'`},
		{name: "canonical-config", mutation: `UPDATE system_backup_v2_configs SET canonical_config_json='{}'`},
		{name: "task-schema", mutation: `UPDATE system_backup_v2_backups SET schema_version='foreign'`},
		{name: "task-installation", mutation: `UPDATE system_backup_v2_backups SET origin_installation_id='foreign'`},
		{name: "task-type", mutation: `UPDATE system_backup_v2_backups SET task_type='preflight'`},
		{name: "request", mutation: `UPDATE system_backup_v2_backups SET request_id='foreign'`},
		{name: "claim-owner", mutation: `UPDATE system_backup_v2_backups SET controller_owner='foreign'`},
		{name: "claim-version", mutation: `UPDATE system_backup_v2_backups SET row_version=row_version+1`},
		{name: "claim-expiry", mutation: `UPDATE system_backup_v2_backups SET controller_lease_expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 MICROSECOND`},
		{name: "deadline", mutation: `UPDATE system_backup_v2_backups SET deadline_at=deadline_at+INTERVAL 1 MICROSECOND`},
		{name: "config-version", mutation: `UPDATE system_backup_v2_backups SET config_version=2`},
		{name: "config-hash", mutation: `UPDATE system_backup_v2_backups SET config_snapshot_sha256=REPEAT('a',64)`},
		{name: "config-size", mutation: `UPDATE system_backup_v2_backups SET config_snapshot_size_bytes=config_snapshot_size_bytes+1`},
		{name: "config-bytes", mutation: `UPDATE system_backup_v2_backups SET config_snapshot_json='{}'`},
		{name: "task-maintenance-owner", mutation: `UPDATE system_backup_v2_backups SET maintenance_lock_owner='foreign'`},
		{name: "task-maintenance-fence", mutation: `UPDATE system_backup_v2_backups SET maintenance_fencing_token=maintenance_fencing_token+1`},
		{name: "attempt-status", mutation: `UPDATE system_backup_v2_attempts SET status='failed'`},
		{name: "attempt-version", mutation: `UPDATE system_backup_v2_attempts SET row_version=0`},
		{name: "latest-attempt", mutation: `INSERT INTO system_backup_v2_attempts VALUES('backup',?,8,'capture','running',1)`, args: []any{a.TaskPublicID}},
		{name: "cancel-pending", mutation: `INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES(?,'backup',?,'cancel','pending')`, args: []any{a.InstallationID, a.TaskPublicID}},
		{name: "cancel-running", mutation: `INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES(?,'backup',?,'cancel','running')`, args: []any{a.InstallationID, a.TaskPublicID}},
		{name: "original-null-stop-times", mutation: `UPDATE system_backup_v2_runtime_captures SET collectors_stopped_at=UTC_TIMESTAMP(6),source_resumed_at=UTC_TIMESTAMP(6)`, allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := fixture.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := store.snapshotObserved(ctx, tx, a, nil); err != nil {
				t.Fatal("original initial held locks unavailable", err)
			}
			if tc.mutation != "" {
				result, err := tx.ExecContext(ctx, tc.mutation, tc.args...)
				if err != nil {
					t.Fatal("actual same-transaction fault injection failed", err)
				}
				if n, err := result.RowsAffected(); err != nil || n != 1 {
					t.Fatal("fault injection did not change exactly one owned row", n, err)
				}
			}
			legacy, oldErr := store.snapshotObserved(ctx, tx, a, nil)
			current, newErr := store.snapshotOriginalHeldControl(ctx, tx, a, nil)
			if (oldErr == nil) != tc.allowed || (newErr == nil) != tc.allowed {
				t.Fatalf("original/candidate allowed=%t/%t want=%t old=%v new=%v", oldErr == nil, newErr == nil, tc.allowed, oldErr, newErr)
			}
			if tc.allowed {
				legacy.now, current.now = time.Time{}, time.Time{}
				if !reflect.DeepEqual(legacy, current) {
					t.Fatal("complete original snapshot facts changed")
				}
			}
		})
	}
	for round := 0; round < 2; round++ {
		paths := []struct {
			name string
			read func(context.Context, *sql.Tx, d.Authority, func(ExecutionBindDiagnostic)) (executionSnapshot, error)
		}{{"original-prefix", store.snapshotObserved}, {"dependent-current-prefix", store.snapshotOriginalHeldControl}}
		if round == 1 {
			paths[0], paths[1] = paths[1], paths[0]
		}
		for _, path := range paths {
			started := time.Now()
			for i := 0; i < 32; i++ {
				tx, err := fixture.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				_, err = path.read(ctx, tx, a, nil)
				tx.Rollback()
				if err != nil {
					t.Fatal("current prefix timing DATA failed", path.name, err)
				}
			}
			t.Log("held-prefix SQL DATA", path.name, "round", round, "calls", 32, "elapsed", time.Since(started))
		}
	}
}

func TestOriginalHeldControlPrefixLocksBeforeBlockedSuffixMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fixture := newControlPrefixNativeFixture(t, ctx)
	store, a := seedControlPrefixNative(t, ctx, fixture)
	tables := []string{"system_backup_v2_engine_bindings", "system_backup_gate", "system_backup_v2_runtime_captures", "system_backup_v2_maintenance_locks", "system_backup_v2_installation_state", "system_backup_v2_configs", "system_backup_v2_backups"}
	modes := []string{"S", "S", "S", "X", "X", "S", "X"}
	// Include a blocked first engine row: even optimizer-time reads must not
	// acquire any later prefix record before the original first lock succeeds.
	for target := 0; target < len(tables); target++ {
		t.Run(tables[target], func(t *testing.T) {
			blocker, err := fixture.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			var one int
			if blocker.QueryRowContext(ctx, "SELECT 1 FROM `"+tables[target]+"` LIMIT 1 FOR UPDATE").Scan(&one) != nil || one != 1 {
				t.Fatal("owned blocking suffix row unavailable")
			}
			readCtx, stop := context.WithTimeout(ctx, 6*time.Second)
			defer stop()
			tx, err := fixture.db.BeginTx(readCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			var connection uint64
			if tx.QueryRowContext(readCtx, `SELECT CONNECTION_ID()`).Scan(&connection) != nil {
				tx.Rollback()
				t.Fatal("owned prefix connection identity")
			}
			done := make(chan error, 1)
			finished := false
			go func() { _, err := store.readOriginalHeldControlPrefix(readCtx, tx, a); done <- err }()
			defer func() {
				blocker.Rollback()
				stop()
				if !finished {
					select {
					case <-done:
					case <-time.After(8 * time.Second):
						t.Error("owned prefix reader did not terminate after cancellation")
					}
				}
				tx.Rollback()
			}()
			waitUntil := time.Now().Add(3 * time.Second)
			waiting := false
			for time.Now().Before(waitUntil) {
				select {
				case err := <-done:
					finished = true
					t.Fatal("candidate returned before blocked suffix released", err)
				default:
				}
				var table string
				err := fixture.admin.QueryRowContext(ctx, `SELECT r.OBJECT_NAME FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
JOIN performance_schema.threads rt ON rt.THREAD_ID=w.REQUESTING_THREAD_ID
WHERE r.OBJECT_SCHEMA=? AND rt.PROCESSLIST_ID=? LIMIT 1`, fixture.schema, connection).Scan(&table)
				if err == nil {
					if table != tables[target] {
						t.Fatal("dependent prefix waited on a different lock", table, tables[target])
					}
					waiting = true
					break
				}
				if err != sql.ErrNoRows {
					t.Fatal("independent owned prefix wait observation failed", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waiting {
				t.Fatal("no actual blocking prefix lock observed")
			}
			for index, table := range tables {
				if index == target {
					continue
				}
				var held uint64
				if fixture.admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_locks l JOIN performance_schema.threads th ON th.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=? AND th.PROCESSLIST_ID=? AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED'`, fixture.schema, table, connection).Scan(&held) != nil {
					t.Fatal("independent actual record lock inventory unavailable")
				}
				if index < target && held == 0 {
					t.Fatal("earlier original prefix record not held before suffix wait", table)
				}
				if index < target {
					var wrongMode uint64
					if fixture.admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_locks l JOIN performance_schema.threads th ON th.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=? AND th.PROCESSLIST_ID=? AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED' AND SUBSTRING_INDEX(l.LOCK_MODE,',',1)<>?`, fixture.schema, table, connection, modes[index]).Scan(&wrongMode) != nil || wrongMode != 0 {
						t.Fatal("earlier original prefix record has changed lock mode", table, modes[index], wrongMode)
					}
				}
				if index > target && held != 0 {
					t.Fatal("later prefix record was locked out of original order", table)
				}
			}
			if err := blocker.Rollback(); err != nil {
				t.Fatal("owned suffix release failed", err)
			}
			select {
			case err := <-done:
				finished = true
				if err != nil {
					t.Fatal("current prefix failed after original lock release", err)
				}
			case <-readCtx.Done():
				t.Fatal("current prefix did not finish after suffix release")
			}
		})
	}
}
