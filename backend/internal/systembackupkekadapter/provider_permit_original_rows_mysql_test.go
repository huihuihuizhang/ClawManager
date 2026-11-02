package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// This opt-in test proves CURRENT row/lock equivalence only. The actual
// StageOriginal native test still proves complete execution/provider authority.
func TestHeldProviderOriginalRowsCurrentMySQL(t *testing.T) {
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if pin == "" {
		t.Skip("requires independently pinned disposable SAN/TLS MySQL")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable credentials unavailable")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err = dec.Decode(&credential)
	tail := dec.Decode(new(any))
	clear(raw)
	if err != nil || tail != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) || credential.ServerUUID != pin || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("disposable identity/pin unavailable")
	}
	ca, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable CA unavailable")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal("private fixture nonce unavailable")
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "a-permit-original-rows-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("SAN/TLS registration unavailable")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credential.User, credential.Password
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc = tlsName, true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("disposable connection unavailable")
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var server, cipher string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != pin || admin.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("disposable UUID/TLS mismatch before schema creation")
	}
	schema := "ad_a_original_rows_" + run
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal("private schema creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE `"+schema+"`"); err != nil {
			t.Error("exact owned original-row schema cleanup failed", err)
		}
	})
	cfg.DBName = schema
	db, err := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd, credential.Password = "", ""
	if err != nil {
		t.Fatal("private schema connection unavailable")
	}
	t.Cleanup(func() { db.Close() })
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(64),task_public_id VARCHAR(64),attempt_no BIGINT UNSIGNED,phase VARCHAR(16),record_kind VARCHAR(16),payload_sha256 VARCHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_resources(task_public_id VARCHAR(64),attempt_no BIGINT UNSIGNED,phase VARCHAR(16),resource_kind VARCHAR(16),namespace_name VARCHAR(64),resource_name VARCHAR(64),observed_uid VARCHAR(64),revoked BOOLEAN,stopped_at DATETIME(6),lifecycle VARCHAR(16),key_use_json BLOB,request_sha256 VARCHAR(64),PRIMARY KEY(task_public_id,attempt_no,resource_kind,namespace_name,resource_name)) ENGINE=InnoDB`,
		`INSERT INTO system_backup_v2_execution_records VALUES('installation','task',7,'capture','plan','plan')`,
		`INSERT INTO system_backup_v2_runtime_resources VALUES('task',7,'capture','Job','ns','job','uid',FALSE,NULL,'ready','original lease','spec')`,
	} {
		if _, err = db.ExecContext(ctx, ddl); err != nil {
			t.Fatal("private original-row fixture failed", err)
		}
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, proof := originalRowsIssue(tx, ctx)
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&p.grant.DatabaseAccount, &p.grant.Database.ServerUUID, &p.grant.Database.Database) != nil {
		t.Fatal("current private SQL identity unavailable")
	}
	// Exact initial original lock order. Test-only fixtures cannot manufacture
	// a real execution guard; they exercise the private SQL data reader only.
	var value []byte
	if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id='installation' AND task_public_id='task' AND attempt_no=7 AND phase='capture' AND record_kind='plan' FOR SHARE`).Scan(&value) != nil || tx.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE task_public_id='task' AND attempt_no=7 AND resource_kind='Job' AND namespace_name='ns' AND resource_name='job' FOR UPDATE`).Scan(&value) != nil {
		t.Fatal("initial exact locks unavailable")
	}
	legacy := func() ([]byte, error) {
		var account, server, database, planHash, specHash string
		var keyUse []byte
		if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database) != nil || account != p.grant.DatabaseAccount || server != p.grant.Database.ServerUUID || database != p.grant.Database.Database {
			return nil, errors.New("identity")
		}
		if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan' FOR SHARE`, "installation", "task", 7).Scan(&planHash) != nil || planHash != p.planHash {
			return nil, errors.New("plan")
		}
		if tx.QueryRowContext(ctx, `SELECT key_use_json,request_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND stopped_at IS NULL AND lifecycle='ready' FOR SHARE`, "task", 7, "ns", "job", "uid").Scan(&keyUse, &specHash) != nil || specHash != p.specHash {
			return nil, errors.New("job")
		}
		return keyUse, nil
	}
	for _, tc := range []struct {
		name, mutation string
		allowed        bool
	}{
		{"unchanged", "", true},
		{"plan_changed", `UPDATE system_backup_v2_execution_records SET payload_sha256='changed'`, false},
		{"plan_missing", `DELETE FROM system_backup_v2_execution_records`, false},
		{"job_missing", `DELETE FROM system_backup_v2_runtime_resources`, false},
		{"job_revoked", `UPDATE system_backup_v2_runtime_resources SET revoked=TRUE`, false},
		{"job_stopped", `UPDATE system_backup_v2_runtime_resources SET stopped_at=UTC_TIMESTAMP(6)`, false},
		{"job_phase", `UPDATE system_backup_v2_runtime_resources SET phase='publish'`, false},
		{"job_lifecycle", `UPDATE system_backup_v2_runtime_resources SET lifecycle='deleting'`, false},
		{"job_uid", `UPDATE system_backup_v2_runtime_resources SET observed_uid='replacement'`, false},
		{"job_attempt", `UPDATE system_backup_v2_runtime_resources SET attempt_no=8`, false},
		{"job_namespace", `UPDATE system_backup_v2_runtime_resources SET namespace_name='foreign'`, false},
		{"job_request", `UPDATE system_backup_v2_runtime_resources SET request_sha256='changed'`, false},
		{"job_lease", `UPDATE system_backup_v2_runtime_resources SET key_use_json='changed lease'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tx.ExecContext(ctx, "SAVEPOINT original_rows_case"); err != nil {
				t.Fatal(err)
			}
			if tc.mutation != "" {
				if _, err := tx.ExecContext(ctx, tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			old, oldErr := legacy()
			got, gotErr := proof.read(ctx, tx, p, proof.guard)
			oldAllowed := oldErr == nil && bytes.Equal(old, []byte("original lease"))
			gotAllowed := gotErr == nil && bytes.Equal(got, []byte("original lease"))
			if oldAllowed != tc.allowed || gotAllowed != oldAllowed || (oldErr == nil && gotErr == nil && !bytes.Equal(old, got)) {
				t.Fatal("current sequential/batch differential changed", oldAllowed, gotAllowed, tc.allowed)
			}
			if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT original_rows_case"); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A different session cannot change the locked plan; no historical read
	// view is silently substituted for the current FOR SHARE scalar read.
	other, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=1"); err != nil {
		t.Fatal(err)
	}
	_, err = other.ExecContext(ctx, `UPDATE system_backup_v2_execution_records SET payload_sha256='other session'`)
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1205 {
		t.Fatal("original plan lock did not block a foreign writer", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = proof.read(ctx, tx, p, proof.guard); err == nil {
		t.Fatal("finished transaction reused")
	}
}
