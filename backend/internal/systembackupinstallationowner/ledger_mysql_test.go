package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Real SQL source/lock tests only. This does not enroll an owner, perform a
// provider probe, admit a config or claim least-privilege production execution.
func TestInstallationOwnerOriginalLedgerCurrentAndLocksMySQL(t *testing.T) {
	credentials := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if credentials == "" {
		t.Skip("requires root-owned disposable SAN TLS MySQL and independent UUID pin")
	}
	var cred struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, e := os.ReadFile(credentials)
	if e != nil || len(raw) > 16384 {
		t.Fatal("private disposable credentials")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	e = decoder.Decode(&cred)
	tail := decoder.Decode(new(any))
	clear(raw)
	if e != nil || tail != io.EOF || !serverPattern.MatchString(pin) || pin != cred.ServerUUID || cred.Host != "127.0.0.1" || cred.Port < 1024 || cred.Port > 65535 || cred.Port == 3306 || cred.User == "" || cred.Password == "" || cred.TLSServerName == "" || !filepath.IsAbs(cred.CAFile) {
		t.Fatal("disposable scope")
	}
	ca, e := os.ReadFile(cred.CAFile)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("private CA")
	}
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	suffix := hex.EncodeToString(nonce)
	tlsName := "owner-ledger-" + suffix
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: cred.TLSServerName}) != nil {
		t.Fatal("TLS registration")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = cred.User, cred.Password
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc, cfg.InterpolateParams = tlsName, true, time.UTC, true
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var uuid, protocol string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != pin || admin.QueryRowContext(ctx, `SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'`).Scan(&protocol) != nil || protocol != "TLSv1.3" {
		t.Fatal("server/TLS mismatch")
	}
	schema := "ad_a_owner_" + suffix
	if _, e := admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var actual string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&actual) != nil || actual != pin || !regexp.MustCompile(`^ad_a_owner_[a-f0-9]{24}$`).MatchString(schema) {
			t.Error("refusing changed cleanup identity")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE `"+schema+"`"); e != nil {
			t.Error("owned schema cleanup", e)
		}
	})
	cfg.DBName = schema
	db, e := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd, cred.Password = "", ""
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(6)
	ddl, e := os.ReadFile("../db/migrations/134_backup_v2_installation_owner_authority.sql")
	if e != nil {
		t.Fatal(e)
	}
	var lines []string
	for _, line := range strings.Split(string(ddl), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	for _, statement := range strings.Split(strings.Join(lines, "\n"), ";") {
		if strings.TrimSpace(statement) != "" {
			if _, e := db.ExecContext(ctx, statement); e != nil {
				t.Fatal("actual 134 DDL", e)
			}
		}
	}
	if _, e := db.ExecContext(ctx, `CREATE TABLE users(id BIGINT PRIMARY KEY,username VARCHAR(80),role VARCHAR(20),is_active BOOLEAN,auth_provider VARCHAR(20)) ENGINE=InnoDB`); e != nil {
		t.Fatal(e)
	}
	f := ownerRecordFixture(t)
	f.pin.ServerUUID = pin
	f.pin.Database = schema
	f.record.Target.ServerUUID = pin
	f.record.Target.Database = schema
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&f.pin.DatabaseAccount) != nil {
		t.Fatal("actual identity")
	}
	f.record.Target.DatabaseAccount = f.pin.DatabaseAccount
	f.resign(t)
	head := Head{SchemaVersion: HeadVersion, InstallationID: f.pin.InstallationID, EnrollmentID: f.pin.EnrollmentID, IssuerID: f.pin.IssuerID, OwnerSubject: f.pin.OwnerSubject, EnrollmentRevision: 1, Revision: 1, GrantID: f.pin.GrantID, GrantRevision: 1, RecordSHA256: f.pin.RecordSHA256, State: "active", NotBefore: f.record.NotBefore, Until: f.record.Until}
	headRaw, _ := EncodeHead(head)
	headSig := ed25519.Sign(f.private, append([]byte(HeadDomain), headRaw...))
	if _, e := db.ExecContext(ctx, `INSERT INTO users VALUES(7,'local-admin','admin',TRUE,'local')`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_installation_owner_heads VALUES(?,?,?,?,?,?,'active',1,UTC_TIMESTAMP(6))`, f.pin.InstallationID, f.pin.EnrollmentID, 1, digest(headRaw), headRaw, headSig); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_installation_owner_grants VALUES(?,?,?,?,?,?,?,'active',1,UTC_TIMESTAMP(6))`, f.pin.InstallationID, f.pin.EnrollmentID, f.pin.GrantID, 1, f.pin.RecordSHA256, f.raw, f.sig); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	files := RecordFiles{filepath.Join(dir, "record"), filepath.Join(dir, "signature")}
	if os.WriteFile(files.RecordFile, f.raw, 0600) != nil || os.WriteFile(files.SignatureFile, f.sig, 0600) != nil {
		t.Fatal("original source files")
	}
	prepared := func(active context.Context) *PreparedCaptureSigning {
		auth, e := VerifyRecord(f.raw, f.sig, f.pin)
		if e != nil {
			t.Fatal(e)
		}
		p := &PreparedCaptureSigning{validator: &CaptureSigningValidator{pin: f.pin, files: files}, ctx: active, auth: auth}
		p.origin = p
		return p
	}
	t.Run("current_identity_and_own_revocation", func(t *testing.T) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		p := prepared(ctx)
		g, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config)
		if e != nil || g.RecheckOriginalIdentity(ctx, tx) != nil {
			t.Fatal("actual signed source identity", e)
		}
		if _, e := tx.ExecContext(ctx, `UPDATE system_backup_installation_owner_heads SET head_state='revoked',row_version=row_version+1`); e != nil {
			t.Fatal(e)
		}
		if g.RecheckOriginalIdentity(ctx, tx) == nil {
			t.Fatal("same-transaction revocation reused stale authority")
		}
	})
	t.Run("head_wait_preserves_admin_then_grant_order", func(t *testing.T) {
		blocker, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback()
		var version uint64
		if blocker.QueryRowContext(ctx, `SELECT row_version FROM system_backup_installation_owner_heads FOR UPDATE`).Scan(&version) != nil {
			t.Fatal("blocker")
		}
		active, stop := context.WithTimeout(ctx, 6*time.Second)
		defer stop()
		tx, e := db.BeginTx(active, nil)
		if e != nil {
			t.Fatal(e)
		}
		var connection uint64
		if tx.QueryRowContext(active, "SELECT CONNECTION_ID()").Scan(&connection) != nil {
			tx.Rollback()
			t.Fatal("reader connection")
		}
		p := prepared(active)
		done := make(chan error, 1)
		finished := false
		go func() { _, e := p.AuthorizeOriginal(active, tx, p.grant, p.config); done <- e }()
		defer func() {
			blocker.Rollback()
			stop()
			if !finished {
				select {
				case <-done:
				case <-time.After(8 * time.Second):
					t.Error("reader did not stop")
				}
			}
			tx.Rollback()
		}()
		waiting := false
		until := time.Now().Add(3 * time.Second)
		for time.Now().Before(until) {
			select {
			case e := <-done:
				finished = true
				t.Fatal("returned before head release", e)
			default:
			}
			var table string
			e := admin.QueryRowContext(ctx, `SELECT l.OBJECT_NAME FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID JOIN performance_schema.threads th ON th.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND th.PROCESSLIST_ID=? LIMIT 1`, schema, connection).Scan(&table)
			if e == nil {
				if table != "system_backup_installation_owner_heads" {
					t.Fatal("wrong wait", table)
				}
				waiting = true
				break
			}
			if e != sql.ErrNoRows {
				t.Fatal(e)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting {
			t.Fatal("no head wait")
		}
		for _, table := range []string{"users", "system_backup_installation_owner_grants"} {
			var held uint64
			if admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_locks l JOIN performance_schema.threads th ON th.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=? AND th.PROCESSLIST_ID=? AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED'`, schema, table, connection).Scan(&held) != nil {
				t.Fatal("lock inventory")
			}
			if table == "users" && held == 0 || table != "users" && held != 0 {
				t.Fatal("L2 order changed", table, held)
			}
		}
		if blocker.Rollback() != nil {
			t.Fatal("head release")
		}
		select {
		case e := <-done:
			finished = true
			if e != nil {
				t.Fatal(e)
			}
		case <-active.Done():
			t.Fatal("reader not completed")
		}
	})
	t.Run("revoker_waits_until_original_authority_transaction_finishes", func(t *testing.T) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		p := prepared(ctx)
		if _, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config); e != nil {
			t.Fatal(e)
		}
		other, e := db.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer other.Close()
		if _, e := other.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=1"); e != nil {
			t.Fatal(e)
		}
		_, e = other.ExecContext(ctx, `UPDATE system_backup_installation_owner_heads SET head_state='revoked',row_version=row_version+1`)
		var mysqlError *mysql.MySQLError
		if !errors.As(e, &mysqlError) || mysqlError.Number != 1205 {
			t.Fatal("revocation did not serialize", e)
		}
		tx.Rollback()
		if _, e := other.ExecContext(ctx, `UPDATE system_backup_installation_owner_heads SET head_state='revoked',row_version=row_version+1`); e != nil {
			t.Fatal(e)
		}
		next, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer next.Rollback()
		q := prepared(ctx)
		if _, e := q.AuthorizeOriginal(ctx, next, q.grant, q.config); e == nil {
			t.Fatal("committed revoke ignored")
		}
	})
}
