//go:build systembackup_mysql

package systembackupsecurity

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
	"strconv"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Actual shared admin source and revocation serialization under a SELECT-only
// account. The reused disposable fixture creates unrelated minimal publication
// tables as well; no whole catalog/bootstrap/provider success is claimed here.
func TestBootstrapCurrentAdminReadOnlyAccountTLSMySQL(t *testing.T) {
	db, database := firstStageNativeDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	var marker string
	if db.QueryRowContext(ctx, `SELECT run_id FROM _a_publication_first_owner`).Scan(&marker) != nil {
		t.Fatal("owned fixture marker")
	}
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		t.Fatal(e)
	}
	user := "a_ba_" + hex.EncodeToString(nonce[:])
	var secret [32]byte
	if _, e := rand.Read(secret[:]); e != nil {
		t.Fatal(e)
	}
	password := "Aa1!" + hex.EncodeToString(secret[:])
	clear(secret[:])
	if _, e := db.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"' REQUIRE SSL"); e != nil {
		t.Fatal("owned select-only user creation")
	}
	var consumer *sql.DB
	t.Cleanup(func() {
		if consumer != nil {
			_ = consumer.Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var gotUUID, gotMarker string
		if db.QueryRowContext(cleanup, `SELECT @@server_uuid`).Scan(&gotUUID) != nil || gotUUID != pin || db.QueryRowContext(cleanup, `SELECT run_id FROM _a_publication_first_owner`).Scan(&gotMarker) != nil || gotMarker != marker {
			t.Error("select-only account cleanup source changed; account retained")
			return
		}
		if _, e := db.ExecContext(cleanup, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
			t.Error("owned select-only account cleanup failed")
		}
	})
	if _, e := db.ExecContext(ctx, `CREATE TABLE users(id BIGINT PRIMARY KEY,username VARCHAR(128),password_hash VARCHAR(255),role VARCHAR(32),is_active BOOLEAN,auth_provider VARCHAR(32)) ENGINE=InnoDB`); e != nil {
		t.Fatal("owned users source DDL")
	}
	if _, e := db.ExecContext(ctx, `INSERT INTO users VALUES(7,'original-admin','never-readable','admin',TRUE,'local')`); e != nil {
		t.Fatal("owned users source fixture")
	}
	if _, e := db.ExecContext(ctx, "GRANT SELECT(id,username,role,is_active,auth_provider) ON `"+database+"`.users TO '"+user+"'@'127.0.0.1'"); e != nil {
		t.Fatal("owned column-limited grant")
	}
	consumer = bootstrapAdminNativeConsumer(t, ctx, database, user, password, pin)
	password = ""
	var value string
	e := consumer.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=7`).Scan(&value)
	requireBootstrapAdminPrivilegeDenial(t, e)
	tx, e := consumer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	e = tx.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=7 FOR UPDATE`).Scan(new(string), new(string), new(bool), new(string))
	requireBootstrapAdminPrivilegeDenial(t, e)
	_ = tx.Rollback()
	grant := OfflineBootstrapGrant{UserID: 7, Username: "original-admin"}
	reader, e := consumer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Rollback()
	if e := lockBootstrapCurrentAdmin(ctx, reader, grant); e != nil {
		t.Fatal("actual SELECT-only source read failed", e)
	}
	candidate := &configBootstrapCandidateSession{plan: &ConfigBootstrapCandidates{grant: grant}}
	if candidate.checkAdmin(ctx, reader) != nil {
		t.Fatal("candidate still requires admin write privilege")
	}
	writerCtx, stopWriter := context.WithTimeout(ctx, 6*time.Second)
	defer stopWriter()
	writer, e := db.Conn(writerCtx)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	var writerID uint64
	if writer.QueryRowContext(writerCtx, `SELECT CONNECTION_ID()`).Scan(&writerID) != nil {
		t.Fatal("actual revoker connection identity")
	}
	done := make(chan error, 1)
	go func() {
		_, e := writer.ExecContext(writerCtx, `UPDATE users SET is_active=FALSE WHERE id=7`)
		done <- e
	}()
	finished := false
	defer func() {
		_ = reader.Rollback()
		stopWriter()
		if !finished {
			select {
			case <-done:
			case <-time.After(7 * time.Second):
				t.Error("actual source revoker did not stop")
			}
		}
	}()
	waiting := false
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		select {
		case e := <-done:
			finished = true
			t.Fatal("admin revocation escaped held shared lock", e)
		default:
		}
		var table string
		e := db.QueryRowContext(ctx, `SELECT l.OBJECT_NAME FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID JOIN performance_schema.threads th ON th.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND th.PROCESSLIST_ID=? LIMIT 1`, database, writerID).Scan(&table)
		if e == nil {
			if table != "users" {
				t.Fatal("revoker waiting on an unrelated range")
			}
			waiting = true
			break
		}
		if !errors.Is(e, sql.ErrNoRows) {
			t.Fatal("actual lock wait readback", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting || lockBootstrapCurrentAdmin(ctx, reader, grant) != nil {
		t.Fatal("no actual shared row protection/current recheck")
	}
	if reader.Commit() != nil {
		t.Fatal("original reader completion")
	}
	select {
	case e := <-done:
		finished = true
		if e != nil {
			t.Fatal("revoker after original reader", e)
		}
	case <-writerCtx.Done():
		t.Fatal("revocation did not follow reader completion")
	}
	var active bool
	if db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE id=7`).Scan(&active) != nil || active {
		t.Fatal("actual admin revocation was not persisted")
	}
	after, e := consumer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer after.Rollback()
	if lockBootstrapCurrentAdmin(ctx, after, grant) != ErrRegistrationPermission || candidate.checkAdmin(ctx, after) == nil {
		t.Fatal("revoked admin passed new original/candidate source read")
	}
}

func requireBootstrapAdminPrivilegeDenial(t *testing.T, e error) {
	t.Helper()
	var mysqlError *mysql.MySQLError
	if !errors.As(e, &mysqlError) || (mysqlError.Number != 1142 && mysqlError.Number != 1143) {
		t.Fatal("expected actual table/column privilege refusal", e)
	}
}
func bootstrapAdminNativeConsumer(t *testing.T, ctx context.Context, database, user, password, pin string) *sql.DB {
	t.Helper()
	raw, e := os.ReadFile(os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"))
	if e != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("controlled credentials unavailable")
	}
	var cred struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	e = d.Decode(&cred)
	tail := d.Decode(new(any))
	clear(raw)
	cred.Password = ""
	if e != nil || tail != io.EOF || cred.Host != "127.0.0.1" || cred.Port < 1024 || cred.Port > 65535 || cred.Port == 3306 || cred.ServerUUID != pin || cred.TLSServerName == "" {
		t.Fatal("controlled consumer endpoint/UUID scope")
	}
	ca, e := os.ReadFile(cred.CAFile)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("controlled consumer CA")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.DBName = user, password, database
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.TLS = &tls.Config{RootCAs: roots, ServerName: cred.TLSServerName, MinVersion: tls.VersionTLS13}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	connector, e := mysql.NewConnector(cfg)
	cfg.Passwd = ""
	if e != nil {
		t.Fatal("limited consumer connector")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(2)
	var actual, account, name, protocol string
	if db.QueryRowContext(ctx, `SELECT @@server_uuid,CURRENT_USER()`).Scan(&actual, &account) != nil || actual != pin || account != user+"@127.0.0.1" || db.QueryRowContext(ctx, `SHOW SESSION STATUS LIKE 'Ssl_version'`).Scan(&name, &protocol) != nil || name != "Ssl_version" || protocol != "TLSv1.3" {
		db.Close()
		t.Fatal("actual limited account/TLS identity")
	}
	return db
}
