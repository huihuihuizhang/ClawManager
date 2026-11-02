//go:build systembackup_mysql

package install

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
	"strconv"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// Actual disposable SAN/TLS MySQL + local TLS Kubernetes protocol only.
// No real cluster enrollment, app admission or provider authorization is done.
func TestOwnerEnrollOriginalLocalAdminTLSMySQL(t *testing.T) {
	path, uuid := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" || uuid == "" {
		t.Skip("root-owned disposable TLS MySQL and independent UUID required")
	}
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 16384 {
		t.Fatal("disposable credentials unavailable")
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
	if e != nil || tail != io.EOF || cred.Host != "127.0.0.1" || cred.Port < 1024 || cred.Port > 65535 || cred.Port == 3306 || cred.ServerUUID != uuid || cred.User == "" || cred.Password == "" || cred.TLSServerName == "" {
		t.Fatal("disposable SQL identity scope")
	}
	ca, e := os.ReadFile(cred.CAFile)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable SQL CA unavailable")
	}
	cfg := mysql.NewConfig()
	cfg.User = cred.User
	cfg.Passwd = cred.Password
	cred.Password = ""
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: cred.TLSServerName}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		t.Fatal("disposable TLS connector")
	}
	root := sql.OpenDB(connector)
	t.Cleanup(func() { root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var actual string
	if root.QueryRowContext(ctx, `SELECT @@server_uuid`).Scan(&actual) != nil || actual != uuid {
		t.Fatal("independent SQL UUID mismatch")
	}
	var random [12]byte
	if _, e = rand.Read(random[:]); e != nil {
		t.Fatal(e)
	}
	marker := hex.EncodeToString(random[:])
	database := "a_owner_enroll_" + marker
	if _, e = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); e != nil {
		t.Fatal("owned disposable schema creation")
	}
	var db *sql.DB
	markerReady := false
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if db != nil {
			defer db.Close()
		}
		var gotUUID, gotMarker string
		if root.QueryRowContext(cleanup, `SELECT @@server_uuid`).Scan(&gotUUID) != nil || gotUUID != uuid {
			t.Error("owned schema cleanup UUID mismatch; schema retained")
			return
		}
		// Before marker creation, ownership is the successful CREATE of this
		// exact fresh random name on the independently pinned server.
		if markerReady && (db.QueryRowContext(cleanup, `SELECT marker FROM owner_enroll_marker`).Scan(&gotMarker) != nil || gotMarker != marker) {
			t.Error("owned schema cleanup marker mismatch; schema retained")
			return
		}
		if _, e := root.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("owned schema cleanup failed")
		}
	})
	cfg.DBName = database
	connector, e = mysql.NewConnector(cfg)
	cfg.Passwd = ""
	if e != nil {
		t.Fatal("owned SQL connector")
	}
	db = sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	if _, e = db.ExecContext(ctx, `CREATE TABLE owner_enroll_marker(marker VARCHAR(64) PRIMARY KEY)`); e != nil {
		t.Fatal("owned marker DDL")
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO owner_enroll_marker VALUES(?)`, marker); e != nil {
		t.Fatal("owned marker insert")
	}
	markerReady = true
	if _, e = db.ExecContext(ctx, `CREATE TABLE users(id BIGINT PRIMARY KEY,username VARCHAR(128) NOT NULL UNIQUE,password_hash VARCHAR(255) NOT NULL,role VARCHAR(32) NOT NULL,is_active BOOLEAN NOT NULL,auth_provider VARCHAR(32) NOT NULL) ENGINE=InnoDB`); e != nil {
		t.Fatal("owned users fixture DDL")
	}
	fixture, model, created, password := enrollmentFixture(t, "")
	defer clear(password)
	stored, e := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO users VALUES(7,?,?,'admin',TRUE,'local')`, fixture.plan.LocalAdminUsername, string(stored)); e != nil {
		t.Fatal("owned admin fixture")
	}
	p := fixture.plan
	p.Target.Database = database
	p.Target.ServerUUID = uuid
	p.DatabaseCASHA256 = hash(ca)
	p.DatabaseTLSServerName = cred.TLSServerName
	if db.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&p.InstallerDatabaseAccount) != nil {
		t.Fatal("actual installer account")
	}
	planRaw, e := canonical(p)
	if e != nil {
		t.Fatal(e)
	}
	i, e := New(db, fixture.kube, planRaw, hash(planRaw), fixture.public, hash(fixture.public))
	if e != nil {
		t.Fatal(e)
	}
	r, e := i.Enroll(ctx, password)
	if e != nil || r.Pin.ConfigMapUID == "" || *created != 1 || model.queries != 0 {
		t.Fatal("actual SQL authenticated enrollment failed", e)
	}
	if _, e = db.ExecContext(ctx, `UPDATE users SET is_active=FALSE WHERE id=7`); e != nil {
		t.Fatal("owned admin revoke")
	}
	if receipt, e := i.Enroll(ctx, password); e == nil || receipt.Pin.ConfigMapUID != "" || *created != 1 {
		t.Fatal("revoked original SQL admin replayed enrollment")
	}
}
