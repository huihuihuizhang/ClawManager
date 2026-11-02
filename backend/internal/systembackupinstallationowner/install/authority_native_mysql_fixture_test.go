//go:build systembackup_mysql

package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type nativeAuthorityFixture struct {
	f                         *authorityFixture
	root, installer, consumer *sql.DB
	installerConnector        driver.Connector
	database                  string
}

// All SQL below reaches the independently pinned disposable SAN/TLS server.
// The reused Vault TLS protocol and Kubernetes SDK fixture remain controlled
// local fixtures, never evidence of field enrollment/provider authorization.
func newNativeAuthorityFixture(t *testing.T, ctx context.Context) *nativeAuthorityFixture {
	t.Helper()
	path, uuid := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" || uuid == "" {
		t.Skip("unverified: root-owned disposable SAN/TLS MySQL credentials and independent UUID required")
	}
	raw, e := ReadPrivateFile(path, 16384)
	if e != nil {
		t.Fatal("private disposable credentials")
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
	if e != nil || tail != io.EOF || !serverUUIDPatternForNative(uuid) || cred.ServerUUID != uuid || cred.Host != "127.0.0.1" || cred.Port < 1024 || cred.Port > 65535 || cred.Port == 3306 || cred.User == "" || cred.Password == "" || cred.TLSServerName == "" || !filepath.IsAbs(cred.CAFile) {
		t.Fatal("disposable SQL identity scope")
	}
	ca, e := ReadPrivateFile(cred.CAFile, 65536)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("private disposable SQL CA")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = cred.User, cred.Password
	cred.Password = ""
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: cred.TLSServerName}
	rootConnector, e := mysql.NewConnector(cfg)
	if e != nil {
		t.Fatal("disposable TLS connector")
	}
	root := sql.OpenDB(rootConnector)
	t.Cleanup(func() { root.Close() })
	var actual string
	if root.QueryRowContext(ctx, `SELECT @@server_uuid`).Scan(&actual) != nil || actual != uuid {
		t.Fatal("independent SQL UUID mismatch")
	}
	requireNativeAuthorityTLS(t, ctx, root)
	marker := nativeAuthorityRandom(t, 12)
	database := "a_owner_authority_" + marker
	if _, e = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); e != nil {
		t.Fatal("owned random schema creation")
	}
	var opened []*sql.DB
	var createdUsers []string
	markerReady := false
	t.Cleanup(func() {
		for _, db := range opened {
			_ = db.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var gotUUID, gotMarker string
		if root.QueryRowContext(cleanup, `SELECT @@server_uuid`).Scan(&gotUUID) != nil || gotUUID != uuid {
			t.Error("cleanup UUID mismatch; owned schema/accounts retained")
			return
		}
		// Before the marker exists, ownership is the successful CREATE of this
		// exact random name; a failed CREATE never registers cleanup ownership.
		if markerReady && (root.QueryRowContext(cleanup, "SELECT marker FROM `"+database+"`.owner_authority_marker").Scan(&gotMarker) != nil || gotMarker != marker) {
			t.Error("cleanup marker mismatch; owned schema/accounts retained")
			return
		}
		for _, user := range createdUsers {
			if _, e := root.ExecContext(cleanup, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
				t.Error("owned limited account cleanup failed")
			}
		}
		if _, e := root.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("owned schema cleanup failed")
		}
	})
	open := func(user, password string) (*sql.DB, driver.Connector) {
		t.Helper()
		selected := cfg.Clone()
		selected.User, selected.Passwd, selected.DBName = user, password, database
		connector, e := mysql.NewConnector(selected)
		selected.Passwd = ""
		if e != nil {
			t.Fatal("owned connector")
		}
		db := sql.OpenDB(connector)
		db.SetMaxOpenConns(8)
		opened = append(opened, db)
		if db.PingContext(ctx) != nil {
			t.Fatal("owned account TLS connection")
		}
		return db, connector
	}
	ddlDB, _ := open(cfg.User, cfg.Passwd)
	cfg.Passwd = ""
	if _, e = ddlDB.ExecContext(ctx, `CREATE TABLE owner_authority_marker(marker VARCHAR(64) PRIMARY KEY) ENGINE=InnoDB`); e != nil {
		t.Fatal("owned marker DDL")
	}
	if _, e = ddlDB.ExecContext(ctx, `INSERT INTO owner_authority_marker VALUES(?)`, marker); e != nil {
		t.Fatal("owned marker insert")
	}
	markerReady = true
	applyNativeAuthority134(t, ctx, ddlDB)
	if _, e = ddlDB.ExecContext(ctx, `CREATE TABLE users(id BIGINT PRIMARY KEY,username VARCHAR(128) NOT NULL UNIQUE,password_hash VARCHAR(255) NOT NULL,role VARCHAR(32) NOT NULL,is_active BOOLEAN NOT NULL,auth_provider VARCHAR(32) NOT NULL) ENGINE=InnoDB`); e != nil {
		t.Fatal("owned users fixture DDL")
	}
	installerName, consumerName := "a_oi_"+marker, "a_oc_"+marker
	createUser := func(user string) string {
		password := nativeAuthorityRandom(t, 32)
		// Names/passwords contain only locally generated lowercase hex plus
		// fixed identifiers; no caller-controlled SQL text is interpolated.
		if _, e := root.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"' REQUIRE SSL"); e != nil {
			t.Fatal("owned limited user creation")
		}
		createdUsers = append(createdUsers, user)
		return password
	}
	installerPassword, consumerPassword := createUser(installerName), createUser(consumerName)
	grant := func(privileges, table, user string) {
		if _, e := root.ExecContext(ctx, "GRANT "+privileges+" ON `"+database+"`."+table+" TO '"+user+"'@'127.0.0.1'"); e != nil {
			t.Fatal("owned limited grants")
		}
	}
	grant("SELECT", "users", installerName)
	grant("SELECT (id,username,role,is_active,auth_provider)", "users", consumerName)
	for _, table := range []string{"system_backup_installation_owner_heads", "system_backup_installation_owner_grants"} {
		grant("SELECT,INSERT,UPDATE", table, installerName)
		grant("SELECT", table, consumerName)
	}
	installer, installerConnector := open(installerName, installerPassword)
	consumer, _ := open(consumerName, consumerPassword)
	installerPassword, consumerPassword = "", ""
	requireNativeAuthorityTLS(t, ctx, installer)
	requireNativeAuthorityTLS(t, ctx, consumer)
	f := newAuthorityFixture(t)
	p := f.i.plan
	p.Target.Database, p.Target.ServerUUID = database, uuid
	p.DatabaseCASHA256, p.DatabaseTLSServerName = hash(ca), cred.TLSServerName
	if installer.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&p.InstallerDatabaseAccount) != nil || consumer.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&p.Target.DatabaseAccount) != nil || p.InstallerDatabaseAccount == p.Target.DatabaseAccount {
		t.Fatal("actual distinct installer and consumer identities")
	}
	if _, e = ddlDB.ExecContext(ctx, `INSERT INTO users VALUES(7,?,?,'admin',TRUE,'local')`, p.LocalAdminUsername, f.s.auth.stored); e != nil {
		t.Fatal("actual local bcrypt admin fixture")
	}
	plan, e := canonical(p)
	if e != nil {
		t.Fatal(e)
	}
	i, e := New(installer, f.i.kube, plan, hash(plan), f.i.public, hash(f.i.public))
	if e != nil {
		t.Fatal("actual SQL plan binding", e)
	}
	// Only the controlled fake API object is replaced to install this test's
	// new independently selected SQL plan; no field API mutation is performed.
	if i.kube.CoreV1().ConfigMaps(p.Target.Namespace).Delete(ctx, p.EnrollmentName, metav1.DeleteOptions{}) != nil {
		t.Fatal("controlled old fixture enrollment removal")
	}
	r, e := i.Enroll(ctx, f.password)
	if e != nil {
		t.Fatal("actual SQL authenticated controlled enrollment", e)
	}
	f.i, f.enrollment = i, r.Pin
	f.record.Target = p.Target
	f.grant.ServerUUID, f.grant.Database = uuid, database
	grantJSON, e := json.Marshal(f.grant)
	if e != nil {
		t.Fatal(e)
	}
	f.record.GrantSHA256 = hash(grantJSON)
	grantFile, e := canonical(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: f.record.NotBefore.Add(-time.Minute), ExpiresAt: f.record.Until.Add(time.Minute), Grant: f.grant})
	if e != nil || os.WriteFile(f.files.GrantFile, grantFile, 0600) != nil {
		t.Fatal("actual target grant file")
	}
	f.files.GrantFileSHA256 = hash(grantFile)
	f.draft, e = owner.EncodeRecord(f.record)
	if e != nil {
		t.Fatal(e)
	}
	return &nativeAuthorityFixture{f: f, root: ddlDB, installer: installer, consumer: consumer, installerConnector: installerConnector, database: database}
}

func nativeAuthorityRandom(t *testing.T, count int) string {
	t.Helper()
	raw := make([]byte, count)
	if _, e := rand.Read(raw); e != nil {
		t.Fatal("native fixture nonce")
	}
	defer clear(raw)
	return hex.EncodeToString(raw)
}
func serverUUIDPatternForNative(s string) bool {
	if len(s) != 36 {
		return false
	}
	for n, b := range []byte(s) {
		if n == 8 || n == 13 || n == 18 || n == 23 {
			if b != '-' {
				return false
			}
			continue
		}
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func requireNativeAuthorityTLS(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var name, value string
	if db.QueryRowContext(ctx, `SHOW SESSION STATUS LIKE 'Ssl_version'`).Scan(&name, &value) != nil || name != "Ssl_version" || value != "TLSv1.3" {
		t.Fatal("actual SQL connection is not TLS 1.3")
	}
}
func applyNativeAuthority134(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	raw, e := os.ReadFile("../../db/migrations/134_backup_v2_installation_owner_authority.sql")
	if e != nil {
		t.Fatal("actual migration 134 source")
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	count := 0
	for _, statement := range strings.Split(strings.Join(lines, "\n"), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if !strings.HasPrefix(statement, "CREATE TABLE system_backup_installation_owner_") {
			t.Fatal("unexpected migration 134 operation")
		}
		if _, e = db.ExecContext(ctx, statement); e != nil {
			t.Fatal("actual migration 134 DDL", e)
		}
		count++
	}
	if count != 2 {
		t.Fatal("migration 134 must contain the two original authority tables")
	}
}
