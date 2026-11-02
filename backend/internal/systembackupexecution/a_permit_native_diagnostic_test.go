package systembackupexecution

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
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// This entry adds only disposable-instance preflight around the SAME
// existing original-task fixture. It does not change its claim/key windows,
// capture sources, control handler, provider, publication or recovery checks.
func TestAPermitTimingOriginalThirtySecondNativeMySQL(t *testing.T) {
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if pin == "" {
		t.Skip("requires an exclusively owned disposable SAN/TLS MySQL; never production")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	path := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable credentials unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&credential)
	tailErr := decoder.Decode(new(any))
	clear(raw)
	if err != nil || tailErr != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) || credential.ServerUUID != pin || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("disposable endpoint/independent UUID pin invalid; no fixture started")
	}
	ca, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable SAN/TLS CA unavailable")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal("disposable TLS registration unavailable")
	}
	tlsName := "a-permit-native-" + hex.EncodeToString(nonce[:])
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("disposable SAN/TLS registration unavailable")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	connection := mysql.NewConfig()
	connection.User, connection.Passwd = credential.User, credential.Password
	connection.Net, connection.Addr = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	connection.TLSConfig = tlsName
	connection.Timeout, connection.ReadTimeout, connection.WriteTimeout = 5*time.Second, 20*time.Second, 20*time.Second
	db, err := sql.Open("mysql", connection.FormatDSN())
	credential.Password = ""
	connection.Passwd = ""
	if err != nil {
		t.Fatal("disposable database connection unavailable")
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var observed, cipher string
	if db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&observed) != nil || observed != pin || db.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("disposable server/TLS mismatch; no fixture started")
	}
	// Require full schema visibility, rather than interpreting a restricted
	// account's SHOW DATABASES result as absence of production schemas.
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		t.Fatal("disposable global schema visibility unavailable")
	}
	visible := false
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil {
			rows.Close()
			t.Fatal("disposable grants unreadable")
		}
		if regexp.MustCompile(`^GRANT (ALL PRIVILEGES|.*\bSHOW DATABASES\b.*) ON \*\.\* TO `).MatchString(grant) {
			visible = true
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil || !visible {
		t.Fatal("disposable account must explicitly see all schemas; no fixture started")
	}
	if schemas := aPermitNativeSchemas(t, ctx, db); len(schemas) != 0 {
		t.Fatal("disposable instance is not empty; no fixture started")
	}
	// No census/difference/prefix-based DROP is allowed here: a concurrent
	// fixture's schema would not belong to this invocation. The original
	// fixture owns its exact success cleanup. On failure the disposable instance
	// owner destroys the whole exclusively owned instance/volume, not a schema
	// inferred from logs or a later census.
	t.Log("A permit disposable preflight passed; original fixture/key window unchanged")
	runDOriginalUploadedManifestThroughRemoteCAnd102(t, true, true, true)
}

func aPermitNativeSchemas(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema') ORDER BY SCHEMA_NAME")
	if err != nil {
		t.Fatal("disposable schema census unavailable")
	}
	defer rows.Close()
	var schemas []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			t.Fatal("disposable schema census unreadable")
		}
		schemas = append(schemas, name)
	}
	if rows.Err() != nil {
		t.Fatal("disposable schema census incomplete")
	}
	return schemas
}
