//go:build systembackup_mysql

package systembackupkekregistry

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
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// Only the supervisor's explicitly disposable, independently UUID-pinned
// SAN/TLS endpoint is accepted. No legacy non-TLS helper or production DSN.
func bindingReadTLSMySQL(t *testing.T, ctx context.Context) (*sql.DB, *sql.DB, string, Binding) {
	t.Helper()
	path, pin := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" {
		t.Skip("requires supervisor-owned disposable SAN/TLS MySQL credentials and independent UUID pin")
	}
	if !regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("independent disposable UUID pin required")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable TLS credentials unavailable")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err, tail := decoder.Decode(&credential), error(nil)
	if err == nil {
		tail = decoder.Decode(new(any))
	}
	clear(raw)
	if err != nil || tail != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.ServerUUID != pin || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) {
		t.Fatal("disposable endpoint/UUID/SAN TLS materials invalid")
	}
	ca, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable TLS CA unavailable")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("fixture nonce unavailable")
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "d-kek-binding-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("disposable verified TLS configuration failed")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credential.User, credential.Password
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc = tlsName, true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	// Session-only lock timeout makes the separate original writer's blocked
	// fence acquisition observable without timing sleeps or changing sysctls.
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "1"}
	cfg.MultiStatements = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("disposable TLS connection unavailable")
	}
	t.Cleanup(func() { admin.Close() })
	var actual, tlsVersion, cipher string
	var secure int
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid,@@require_secure_transport").Scan(&actual, &secure) != nil || actual != pin || secure != 1 ||
		admin.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&tlsVersion) != nil || tlsVersion != "TLSv1.3" ||
		admin.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("actual disposable UUID/secure transport/TLS1.3 session mismatch")
	}
	database := "d_kek_binding_" + run
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal("owned binding fixture schema creation failed")
	}
	markerWritten := false
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var got, marker string
		if !regexp.MustCompile(`^d_kek_binding_[a-f0-9]{24}$`).MatchString(database) || admin.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&got) != nil || got != pin {
			t.Error("binding fixture cleanup server/name ownership mismatch; retained exact schema", database)
			return
		}
		if markerWritten && (admin.QueryRowContext(clean, "SELECT run_id FROM `"+database+"`.d_binding_owner_marker").Scan(&marker) != nil || marker != run) {
			t.Error("binding fixture cleanup marker mismatch; retained exact schema", database)
			return
		}
		if _, err := admin.ExecContext(clean, "DROP DATABASE `"+database+"`"); err != nil {
			t.Error("owned binding fixture cleanup failed", database)
		}
	})
	cfg.DBName = database
	owner, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("owned fixture connection unavailable")
	}
	owner.SetMaxOpenConns(4)
	t.Cleanup(func() { owner.Close() })
	// Separate pool/physical transaction for the original owner Revoke path.
	writer, err := sql.Open("mysql", cfg.FormatDSN())
	credential.Password, cfg.Passwd = "", ""
	if err != nil {
		t.Fatal("independent fixture writer unavailable")
	}
	t.Cleanup(func() { writer.Close() })
	if _, err := owner.ExecContext(ctx, "CREATE TABLE d_binding_owner_marker(run_id VARCHAR(64) PRIMARY KEY) ENGINE=InnoDB"); err != nil {
		t.Fatal("binding fixture ownership marker unavailable")
	}
	if _, err := owner.ExecContext(ctx, "INSERT INTO d_binding_owner_marker VALUES (?)", run); err != nil {
		t.Fatal("binding fixture ownership marker write failed")
	}
	markerWritten = true
	ddl, err := os.ReadFile("../db/migrations/127_backup_v2_kek_registry.sql")
	if err != nil {
		t.Fatal("original registry migration unavailable")
	}
	if _, err := owner.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatal("original registry migration failed")
	}
	b := bindingReadFixture()
	b.InstallationID += "_" + run
	row := bindingReadFixtureRow(t)
	row.values[4], _, err = hashJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	row.values[3], err = semanticCoreHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, "INSERT INTO system_backup_v2_kek_fences(installation_id,epoch) VALUES (?,7)", b.InstallationID); err != nil {
		t.Fatal("owned fixture fence seed failed")
	}
	if _, err := owner.ExecContext(ctx, "INSERT INTO system_backup_v2_kek_bindings(installation_id,"+bindingReadColumns+") VALUES (?,?,?,?,?,?,?,?,?)", append([]any{b.InstallationID}, row.values...)...); err != nil {
		t.Fatal("owned fixture binding seed failed")
	}
	return owner, writer, run, b
}

type bindingReadRevocationAuthority struct {
	ctx   context.Context
	tx    *sql.Tx
	pin   ReferencePin
	rev   Revocation
	epoch uint64
	until time.Time
}

func (p bindingReadRevocationAuthority) Reference() ReferencePin { return p.pin }
func (p bindingReadRevocationAuthority) Revocation() Revocation  { return p.rev }
func (p bindingReadRevocationAuthority) ExpectedEpoch() uint64   { return p.epoch }
func (p bindingReadRevocationAuthority) ValidUntil() time.Time   { return p.until }
func (p bindingReadRevocationAuthority) Recheck(ctx context.Context, view SQLReadView, snapshot LockedSnapshot, now time.Time) error {
	facts := snapshot.Facts()
	if ctx != p.ctx || view != p.tx || facts.Epoch != p.epoch || len(facts.Bindings) != 1 || facts.Bindings[0].Binding.ConfigRef != p.pin || p.rev.ObservedAt.After(now) || !now.Before(p.until) {
		return ErrKEKFacts
	}
	return nil
}

func TestReadBindingTxReadOnlyAndOriginalRevokeMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, writerDB, _, binding := bindingReadTLSMySQL(t, ctx)
	store := &SQLStore{}
	read, err := owner.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer read.Rollback()
	facts, err := store.ReadBindingTx(ctx, read, binding.InstallationID, binding.ConfigRef)
	if err != nil || !SameSecurityBinding(facts.Binding, binding) || facts.RowVersion != 7 || facts.GenerateRevoked != nil || facts.UnwrapRevoked != nil {
		t.Fatal("real read-only transaction could not consume current exact binding", err)
	}
	// An independent original writer cannot pass its fence while the read-only
	// consumer holds the shared fence. Bind is used ONLY by this test writer,
	// never by ReadBindingTx. The server's 1205 is the observed lock contention.
	blocked, err := writerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, blockedErr := (SQLStore{}).Bind(ctx, blocked, binding.InstallationID)
	_ = blocked.Rollback()
	var lockErr *mysql.MySQLError
	if !errors.As(blockedErr, &lockErr) || lockErr.Number != 1205 {
		t.Fatal("independent original writer was not blocked by current shared fence", blockedErr)
	}
	// The exact binding row is also shared-locked, independently of the fence.
	rowWriter, err := writerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rv uint64
	rowErr := rowWriter.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR UPDATE NOWAIT", binding.InstallationID, binding.ConfigRef.IdentityHash, binding.ConfigRef.Version).Scan(&rv)
	_ = rowWriter.Rollback()
	if !errors.As(rowErr, &lockErr) || lockErr.Number != 3572 {
		t.Fatal("exact current binding row was not shared-locked", rowErr)
	}
	var unchanged uint64
	if read.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?", binding.InstallationID).Scan(&unchanged) != nil || unchanged != 7 {
		t.Fatal("read API changed/closed original transaction or fence")
	}
	if err := read.Commit(); err != nil {
		t.Fatal(err)
	}
	writer, err := writerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	bound, locked, err := (SQLStore{}).Bind(ctx, writer, binding.InstallationID)
	if err != nil {
		t.Fatal("released shared fence did not admit original writer", err)
	}
	var now time.Time
	if writer.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("original revocation SQL clock unavailable")
	}
	rev := bindingReadRevocation(UnwrapRevocation)
	rev.ObservedAt = now
	prepared := bindingReadRevocationAuthority{ctx: ctx, tx: writer, pin: binding.ConfigRef, rev: rev,
		epoch: locked.Facts().Epoch, until: now.Add(time.Minute)}
	if err := bound.Revoke(ctx, prepared); err != nil {
		t.Fatal("original independent writer Revoke failed", err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal("original unwrap revocation commit failed", err)
	}
	current, err := owner.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Rollback()
	facts, err = store.ReadBindingTx(ctx, current, binding.InstallationID, binding.ConfigRef)
	if err != nil || facts.RowVersion != 8 || facts.GenerateRevoked != nil || facts.UnwrapRevoked == nil || !reflect.DeepEqual(*facts.UnwrapRevoked, rev) || !SameSecurityBinding(facts.Binding, binding) {
		t.Fatal("new read-only consumer lost committed current independent Unwrap revocation", err)
	}
	// Returning facts does not waive a purpose revocation. C must explicitly
	// reject this nonnil UnwrapRevoked in its current authority gate.
}

func TestReadBindingTxMissingAndMalformedMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, _, _, binding := bindingReadTLSMySQL(t, ctx)
	store := &SQLStore{}
	read := func(installation string, pin ReferencePin) error {
		t.Helper()
		tx, err := owner.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = store.ReadBindingTx(ctx, tx, installation, pin)
		return err
	}
	missing := binding.InstallationID + "_missing"
	if !errors.Is(read(missing, binding.ConfigRef), ErrKEKFacts) || !errors.Is(read(binding.InstallationID, ReferencePin{IdentityHash: strings.Repeat("f", 64), Version: "absent-v1"}), ErrKEKFacts) {
		t.Fatal("absent fence/binding did not refuse")
	}
	var count int
	if owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_kek_fences WHERE installation_id=?", missing).Scan(&count) != nil || count != 0 {
		t.Fatal("read-only missing-fence path created a fence")
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := owner.ExecContext(ctx, query, args...); err != nil {
			t.Fatal("owned malformed-row test setup failed", err)
		}
	}
	for _, tc := range []struct {
		name, column string
		value        any
		restore      any
	}{
		{"core-hash", "core_sha256", strings.Repeat("0", 64), func() string { h, _ := semanticCoreHash(binding); return h }()},
		{"fingerprint", "binding_sha256", strings.Repeat("0", 64), func() string { h, _ := BindingFingerprint(binding); return h }()},
		{"zero-rv", "row_version", uint64(0), uint64(7)},
		{"unwrap-json", "unwrap_revocation_json", []byte(`{`), nil},
		{"generate-json", "generate_revocation_json", []byte(`{`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec("UPDATE system_backup_v2_kek_bindings SET "+tc.column+"=? WHERE installation_id=?", tc.value, binding.InstallationID)
			if !errors.Is(read(binding.InstallationID, binding.ConfigRef), ErrKEKFacts) {
				t.Fatal("malformed persisted binding accepted")
			}
			exec("UPDATE system_backup_v2_kek_bindings SET "+tc.column+"=? WHERE installation_id=?", tc.restore, binding.InstallationID)
		})
	}
	// Corrupt ONLY this uniquely owned test schema to remove uniqueness; the
	// production migration above remains unchanged. The API must still reject
	// two exact rows instead of selecting an arbitrary one.
	exec("DROP TABLE system_backup_v2_kek_references,system_backup_v2_kek_admissions")
	exec("ALTER TABLE system_backup_v2_kek_bindings DROP FOREIGN KEY sbv2_kek_binding_fence, DROP PRIMARY KEY")
	exec("INSERT INTO system_backup_v2_kek_bindings(installation_id,"+bindingReadColumns+") SELECT installation_id,"+bindingReadColumns+" FROM system_backup_v2_kek_bindings WHERE installation_id=?", binding.InstallationID)
	if !errors.Is(read(binding.InstallationID, binding.ConfigRef), ErrKEKFacts) {
		t.Fatal("duplicate current binding accepted")
	}
}
