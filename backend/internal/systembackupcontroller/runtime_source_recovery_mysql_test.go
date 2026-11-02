//go:build systembackup_mysql

package systembackupcontroller

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

// All tables below are connection-private TEMPORARY tables on the supervisor's
// independently UUID-pinned disposable TLS server. Closing the single owned
// connection drops every table; no source DB, shared schema or files are changed.
func sourceRecoveryTemporarySQL(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	path, pin := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" {
		t.Skip("requires supervisor disposable SAN/TLS MySQL and independent UUID pin")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &credential) != nil || pin == "" || credential.ServerUUID != pin || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" {
		t.Fatal("owned disposable TLS credentials/UUID unavailable")
	}
	clear(raw)
	pem, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		t.Fatal("owned TLS CA unavailable")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("fixture nonce")
	}
	tlsName := "d-source-recovery-" + hex.EncodeToString(nonce[:])
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("verified TLS config")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port)), "mysql"
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc = tlsName, true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	credential.Password, cfg.Passwd = "", ""
	if err != nil {
		t.Fatal("owned TLS connection")
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var actual, version string
	var secure int
	if db.QueryRowContext(ctx, "SELECT @@server_uuid,@@require_secure_transport").Scan(&actual, &secure) != nil || actual != pin || secure != 1 || db.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&version) != nil || version != "TLSv1.3" {
		t.Fatal("actual disposable TLS/UUID mismatch")
	}
	return db
}

func TestSourceRecoveryOldEpochLeaseFactsIgnoreNewBusinessWorkMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := sourceRecoveryTemporarySQL(t, ctx)
	for _, statement := range []string{
		`CREATE TEMPORARY TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(80),application_scope VARCHAR(80),gate_generation BIGINT UNSIGNED,acquire_token BIGINT UNSIGNED,held_token BIGINT NULL,collectors_stopped_at DATETIME(6),source_resumed_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TEMPORARY TABLE system_backup_mutation_leases(public_id VARCHAR(80) PRIMARY KEY,scope VARCHAR(80),generation BIGINT UNSIGNED,expires_at DATETIME(6),released_at DATETIME(6) NULL) ENGINE=InnoDB`,
		`INSERT INTO system_backup_v2_runtime_captures VALUES ('original-task','original-scope',7,20,21,UTC_TIMESTAMP(6)-INTERVAL 10 SECOND,UTC_TIMESTAMP(6)-INTERVAL 5 SECOND)`,
		`INSERT INTO system_backup_mutation_leases VALUES ('old-released','original-scope',6,UTC_TIMESTAMP(6)-INTERVAL 1 MINUTE,UTC_TIMESTAMP(6)-INTERVAL 15 SECOND),('new-active','original-scope',7,UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE,NULL),('foreign-active','foreign',6,UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE,NULL)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal("owned lease fixture setup")
		}
	}
	g := SQLCaptureGate{Authority: SQLExecutionAuthority{DB: db, ApplicationScope: "original-scope"}}
	a := d.Authority{TaskPublicID: "original-task", MaintenanceFencingToken: 7}
	read := func() ([]byte, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		return g.sourceRecoveryLeaseFactsTx(ctx, tx, a)
	}
	before, err := read()
	if err != nil {
		t.Fatal("new legitimate active lease blocked original release facts")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO system_backup_mutation_leases VALUES ('another-new-active','original-scope',7,UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE,NULL)`); err != nil {
		t.Fatal("new business work fixture")
	}
	after, err := read()
	if err != nil || string(before) != string(after) {
		t.Fatal("new business work changed immutable old work digest")
	}
	for _, tc := range []struct{ name, mutate, reset string }{
		{"unreleased-old-work", `UPDATE system_backup_mutation_leases SET released_at=NULL WHERE public_id='old-released'`, `UPDATE system_backup_mutation_leases SET released_at=UTC_TIMESTAMP(6)-INTERVAL 15 SECOND WHERE public_id='old-released'`},
		{"late-old-release", `UPDATE system_backup_mutation_leases SET released_at=UTC_TIMESTAMP(6) WHERE public_id='old-released'`, `UPDATE system_backup_mutation_leases SET released_at=UTC_TIMESTAMP(6)-INTERVAL 15 SECOND WHERE public_id='old-released'`},
		{"missing-held-proof", `UPDATE system_backup_v2_runtime_captures SET held_token=NULL`, `UPDATE system_backup_v2_runtime_captures SET held_token=21`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, tc.mutate); err != nil {
				t.Fatal("negative fixture mutation")
			}
			if _, err := read(); err == nil {
				t.Fatal("old work release/held proof was inferred")
			}
			if _, err := db.ExecContext(ctx, tc.reset); err != nil {
				t.Fatal("owned fixture reset")
			}
		})
	}
}

func TestSourceRecoveryUnfilteredStableFamilyFindsExpiredCrossOwnerOrphansMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := sourceRecoveryTemporarySQL(t, ctx)
	if _, err := db.ExecContext(ctx, `CREATE TEMPORARY TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(20),owner_target_public_id VARCHAR(80),observed_health VARCHAR(20),expires_at DATETIME(6)) ENGINE=InnoDB`); err != nil {
		t.Fatal("owned evidence fixture")
	}
	scope := ce.Scope{Installation: "installation", Backup: "sbk_original", Attempt: 1}
	for _, id := range []string{sourceRecoveryID(scope, "writer"), sourceRecoveryID(scope, "") + ":child", sourceRecoveryFamily(scope) + "bad-descendant"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence VALUES (?,'backup','sbk_foreign','unhealthy',UTC_TIMESTAMP(6)-INTERVAL 1 DAY)`, id); err != nil {
			t.Fatal("expired cross-owner orphan fixture")
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("owned family read")
	}
	defer tx.Rollback()
	count, err := sourceRecoveryFamilyCountTx(ctx, tx, scope)
	if err != nil || count != 3 {
		t.Fatal("unfiltered original family orphan was invisible")
	}
	scope.Attempt++
	count, err = sourceRecoveryFamilyCountTx(ctx, tx, scope)
	if err != nil || count != 0 {
		t.Fatal("another attempt inherited family residue")
	}
}
