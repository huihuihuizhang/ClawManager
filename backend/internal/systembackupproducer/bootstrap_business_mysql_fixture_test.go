//go:build systembackup_mysql

package systembackupproducer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// Real MySQL only. Reuses Root's independently UUID-pinned disposable SAN/TLS
// credentials convention; never accepts an arbitrary DSN or the original DB.
func bootstrapBusinessNativeDB(t *testing.T, ctx context.Context) (*sql.DB, *sql.DB, Scope, string) {
	t.Helper()
	path, pin := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"), os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if path == "" || !regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("explicit disposable SAN/TLS credentials and independent UUID pin required")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable credentials unavailable")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	err = d.Decode(&credential)
	tail := d.Decode(new(any))
	clear(raw)
	if err != nil || tail != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.ServerUUID != pin || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) {
		t.Fatal("disposable endpoint/UUID/SAN credential definition invalid")
	}
	ca, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable CA unavailable")
	}
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(entropy[:])
	tlsName := "a-bootstrap-business-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("verified TLS config unavailable")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credential.User, credential.Password
	credential.Password = ""
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.TLSConfig, cfg.ParseTime, cfg.Loc = tlsName, true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "1"}
	cfg.MultiStatements = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	var actual, version, tlsVersion, cipher string
	var secure int
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION(),@@require_secure_transport").Scan(&actual, &version, &secure) != nil || actual != pin || !strings.HasPrefix(version, "8.4.") || secure != 1 || admin.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&tlsVersion) != nil || tlsVersion != "TLSv1.3" || admin.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("actual pinned MySQL8.4/SAN TLS1.3 session mismatch")
	}
	database, user := "a_bootstrap_"+run, "ab_"+run[:20]
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal("owned schema create", err)
	}
	markerWritten, userCreated := false, false
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var got, marker string
		if !regexp.MustCompile(`^a_bootstrap_[a-f0-9]{24}$`).MatchString(database) || !regexp.MustCompile(`^ab_[a-f0-9]{20}$`).MatchString(user) || admin.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&got) != nil || got != pin {
			t.Error("cleanup identity mismatch; retained owned schema/user")
			return
		}
		if markerWritten && (admin.QueryRowContext(clean, "SELECT run_id FROM `"+database+"`.a_bootstrap_owner_marker").Scan(&marker) != nil || marker != run) {
			t.Error("cleanup marker mismatch; retained owned schema/user")
			return
		}
		if userCreated {
			if _, err := admin.ExecContext(clean, "DROP USER '"+user+"'@'%'"); err != nil {
				t.Error("owned user cleanup", err)
			}
		}
		if _, err := admin.ExecContext(clean, "DROP DATABASE `"+database+"`"); err != nil {
			t.Error("owned schema cleanup", err)
		}
	})
	cfg.DBName = database
	owner, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	if _, err := owner.ExecContext(ctx, "CREATE TABLE a_bootstrap_owner_marker(run_id VARCHAR(64) PRIMARY KEY) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, "INSERT INTO a_bootstrap_owner_marker VALUES (?)", run); err != nil {
		t.Fatal(err)
	}
	markerWritten = true
	ddl, err := os.ReadFile("../db/migrations/137_backup_producer_authority.sql")
	digest := sha256.Sum256(ddl)
	if err != nil || hex.EncodeToString(digest[:]) != "2879ac4a1ed73b2e30315b10f4153a89ddb7fbd3f2d7c46fdca9b93dd9485bb2" {
		t.Fatal("exact formal137 schema pin mismatch")
	}
	if _, err := owner.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatal("actual formal137 eight tables", err)
	}
	if _, err := owner.ExecContext(ctx, bootstrapBusinessMetadataDDL); err != nil {
		t.Fatal("declared TEST metadata fixture", err)
	}
	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := "Aa1!" + hex.EncodeToString(secret[:])
	clear(secret[:])
	if _, err := admin.ExecContext(ctx, "CREATE USER '"+user+"'@'%' IDENTIFIED BY '"+password+"' REQUIRE SSL"); err != nil {
		t.Fatal("owned business principal", err)
	}
	userCreated = true
	for _, table := range []string{"domains", "grants", "runs", "targets", "evidence_bindings", "result_receipts", "evidence_refs"} {
		if _, err := admin.ExecContext(ctx, "GRANT SELECT ON `"+database+"`.`system_backup_producer_"+table+"` TO '"+user+"'@'%'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.ExecContext(ctx, "GRANT UPDATE ON `"+database+"`.`system_backup_producer_domains` TO '"+user+"'@'%'"); err != nil {
		t.Fatal(err)
	}
	// These extra grants are explicitly TEST metadata authority, outside the
	// C1 table set. They are not a claim about D1's complete production profile.
	// Match these two existing business baseline entries exactly. Evidence
	// needs its original UPDATE privilege for the SDK's exclusive source lock;
	// chunks has no UPDATE privilege and remains protected by FOR SHARE.
	for _, grant := range []struct{ table, privileges string }{
		{"system_backup_v2_evidence", "INSERT,SELECT,UPDATE"},
		{"system_backup_v2_evidence_chunks", "INSERT,SELECT"},
	} {
		if _, err := admin.ExecContext(ctx, "GRANT "+grant.privileges+" ON `"+database+"`.`"+grant.table+"` TO '"+user+"'@'%'"); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations"} {
		if _, err := admin.ExecContext(ctx, "GRANT SELECT,INSERT,UPDATE ON `"+database+"`.`"+table+"` TO '"+user+"'@'%'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.ExecContext(ctx, "GRANT SELECT,INSERT ON `"+database+"`.`audit_logs` TO '"+user+"'@'%'"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "GRANT SELECT(id,username,role,is_active,auth_provider) ON `"+database+"`.`users` TO '"+user+"'@'%'"); err != nil {
		t.Fatal(err)
	}
	businessCfg := cfg.Clone()
	businessCfg.User, businessCfg.Passwd = user, password
	cfg.Passwd = ""
	password = ""
	businessCfg.MultiStatements = false
	connector, err := mysql.NewConnector(businessCfg)
	businessCfg.Passwd = ""
	if err != nil {
		t.Fatal("business connector unavailable")
	}
	// Only the actual business connection is traced. Admin/credential SQL is
	// never wrapped; the wrapper logs fixed SQL and numeric error codes only.
	business := sql.OpenDB(bootstrapNativeTraceConnector{Connector: connector, t: t})
	business.SetMaxOpenConns(1)
	t.Cleanup(func() { business.Close() })
	var principal, statusName string
	if business.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&principal) != nil || principal != user+"@%" || business.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&statusName, &tlsVersion) != nil || tlsVersion != "TLSv1.3" {
		t.Fatal("actual separate business principal/TLS mismatch")
	}
	// Exact actual C1 privileges: seven SELECT + UPDATE domains, no column,
	// schema, role or global grant is created by this fixture.
	rows, err := admin.QueryContext(ctx, "SELECT TABLE_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=? AND TABLE_SCHEMA=? AND TABLE_NAME LIKE 'system_backup_producer_%' ORDER BY TABLE_NAME,PRIVILEGE_TYPE", "'"+user+"'@'%'", database)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for rows.Next() {
		var table, verb, grantable string
		if rows.Scan(&table, &verb, &grantable) != nil || grantable != "NO" {
			rows.Close()
			t.Fatal("business C1 privilege shape")
		}
		got = append(got, table+":"+verb)
	}
	if rows.Err() != nil || rows.Close() != nil {
		t.Fatal("business grant EOF")
	}
	want := []string{}
	for _, table := range []string{"domains", "grants", "runs", "targets", "evidence_bindings", "result_receipts", "evidence_refs"} {
		want = append(want, "system_backup_producer_"+table+":SELECT")
	}
	want = append(want, "system_backup_producer_domains:UPDATE")
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatal("actual C1 grants differ", got, want)
	}
	return owner, business, Scope{ServerUUID: ServerUUID(pin), Database: Database(database), Installation: "installation_native_business"}, principal
}

// Explicit TEST-only metadata schema. C1 tables above are the real pinned
// migration137 verbatim. This harness does not replace full migration tests.
const bootstrapBusinessMetadataDDL = `
CREATE TABLE users(id BIGINT PRIMARY KEY,username VARCHAR(128),role VARCHAR(32),is_active BOOLEAN,auth_provider VARCHAR(32)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_evidence(id BIGINT PRIMARY KEY,schema_version VARCHAR(64),public_id VARCHAR(128) UNIQUE,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(64),storage_state VARCHAR(32),evidence_failure_code VARCHAR(32),storage_provider_role VARCHAR(32),storage_identity_hash CHAR(64),storage_ref_version VARCHAR(128),storage_relative_key_hash CHAR(64),storage_relative_key VARCHAR(1024),storage_immutable_version VARCHAR(256),content_checksum CHAR(64),content_size_bytes BIGINT,object_checksum CHAR(64),object_size_bytes BIGINT,redaction_classification VARCHAR(32),encryption VARCHAR(32),envelope_framing_version VARCHAR(64),kek_identity_hash CHAR(64),kek_version VARCHAR(128),row_version BIGINT,expires_at DATETIME(6),protected_until DATETIME(6),claim_owner VARCHAR(128) NULL,claim_expires_at DATETIME(6) NULL,inline_payload MEDIUMBLOB NULL,chunk_count BIGINT,plaintext_chunk_size_bytes BIGINT,chunk_list_root CHAR(64),envelope_hash CHAR(64),media_type VARCHAR(64),created_at DATETIME(6)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_evidence_chunks(id BIGINT PRIMARY KEY,evidence_id BIGINT,chunk_index BIGINT,plaintext_offset BIGINT,plaintext_length BIGINT,plaintext_sha256 CHAR(64),object_frame_offset BIGINT,object_frame_length BIGINT,ciphertext_sha256 CHAR(64),gcm_nonce VARBINARY(128),gcm_tag VARBINARY(128),UNIQUE KEY(evidence_id,chunk_index)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128),version BIGINT,enabled BOOLEAN,config_sha256 CHAR(64),config_canonical_json MEDIUMBLOB,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,active_config_version BIGINT,matrix_key VARCHAR(128)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_operations(public_id VARCHAR(128) PRIMARY KEY,origin_installation_id VARCHAR(128),operation_type VARCHAR(64),target_type VARCHAR(32),target_public_id VARCHAR(128),actor_type VARCHAR(32),actor_id VARCHAR(128),endpoint VARCHAR(256),idempotency_key VARCHAR(128),request_hash CHAR(64),status VARCHAR(32),external_action_public_ids_canonical_json MEDIUMBLOB,external_action_public_ids_sha256 CHAR(64),result_config_version BIGINT,http_status BIGINT,external_action_public_ids_size_bytes BIGINT,UNIQUE KEY(origin_installation_id,actor_type,actor_id,endpoint,idempotency_key)) ENGINE=InnoDB;
CREATE TABLE audit_logs(id BIGINT PRIMARY KEY,user_id BIGINT,action VARCHAR(128),resource_type VARCHAR(32),resource_id BIGINT NULL,details MEDIUMBLOB,created_at DATETIME(6)) ENGINE=InnoDB;
`

func bootstrapNativeInsert(t *testing.T, ctx context.Context, db *sql.DB, table string, values map[string]any) {
	t.Helper()
	columns := []string{}
	for c := range values {
		columns = append(columns, c)
	}
	sort.Strings(columns)
	quoted, args, marks := []string{}, []any{}, []string{}
	for _, c := range columns {
		quoted = append(quoted, "`"+c+"`")
		args = append(args, values[c])
		marks = append(marks, "?")
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO `"+table+"` ("+strings.Join(quoted, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...); err != nil {
		t.Fatal("native fixture insert", table, err)
	}
}
