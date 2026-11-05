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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// This is a native MySQL SQL-transport/query/SELECT-permission component gate.
// Historical old/current config, normal-enable op/response and KEK rows are
// explicitly seeded from enabledSigningFixture's complete historical ROW
// MODEL. They are NOT created by the genuine normal-enable/admission writers.
// This test does not qualify normal enable, KEK/HSM, Task2 or 17-proof adoption.
func TestOriginalEnabledOnlyReaderHistoricalRowsMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pin := os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, e := os.ReadFile(os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"))
	if e != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("private disposable MySQL credentials unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	e = decoder.Decode(&credential)
	tail := decoder.Decode(new(any))
	clear(raw)
	if e != nil || tail != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) || credential.ServerUUID != pin || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(pin) {
		t.Fatal("disposable loopback/SAN/independent UUID pin invalid")
	}
	ca, e := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if e != nil || len(ca) == 0 || len(ca) > 65536 || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable CA unavailable")
	}
	clear(ca)
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credential.User, credential.Password
	credential.Password = ""
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.TLS = &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.MultiStatements = false
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	connector, e := mysql.NewConnector(cfg)
	cfg.Passwd = ""
	if e != nil {
		t.Fatal("disposable admin connector unavailable")
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { _ = admin.Close() })
	var actual, version, status, protocol string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION()").Scan(&actual, &version) != nil || actual != pin || !strings.HasPrefix(version, "8.4.8") || admin.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&status, &protocol) != nil || status != "Ssl_version" || protocol != "TLSv1.3" {
		t.Fatal("actual disposable MySQL 8.4.8/UUID/TLS1.3 mismatch")
	}
	var nonce [12]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		t.Fatal("private fixture nonce unavailable")
	}
	run := hex.EncodeToString(nonce[:])
	clear(nonce[:])
	schema, user := "ad_a_enabled_lineage_"+run, "ad_a_lin_"+run[:16]
	qschema := "`" + schema + "`"
	account := "'" + user + "'@'%'"
	// All interpolated identifiers/account fragments are locally generated hex.
	createdSchema, markerReady, createdUser := false, false, false
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if !createdSchema {
			return
		}
		var uuid, gotRun, gotSchema, gotServer, gotAccount string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != pin || !markerReady || admin.QueryRowContext(cleanup, "SELECT run_id,schema_name,server_uuid,account_name FROM "+qschema+".`_a_enabled_lineage_owner` WHERE id=1").Scan(&gotRun, &gotSchema, &gotServer, &gotAccount) != nil || gotRun != run || gotSchema != schema || gotServer != pin || gotAccount != user {
			t.Error("owned fixture cleanup marker/UUID mismatch; Root must remove its disposable fixture")
			return
		}
		if createdUser {
			if _, err := admin.ExecContext(cleanup, "DROP USER "+account); err != nil {
				t.Error("owned SELECT-only account cleanup failed")
				return
			}
		}
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+qschema); err != nil {
			t.Error("owned historical-row schema cleanup failed")
			return
		}
		var schemas, users int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=?", schema).Scan(&schemas) != nil || schemas != 0 || admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM mysql.user WHERE user=? AND host='%'", user).Scan(&users) != nil || users != 0 {
			t.Error("owned schema/account cleanup readback failed")
			return
		}
		t.Log("owned schema/marker and SELECT-only account cleanup readback PASS")
	})
	if _, e = admin.ExecContext(ctx, "CREATE DATABASE "+qschema+" CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
		t.Fatal("random owned schema creation failed")
	}
	createdSchema = true
	if _, e = admin.ExecContext(ctx, "CREATE TABLE "+qschema+".`_a_enabled_lineage_owner`(id INT PRIMARY KEY,run_id VARCHAR(64) NOT NULL,schema_name VARCHAR(64) NOT NULL,server_uuid CHAR(36) NOT NULL,account_name VARCHAR(32) NOT NULL) ENGINE=InnoDB"); e != nil {
		t.Fatal("owned marker DDL failed")
	}
	if _, e = admin.ExecContext(ctx, "INSERT INTO "+qschema+".`_a_enabled_lineage_owner` VALUES (1,?,?,?,?)", run, schema, pin, user); e != nil {
		t.Fatal("owned marker write failed")
	}
	markerReady = true
	// Reuse exactly the new component ROW MODEL; no normal-enable writer runs.
	_, m, _, _ := enabledSigningFixture(t)
	columns, _, e := m.old.sqlValues(m.policy.InstallationID, "41", "historical row fixture only", 1)
	if e != nil {
		t.Fatal("historical config fixture unavailable")
	}
	defs := []string{"schema_version VARCHAR(64) NOT NULL DEFAULT 'system-backup-config.v1'", "row_version BIGINT UNSIGNED NOT NULL DEFAULT 1"}
	for _, column := range columns {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(column) {
			t.Fatal("invalid source-defined config column")
		}
		kind := "LONGTEXT NOT NULL"
		switch column {
		case "origin_installation_id":
			kind = "VARCHAR(128) NOT NULL"
		case "version", "config_size_bytes", "minimum_recovery_points":
			kind = "BIGINT UNSIGNED NOT NULL"
		case "enabled":
			kind = "BOOLEAN NOT NULL"
		case "config_sha256":
			kind = "CHAR(64) NOT NULL"
		case "canonical_config_json":
			kind = "LONGBLOB NOT NULL"
		}
		if _, numeric := m.old.snapshot.numbers[column]; numeric {
			kind = "BIGINT UNSIGNED NOT NULL"
			if column == "source_size_safety_factor" {
				kind = "DECIMAL(20,2) NOT NULL"
			}
		}
		defs = append(defs, "`"+column+"` "+kind)
	}
	defs = append(defs, "PRIMARY KEY(origin_installation_id,version)", "CHECK(config_sha256=SHA2(canonical_config_json,256))", "CHECK(config_size_bytes=OCTET_LENGTH(canonical_config_json))")
	ddl := []string{
		"CREATE TABLE " + qschema + ".system_backup_v2_configs(" + strings.Join(defs, ",") + ") ENGINE=InnoDB",
		"CREATE TABLE " + qschema + `.system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(64) NOT NULL DEFAULT 'system-backup-installation-state.v1',active_config_version BIGINT UNSIGNED NOT NULL,last_effective_enabled BOOLEAN NOT NULL,row_version BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB`,
		"CREATE TABLE " + qschema + `.system_backup_v2_operations(id BIGINT UNSIGNED PRIMARY KEY,origin_installation_id VARCHAR(128) NOT NULL,public_id VARCHAR(64) NOT NULL,operation_type VARCHAR(32) NOT NULL,target_type VARCHAR(32) NOT NULL,target_public_id VARCHAR(128) NOT NULL,actor_type VARCHAR(32) NOT NULL,actor_id VARCHAR(32) NOT NULL,endpoint VARCHAR(255) NOT NULL,status VARCHAR(32) NOT NULL,result_config_version BIGINT UNSIGNED NOT NULL,http_status INT NOT NULL,schema_version VARCHAR(64) NOT NULL,retryable BOOLEAN NOT NULL,failure_category VARCHAR(32) NOT NULL,failure_message TEXT NULL,result_resource_public_id VARCHAR(128) NULL,idempotency_key VARCHAR(128) NOT NULL,request_hash CHAR(64) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,redacted_response_evidence_id BIGINT UNSIGNED NOT NULL,redacted_response_sha256 CHAR(64) NOT NULL,created_at DATETIME(6) NOT NULL,started_at DATETIME(6) NOT NULL,finished_at DATETIME(6) NOT NULL,updated_at DATETIME(6) NOT NULL,deadline_at DATETIME(6) NOT NULL,UNIQUE KEY original_operation(origin_installation_id,public_id)) ENGINE=InnoDB`,
		"CREATE TABLE " + qschema + `.system_backup_v2_evidence(id BIGINT UNSIGNED PRIMARY KEY,schema_version VARCHAR(64) NOT NULL,public_id VARCHAR(64) NOT NULL,owner_target_type VARCHAR(32) NOT NULL,owner_target_public_id VARCHAR(128) NOT NULL,evidence_type VARCHAR(32) NOT NULL,storage_state VARCHAR(32) NOT NULL,encryption VARCHAR(32) NOT NULL,observed_health VARCHAR(32) NOT NULL,media_type VARCHAR(64) NOT NULL,inline_payload MEDIUMBLOB NOT NULL,content_checksum CHAR(64) NOT NULL,content_size_bytes BIGINT UNSIGNED NOT NULL,expires_at DATETIME(6) NOT NULL,chunk_count INT UNSIGNED NOT NULL,claim_owner VARCHAR(128) NULL,claim_expires_at DATETIME(6) NULL,evidence_failure_code VARCHAR(64) NOT NULL,redaction_classification VARCHAR(64) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,created_at DATETIME(6) NOT NULL,storage_provider_role VARCHAR(64) NULL,storage_identity_hash CHAR(64) NULL,storage_ref_version VARCHAR(128) NULL,storage_relative_key TEXT NULL,storage_relative_key_hash CHAR(64) NULL,storage_immutable_version TEXT NULL,object_checksum CHAR(64) NULL,object_size_bytes BIGINT UNSIGNED NULL,plaintext_chunk_size_bytes BIGINT UNSIGNED NULL,chunk_list_root CHAR(64) NULL,envelope_framing_version VARCHAR(64) NULL,kek_identity_hash CHAR(64) NULL,kek_version VARCHAR(128) NULL,envelope_hash CHAR(64) NULL,CHECK(content_checksum=SHA2(inline_payload,256)),CHECK(content_size_bytes=OCTET_LENGTH(inline_payload))) ENGINE=InnoDB`,
		"CREATE TABLE " + qschema + `.system_backup_v2_evidence_chunks(evidence_id BIGINT UNSIGNED NOT NULL,chunk_index INT UNSIGNED NOT NULL,PRIMARY KEY(evidence_id,chunk_index)) ENGINE=InnoDB`,
		"CREATE TABLE " + qschema + `.system_backup_v2_kek_bindings(installation_id VARCHAR(128) NOT NULL,identity_hash CHAR(64) NOT NULL,registry_version VARCHAR(128) NOT NULL,core_json LONGBLOB NOT NULL,core_sha256 CHAR(64) NOT NULL,binding_sha256 CHAR(64) NOT NULL,PRIMARY KEY(installation_id,identity_hash,registry_version)) ENGINE=InnoDB`,
		"CREATE TABLE " + qschema + `.system_backup_v2_kek_admissions(installation_id VARCHAR(128) NOT NULL,operation_id VARCHAR(64) NOT NULL,identity_hash CHAR(64) NOT NULL,registry_version VARCHAR(128) NOT NULL,config_version BIGINT UNSIGNED NOT NULL,config_sha256 CHAR(64) NOT NULL,observation_json LONGBLOB NOT NULL,observation_sha256 CHAR(64) NOT NULL,PRIMARY KEY(installation_id,operation_id)) ENGINE=InnoDB`,
	}
	for index, statement := range ddl {
		if _, e = admin.ExecContext(ctx, statement); e != nil {
			t.Fatalf("minimal historical-row fixture DDL failed at source DDL index %d", index)
		}
	}
	var businessTables int
	if admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=? AND table_name<>'_a_enabled_lineage_owner' AND engine='InnoDB'", schema).Scan(&businessTables) != nil || businessTables != 7 {
		t.Fatal("exact seven owned InnoDB component tables unavailable")
	}
	for n, config := range []ConfigValues{m.old, m.current} {
		selected, args, err := config.sqlValues(m.policy.InstallationID, "41", "historical row fixture only", int64(n+1))
		if err != nil {
			t.Fatal("historical config values unavailable")
		}
		quoted := make([]string, len(selected))
		marks := make([]string, len(selected))
		for i, column := range selected {
			quoted[i] = "`" + column + "`"
			marks[i] = "?"
		}
		if _, e = admin.ExecContext(ctx, "INSERT INTO "+qschema+".system_backup_v2_configs("+strings.Join(quoted, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...); e != nil {
			t.Fatal("exact historical config row write failed")
		}
	}
	mustWrite := func(t *testing.T, statement string, args ...any) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal("historical row fixture write failed")
		}
	}
	mustWrite(t, "INSERT INTO "+qschema+`.system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,row_version) VALUES (?,2,TRUE,2)`, m.policy.InstallationID)
	v := m.policy
	mustWrite(t, "INSERT INTO "+qschema+`.system_backup_v2_operations(id,origin_installation_id,public_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,status,result_config_version,http_status,schema_version,retryable,failure_category,idempotency_key,request_hash,row_version,redacted_response_evidence_id,redacted_response_sha256,created_at,started_at,finished_at,updated_at,deadline_at) VALUES (51,?,?,'config_update','system',?,'admin',?,?,'succeeded',2,200,'system-backup-operation.v1',FALSE,'none',?,?,?,71,?,?,?,?,?,?)`, v.InstallationID, v.OperationPublicID, v.InstallationID, strconv.FormatInt(v.ActorID, 10), v.Endpoint, v.IdempotencyKey, v.RequestHash, v.RowVersion, registrationHash(string(m.response)), v.CreatedAt, v.StartedAt, v.FinishedAt, v.UpdatedAt, v.DeadlineAt)
	mustWrite(t, "INSERT INTO "+qschema+`.system_backup_v2_evidence(id,schema_version,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,encryption,observed_health,media_type,inline_payload,content_checksum,content_size_bytes,expires_at,chunk_count,evidence_failure_code,redaction_classification,row_version,created_at) VALUES (71,'system-backup-evidence.v1','sev_12345678-1234-1234-1234-123456789abc','system',?,'diagnostic','inline','none','healthy','application/json',?,?,?,?,0,'none','internal',1,?)`, v.InstallationID, m.response, registrationHash(string(m.response)), len(m.response), m.expires, v.FinishedAt)
	insertBinding := func(t *testing.T) {
		mustWrite(t, "INSERT INTO "+qschema+`.system_backup_v2_kek_bindings VALUES (?,?,?,?,?,?)`, v.InstallationID, strings.Repeat("b", 64), "synthetic-v1", m.core, m.coreSHA, m.bindingSHA)
	}
	insertBinding(t)
	mustWrite(t, "INSERT INTO "+qschema+`.system_backup_v2_kek_admissions VALUES (?,?,?,'synthetic-v1',2,?,?,?)`, v.InstallationID, v.OperationPublicID, strings.Repeat("b", 64), m.current.SHA256(), m.observation, m.observationSHA)
	var entropy [24]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		t.Fatal("private account entropy unavailable")
	}
	password := hex.EncodeToString(entropy[:])
	clear(entropy[:])
	if _, e = admin.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY '"+password+"' REQUIRE SSL"); e != nil {
		t.Fatal("owned SSL-only account creation failed")
	}
	createdUser = true
	tables := []string{"installation_state", "configs", "operations", "evidence", "evidence_chunks", "kek_admissions", "kek_bindings"}
	for _, table := range tables {
		if _, e = admin.ExecContext(ctx, "GRANT SELECT ON "+qschema+".`system_backup_v2_"+table+"` TO "+account); e != nil {
			t.Fatal("exact seven-table SELECT grant failed")
		}
	}
	consumerCfg := cfg.Clone()
	consumerCfg.User, consumerCfg.Passwd, consumerCfg.DBName = user, password, schema
	password = ""
	limited, e := mysql.NewConnector(consumerCfg)
	consumerCfg.Passwd = ""
	if e != nil {
		t.Fatal("owned limited connector unavailable")
	}
	reader := sql.OpenDB(limited)
	defer reader.Close()
	reader.SetMaxOpenConns(2)
	var selectedAccount, selectedDB string
	if reader.QueryRowContext(ctx, "SELECT @@server_uuid,CURRENT_USER(),DATABASE()").Scan(&actual, &selectedAccount, &selectedDB) != nil || actual != pin || selectedAccount != user+"@%" || selectedDB != schema || reader.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&status, &protocol) != nil || status != "Ssl_version" || protocol != "TLSv1.3" {
		t.Fatal("actual limited account/UUID/schema/TLS identity mismatch")
	}
	check := func(t *testing.T, allowed bool) {
		t.Helper()
		tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal("actual READ ONLY RR unavailable")
		}
		defer tx.Rollback()
		proof, err := ReadOriginalEnabledOnlyLineage(ctx, tx, v.InstallationID, m.old.SHA256(), 2, m.current.SHA256())
		if !allowed {
			if err == nil || proof != nil {
				t.Fatal("mutated historical fixture admitted by actual reader")
			}
			if tx.Rollback() != nil {
				t.Fatal("rejected reader view rollback failed")
			}
			return
		}
		if err != nil || !proof.Matches(v.InstallationID, m.old.SHA256(), 2, m.current.SHA256()) {
			t.Fatal("actual historical SQL reader positive failed")
		}
		sha, err := proof.AuthorizationConfigSHA256(ctx, tx)
		if err != nil || sha != m.old.SHA256() {
			t.Fatal("actual same-view authorization scope failed")
		}
		until, err := proof.OriginalDiagnosticUntil(ctx, tx)
		if err != nil || !until.Equal(m.expires) {
			t.Fatal("actual original diagnostic expiry read failed")
		}
		if tx.Rollback() != nil {
			t.Fatal("positive reader view rollback failed")
		}
		if _, err = proof.AuthorizationConfigSHA256(ctx, tx); err == nil {
			t.Fatal("closed actual transaction reused proof")
		}
	}
	t.Run("actual_read_only_rr_positive", func(t *testing.T) { check(t, true) })
	t.Run("flattened_config_drift", func(t *testing.T) {
		mustWrite(t, "UPDATE "+qschema+`.system_backup_v2_configs SET kek_identity_hash=? WHERE origin_installation_id=? AND version=2`, strings.Repeat("0", 64), v.InstallationID)
		defer mustWrite(t, "UPDATE "+qschema+`.system_backup_v2_configs SET kek_identity_hash=? WHERE origin_installation_id=? AND version=2`, strings.Repeat("b", 64), v.InstallationID)
		check(t, false)
	})
	t.Run("response_expiry", func(t *testing.T) {
		mustWrite(t, "UPDATE "+qschema+`.system_backup_v2_evidence SET expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=71`)
		defer mustWrite(t, "UPDATE "+qschema+`.system_backup_v2_evidence SET expires_at=? WHERE id=71`, m.expires)
		check(t, false)
	})
	t.Run("binding_absence", func(t *testing.T) {
		mustWrite(t, "DELETE FROM "+qschema+`.system_backup_v2_kek_bindings WHERE installation_id=?`, v.InstallationID)
		defer insertBinding(t)
		check(t, false)
	})
	t.Run("select_only_role_update_denied", func(t *testing.T) {
		// Outside READ ONLY: this proves account UPDATE denial, not transaction mode.
		_, err := reader.ExecContext(ctx, `UPDATE system_backup_v2_configs SET enabled=enabled WHERE origin_installation_id=? AND version=2`, v.InstallationID)
		var denied *mysql.MySQLError
		if !errors.As(err, &denied) || denied.Number != 1142 {
			t.Fatal("limited account UPDATE was not rejected by actual SQL privilege")
		}
	})
	check(t, true)
	t.Log("actual seven-table historical ROW FIXTURE reader + same-view scope/expiry + SELECT-only SSL role checked; no real normal-enable/admission/Task2 qualification")
}
