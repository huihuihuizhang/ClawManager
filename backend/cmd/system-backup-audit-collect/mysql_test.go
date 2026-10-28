//go:build audit_collector_mysql

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestAuditCollectorMySQL(t *testing.T) {
	// The runner creates a fresh, empty MySQL pod. Never accept an arbitrary DSN.
	runID, uid := os.Getenv("A_AUDIT_MYSQL_RUN"), os.Getenv("A_AUDIT_MYSQL_UID")
	if !regexp.MustCompile(`^aaudit-[0-9]{14}-[a-f0-9]{8}$`).MatchString(runID) || !uuidPattern.MatchString(uid) || os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("isolated runner identity required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := mysql.NewConfig()
	config.User, config.Passwd, config.Net, config.Addr = "root", os.Getenv("MYSQL_ROOT_PASSWORD"), "unix", "/var/run/mysqld/mysqld.sock"
	config.Timeout, config.ReadTimeout, config.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	connect := func(c *mysql.Config) *sql.DB {
		t.Helper()
		connector, err := mysql.NewConnector(c)
		if err != nil {
			t.Fatal("connector rejected")
		}
		db := sql.OpenDB(connector)
		db.SetMaxOpenConns(1)
		t.Cleanup(func() {
			if db.Close() != nil {
				t.Error("database close failed")
			}
		})
		return db
	}
	admin := connect(config)
	var server, markerRun, markerUID, markerServer, version string
	mustAt := func(stage string, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(mysqlFixtureFailure(stage, err))
		}
	}
	must := func(err error) { t.Helper(); mustAt("fixture", err) }
	must(admin.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION()").Scan(&server, &version))
	must(admin.QueryRowContext(ctx, "SELECT run_id,namespace_uid,server_uuid FROM aaudit_guard.run_marker WHERE id=1").Scan(&markerRun, &markerUID, &markerServer))
	if !uuidPattern.MatchString(server) || server != markerServer || markerRun != runID || markerUID != uid || !(strings.HasPrefix(version, "8.4.") || strings.HasPrefix(version, "8.0.")) {
		t.Fatal("isolated server binding rejected")
	}
	var count int
	must(admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','performance_schema','information_schema','aaudit_guard')").Scan(&count))
	if count != 0 {
		t.Fatal("server was not empty")
	}
	_, err := admin.ExecContext(ctx, "CREATE DATABASE aaudit_fixture")
	must(err)
	config.DBName = "aaudit_fixture"
	admin = connect(config)
	schemaSteps, err := mysqlFixtureSchemaSteps(mysqlAuditSchema)
	mustAt("schema_layout", err)
	for _, step := range schemaSteps {
		_, err = admin.ExecContext(ctx, step.query)
		mustAt(step.stage, err)
	}
	password := make([]byte, 24)
	_, err = rand.Read(password)
	must(err)
	observerPassword := hex.EncodeToString(password)
	clear(password)
	for _, user := range []string{"aaudit_observer", "aaudit_denied"} {
		_, err = admin.ExecContext(ctx, "CREATE USER '"+user+"'@'localhost' IDENTIFIED BY '"+observerPassword+"'")
		must(err)
	}
	_, err = admin.ExecContext(ctx, "GRANT SELECT ON aaudit_fixture.* TO 'aaudit_observer'@'localhost'")
	must(err)
	var fixture map[string]any
	must(json.Unmarshal(mysqlAuditFixture, &fixture))
	part := func(name string) map[string]any { return fixture[name].(map[string]any) }
	body := func(name string) string { b, e := json.Marshal(part(name)["body"]); must(e); return string(b) }
	o, a, i, l := part("operation"), part("admission"), part("intent"), part("result_link")
	exec := func(query string, args ...any) { t.Helper(); _, e := admin.ExecContext(ctx, query, args...); must(e) }
	seedSteps, err := mysqlFixtureSeedSteps(mysqlAuditFixture)
	mustAt("seed_layout", err)
	for _, step := range seedSteps {
		_, err = admin.ExecContext(ctx, step.query, step.args...)
		mustAt(step.stage, err)
	}
	ab := a["body"].(map[string]any)
	observer := config.Clone()
	observer.User, observer.Passwd = "aaudit_observer", observerPassword
	observerDB := connect(observer)
	receipt := map[string]any{"status": "HTTP_PASSED_AUDIT_PENDING", "server_uuid": server, "database": "aaudit_fixture", "operation_public_id": o["public_id"], "evidence_id": o["evidence_id"], "installation_id": o["installation_id"], "user_id": 42, "idempotency_key": o["idempotency_key"], "request_hash": o["request_hash"], "subject_sha256": ab["subject_sha256"], "session_sha256": ab["session_sha256"], "expected_bytes": 17, "received_bytes": 17}
	receiptRaw, err := json.Marshal(receipt)
	must(err)
	req := request{SchemaVersion: "a_live_download_audit_request.v1", ServerUUID: server, Database: "aaudit_fixture", CurrentUser: "aaudit_observer@localhost", CurrentRole: "NONE", OperationID: o["public_id"].(string), ReceiptSHA256: digest(receiptRaw), Transport: transport{Mode: "unix"}}
	tmp := t.TempDir()
	dsnPath := filepath.Join(tmp, "observer.dsn")
	must(os.WriteFile(dsnPath, []byte(observer.FormatDSN()), 0600))
	collect := func(t *testing.T, requestValue request, path string, accept bool, review bool) {
		t.Helper()
		raw, e := json.Marshal(requestValue)
		must(e)
		var out bytes.Buffer
		e = run(ctx, []string{"--dsn-file", path}, bytes.NewReader(raw), &out)
		if !accept {
			if e == nil || out.Len() != 0 {
				t.Fatal("rejection emitted successful output")
			}
			return
		}
		if e != nil {
			t.Fatal("collection rejected valid structural fixture")
		}
		var result collection
		if json.Unmarshal(out.Bytes(), &result) != nil || !result.ReadOnly || !result.RolledBack || result.Before.ConnectionID != result.After.ConnectionID || result.RequestSHA256 != digest(raw) {
			t.Fatal("invalid collection envelope")
		}
		sample := map[string]any{"case": t.Name(), "receipt": json.RawMessage(receiptRaw), "request": json.RawMessage(raw), "collection": json.RawMessage(out.Bytes()), "expect_review": review}
		encoded, e := json.Marshal(sample)
		must(e)
		t.Log("A_AUDIT_SAMPLE " + string(encoded))
	}
	t.Run("success", func(t *testing.T) { collect(t, req, dsnPath, true, true) })
	for _, kind := range []string{"server", "database", "user", "role", "operation"} {
		t.Run("wrong_"+kind, func(t *testing.T) {
			wrong := req
			switch kind {
			case "server":
				wrong.ServerUUID = "00000000-0000-0000-0000-000000000000"
			case "database":
				wrong.Database = "aaudit_guard"
			case "user":
				wrong.CurrentUser = "other@localhost"
			case "role":
				wrong.CurrentRole = "other"
			case "operation":
				wrong.OperationID = "sop_00000000-0000-0000-0000-000000000000"
			}
			collect(t, wrong, dsnPath, false, false)
		})
	}
	t.Run("permission_denied", func(t *testing.T) {
		denied := observer.Clone()
		denied.User = "aaudit_denied"
		path := filepath.Join(tmp, "denied.dsn")
		must(os.WriteFile(path, []byte(denied.FormatDSN()), 0600))
		q := req
		q.CurrentUser = "aaudit_denied@localhost"
		collect(t, q, path, false, false)
	})
	t.Run("observer_cannot_write", func(t *testing.T) {
		_, e := observerDB.ExecContext(ctx, "UPDATE system_backup_v2_operations SET status='failed' WHERE id=11")
		var me *mysql.MySQLError
		if !errors.As(e, &me) || me.Number != 1142 {
			t.Fatal("observer update was not denied")
		}
	})
	t.Run("server_enforces_readonly", func(t *testing.T) {
		tx, e := admin.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		must(e)
		defer tx.Rollback()
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_operations SET status='failed' WHERE id=11")
		var me *mysql.MySQLError
		if !errors.As(e, &me) || me.Number != 1792 {
			t.Fatal("server did not enforce readonly transaction")
		}
		must(tx.Rollback())
	})
	for _, tc := range []struct {
		name, change, restore string
		accept, review        bool
	}{
		{"missing_join", "UPDATE system_backup_v2_download_result_receipts SET result_audit_id=99", "UPDATE system_backup_v2_download_result_receipts SET result_audit_id=13", false, false},
		{"malformed_body", "UPDATE system_backup_v2_download_admission_receipts SET receipt_canonical_json='broken'", "", false, false},
		{"unknown_body", "UPDATE audit_logs SET details=JSON_SET(details,'$.private_material','MUST_NOT_EXPORT') WHERE id=13", "", false, false},
		{"duplicate_rows", "INSERT INTO system_backup_v2_download_admission_receipts SELECT * FROM system_backup_v2_download_admission_receipts", "DELETE FROM system_backup_v2_download_admission_receipts LIMIT 1", false, false},
		{"broken_link", "UPDATE system_backup_v2_download_result_receipts SET intent_audit_id=99", "UPDATE system_backup_v2_download_result_receipts SET intent_audit_id=12", true, false},
		{"broken_nonce", "DELETE FROM system_backup_v2_strong_auth_nonces", "", true, false},
		{"broken_digest", "UPDATE system_backup_v2_download_result_receipts SET result_sha256=REPEAT('0',64)", "UPDATE system_backup_v2_download_result_receipts SET result_sha256='" + l["sha256"].(string) + "'", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.change)
			defer func() {
				switch tc.name {
				case "malformed_body":
					exec("UPDATE system_backup_v2_download_admission_receipts SET receipt_canonical_json=?", body("admission"))
				case "unknown_body":
					exec("UPDATE audit_logs SET details=? WHERE id=13", body("result"))
				case "broken_nonce":
					exec("INSERT INTO system_backup_v2_strong_auth_nonces VALUES (?,?,?,?,?,?,?,?)", o["id"], i["id"], o["installation_id"], o["endpoint"], o["idempotency_key"], o["request_hash"], ab["subject_sha256"], ab["session_sha256"])
				default:
					exec(tc.restore)
				}
			}()
			collect(t, req, dsnPath, tc.accept, tc.review)
		})
	}
	t.Run("final_success", func(t *testing.T) { collect(t, req, dsnPath, true, true) })
	t.Logf("A_AUDIT_MYSQL server_uuid=%s version=%s fixture=synthetic_selected_columns transport=unix http=synthetic migrations=not_run", server, version)
}
