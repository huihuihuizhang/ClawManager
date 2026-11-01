package domain

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	mysql "github.com/go-sql-driver/mysql"
)

// Opt-in to a caller-owned disposable loopback server only. No application
// configuration, remote DSNs or existing databases/accounts are discovered.
// Skills DDL is loaded from the actual migrations; instance/Team fixture DDL
// exercises the shared SQL path and does not claim a full production schema.
func TestOfflineBusinessRestoreMySQL(t *testing.T) {
	dsn := os.Getenv("CLAWMANAGER_OFFLINE_RESTORE_MYSQL_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires a dedicated disposable loopback MySQL")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid isolated test DSN")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || cfg.Net != "tcp" || host != "127.0.0.1" || cfg.DBName != "" {
		t.Fatal("dedicated loopback server without a database required")
	}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.ParseTime = false
	cfg.MultiStatements = false
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	open := func(c mysql.Config) *sql.DB {
		db, err := sql.Open("mysql", c.FormatDSN())
		if err != nil {
			t.Fatal("test connection failed")
		}
		t.Cleanup(func() { db.Close() })
		if db.PingContext(ctx) != nil {
			t.Fatal("test server unavailable")
		}
		return db
	}
	admin := open(*cfg)
	t.Run("native-json-boundaries", func(t *testing.T) { testNativeJSONCanonicalization(t, ctx, admin) })
	exec := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			var sqlErr *mysql.MySQLError
			if errors.As(err, &sqlErr) {
				t.Fatalf("fixture SQL failed: MySQL error %d", sqlErr.Number)
			}
			t.Fatalf("fixture SQL failed: %T", err)
		}
	}
	cleanup := func(q string) {
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.ExecContext(c, q); err != nil {
				t.Error("owned fixture cleanup failed")
			}
		})
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(nonce[:])
	seed, _, policy := businessRestoreFixture()
	callerSeed, _, callerPolicy := callerRestoreFixture()
	// Reuse nonempty caller history, but build its schema from actual 057/066.
	seed.Tables[0] = find(callerSeed, "users")
	callerTable := find(callerSeed, "northbound_caller_policies")
	nullCaller := cloneRow(callerTable.Rows[0])
	nullCaller["user_id"], nullCaller["enabled"], nullCaller["scopes_json"] = Text("1"), Text("0"), Text("[]")
	nullCaller["api_keys_json"], nullCaller["updated_by"], nullCaller["api_keys_version"] = Cell{Null: true}, Cell{Null: true}, Text("0")
	callerTable.Rows = append(callerTable.Rows, nullCaller)
	seed.Tables = append(seed.Tables, callerTable)
	policy.Dependencies = callerPolicy.Dependencies
	operationSeed, _, operationPolicy := operationRestoreFixture()
	seed.Tables = append(seed.Tables, find(operationSeed, "northbound_operations"))
	policy.Dependencies["northbound_operations"] = operationPolicy.Dependencies["northbound_operations"]
	policy.Configs.(JSONRegistry)["northbound_operations.request_payload"] = operationPolicy.Configs.(JSONRegistry)["northbound_operations.request_payload"]
	create := func(name string) *sql.DB {
		exec(admin, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
		cleanup("DROP DATABASE `" + name + "`")
		c := *cfg
		c.DBName = name
		c.MultiStatements = true
		db := open(c)
		for _, table := range seed.Tables {
			if table.Name == "northbound_caller_policies" || table.Name == "northbound_operations" {
				continue
			}
			if _, skill := skillCaptureColumns[table.Name]; skill {
				continue
			}
			var columns []string
			for _, col := range table.Columns {
				kind := "VARCHAR(255) NULL"
				if col.Name == "id" {
					kind = "INT NOT NULL PRIMARY KEY"
				}
				columns = append(columns, "`"+col.Name+"` "+kind)
			}
			exec(db, "CREATE TABLE `"+table.Name+"` ("+strings.Join(columns, ",")+") ENGINE=InnoDB")
		}
		// Migration 039's historical update needs these columns even when empty.
		exec(db, "CREATE TABLE instance_commands (id INT PRIMARY KEY, instance_id INT, status VARCHAR(30), error_message TEXT, command_type VARCHAR(60)) ENGINE=InnoDB")
		if !hasColumn(find(seed, "instances"), "runtime_error_message") {
			exec(db, "ALTER TABLE instances ADD COLUMN runtime_error_message TEXT NULL")
		}
		// Empty template prerequisite for actual owner-Team migration 077.
		exec(db, "CREATE TABLE custom_team_templates (id INT PRIMARY KEY,user_id INT NOT NULL) ENGINE=InnoDB")
		for _, file := range []string{"008_add_skill_management.sql", "023_add_skill_hub.sql", "039_add_skill_package_materialize.sql", "045_add_northbound_api.sql", "057_add_northbound_admin_settings.sql", "066_add_northbound_api_keys.sql", "077_add_northbound_owner_teams.sql"} {
			raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", file))
			if err != nil {
				t.Fatal("migration unavailable")
			}
			exec(db, string(raw))
		}
		// Provision an empty disposable target, not an initialized application.
		// The production restore correctly refuses seeded/nonempty business data.
		exec(db, "DELETE FROM skill_hub_tags")
		exec(db, "DELETE FROM northbound_admin_settings")
		return db
	}
	principal := func(name, database, grants string) *sql.DB {
		password := suffix + suffix
		exec(admin, "CREATE USER '"+name+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'")
		cleanup("DROP USER '" + name + "'@'127.0.0.1'")
		conn, err := admin.Conn(ctx)
		if err != nil {
			t.Fatal("grant connection", err)
		}
		grantDB, err := QuotedGrantDatabase(ctx, conn, database)
		conn.Close()
		if err != nil {
			t.Fatal("literal database grant", err)
		}
		exec(admin, "GRANT "+grants+" ON "+grantDB+".* TO '"+name+"'@'127.0.0.1'")
		c := *cfg
		c.DBName, c.User, c.Passwd = database, name, password
		return open(c)
	}
	sourceName := "offline_source_" + suffix
	sourceAdmin := create(sourceName)
	ordered, err := sortedTables(seed.Tables)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range ordered {
		var cols, marks []string
		for _, col := range table.Columns {
			cols = append(cols, "`"+col.Name+"`")
			marks = append(marks, "?")
		}
		for _, row := range table.Rows {
			var args []any
			for _, col := range table.Columns {
				cell := row[col.Name]
				if cell.Null {
					args = append(args, nil)
				} else {
					args = append(args, cell.Bytes)
				}
			}
			exec(sourceAdmin, "INSERT INTO `"+table.Name+"` ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
		}
	}
	source := principal("osr_"+suffix, sourceName, "SELECT")
	snapshot, err := Capture(ctx, source, Limits{MaxRows: 1000, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatal("source capture", err)
	}
	before, _ := Digest(snapshot)
	// Test-only reviewed pin from the just-created migration schema. Production
	// pins must instead come from the authenticated plan and target observation.
	callerAdapter := policy.Dependencies["northbound_caller_policies"]
	callerAdapter.SchemaSHA256 = SchemaDigest(find(snapshot, "northbound_caller_policies"))
	policy.Dependencies["northbound_caller_policies"] = callerAdapter
	operationAdapter := policy.Dependencies["northbound_operations"]
	operationAdapter.SchemaSHA256 = SchemaDigest(find(snapshot, "northbound_operations"))
	policy.Dependencies["northbound_operations"] = operationAdapter
	key := bytes.Repeat([]byte{73}, 32)
	binding := staging.Binding{BackupID: "offline-business", Attempt: "1", Path: "mysql/domain", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "local-fixture"}
	var cipher bytes.Buffer
	if err := staging.Seal(ctx, &cipher, key, binding, func(w io.Writer) error { return Encode(w, snapshot) }); err != nil {
		t.Fatal(err)
	}
	source.Close() // restore takes only authenticated local capture bytes
	var plain bytes.Buffer
	if err := staging.Open(ctx, bytes.NewReader(cipher.Bytes()), &plain, key, binding, 8<<20); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(&plain, Limits{1000, 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var uuid string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("identity unavailable")
	}
	for index, mode := range []string{"success", "evidence-failure", "cancel", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			short := strings.ReplaceAll(mode, "-", "")
			name := "cm_drill_" + short + "_" + suffix
			targetAdmin := create(name)
			exec(targetAdmin, "INSERT INTO users (id,username,password_hash,role,is_active) VALUES (999,'admin','bootstrap','admin','1')")
			writerName := "ow_" + string(rune('a'+index)) + suffix
			writer := principal(writerName, name, "SELECT, INSERT, DELETE")
			reader := principal("or_"+string(rune('a'+index))+suffix, name, "SELECT")
			c, cancel := context.WithCancel(ctx)
			defer cancel()
			authorized := true
			proof := DrillTarget{Database: name, ServerUUID: uuid, CheckIsolation: func(c context.Context) error {
				if !authorized {
					return ErrIsolation
				}
				return c.Err()
			}}
			var evidence bytes.Buffer
			evidenceReached := false
			plan, err := RestoreDrillWithEvidence(c, writer, proof, decoded, policy, func(c context.Context, p RestorePlan) error {
				evidenceReached = true
				switch mode {
				case "evidence-failure":
					return errors.New("local injected evidence failure")
				case "cancel":
					cancel()
					return c.Err()
				case "revoked":
					authorized = false
				}
				return staging.Seal(c, &evidence, key, binding, func(w io.Writer) error { return Encode(w, p.Data) })
			})
			writer.Close()
			exec(admin, "ALTER USER '"+writerName+"'@'127.0.0.1' ACCOUNT LOCK")
			if !evidenceReached {
				t.Fatal("restore did not reach evidence/commit boundary", err)
			}
			locked := *cfg
			locked.DBName, locked.User, locked.Passwd = name, writerName, suffix+suffix
			probe, probeErr := sql.Open("mysql", locked.FormatDSN())
			if probeErr != nil {
				t.Fatal("writer probe setup")
			}
			probeErr = probe.PingContext(ctx)
			probe.Close()
			if probeErr == nil {
				t.Fatal("revoked writer still authenticates")
			}
			if mode != "success" {
				if err == nil {
					t.Fatal("failure committed")
				}
				var users, skills, callers, operations int
				if reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id=999").Scan(&users) != nil || reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM skills").Scan(&skills) != nil || reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM northbound_caller_policies").Scan(&callers) != nil || reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM northbound_operations").Scan(&operations) != nil || users != 1 || skills != 0 || callers != 0 || operations != 0 {
					t.Fatal("rollback failed")
				}
				return
			}
			if err != nil {
				t.Fatal("restore", err)
			}
			if verifyErr := VerifyDrill(ctx, reader, proof, plan); verifyErr != nil {
				actual, captureErr := Capture(ctx, reader, Limits{1000, 8 << 20})
				if captureErr == nil {
					for _, expected := range plan.Data.Tables {
						got := find(actual, expected.Name)
						if len(got.Rows) != len(expected.Rows) {
							t.Log("row count differs:", expected.Name)
							continue
						}
						for i, row := range expected.Rows {
							for name, value := range row {
								cell := got.Rows[i][name]
								if cell.Null != value.Null || !bytes.Equal(cell.Bytes, value.Bytes) {
									t.Log("cell differs:", expected.Name, name)
								}
							}
						}
					}
				}
				t.Fatal("independent SELECT-only verification failed", verifyErr, captureErr)
			}
			var empty, null, timestamp int
			if reader.QueryRowContext(ctx, "SELECT file_name = '', last_scanned_at IS NULL, created_at IS NOT NULL FROM skill_blobs WHERE id=12").Scan(&empty, &null, &timestamp) != nil || empty != 1 || null != 1 || timestamp != 1 {
				t.Fatal("empty/NULL/default timestamp fidelity lost")
			}
			var status, install, findings, job string
			if reader.QueryRowContext(ctx, "SELECT i.status,s.install_path,r.findings_json,j.status FROM instances i JOIN instance_skills s ON s.instance_id=i.id JOIN skill_scan_results r ON r.id=15 JOIN skill_package_materialize_jobs j ON j.instance_id=i.id WHERE i.id=7").Scan(&status, &install, &findings, &job) != nil || status != "stopped" || install != "skills/demo" || job != "cancelled" || findings != `{"finding":"保留"}` {
				t.Fatal("nonempty relation/content mismatch")
			}
			var enabled, actor int
			var keys, version, created string
			if reader.QueryRowContext(ctx, "SELECT enabled,api_keys_json,api_keys_version,updated_by,created_at FROM northbound_caller_policies WHERE user_id=4").Scan(&enabled, &keys, &version, &actor, &created) != nil || enabled != 0 || keys != "[]" || version != "9223372036854775807" || actor != 1 || created != "2026-10-01 01:02:03.123456" {
				t.Fatal("current caller migration fields lost or credentials retained")
			}
			var nullableActor int
			if reader.QueryRowContext(ctx, "SELECT updated_by IS NULL,api_keys_json,api_keys_version FROM northbound_caller_policies WHERE user_id=1").Scan(&nullableActor, &keys, &version) != nil || nullableActor != 1 || keys != "[]" || version != "0" {
				t.Fatal("nullable actor/current version zero lost")
			}
			var operationCount, unfinished, leased int
			if reader.QueryRowContext(ctx, "SELECT COUNT(*),SUM(status NOT IN ('succeeded','failed','canceled')),SUM(lease_owner IS NOT NULL OR lease_expires_at IS NOT NULL) FROM northbound_operations").Scan(&operationCount, &unfinished, &leased) != nil || operationCount != 6 || unfinished != 0 || leased != 0 {
				t.Fatal("operation history omitted or executable")
			}
			var operationID, finished string
			if reader.QueryRowContext(ctx, "SELECT id,finished_at FROM northbound_operations WHERE operation_id='source-operation-0'").Scan(&operationID, &finished) != nil || operationID != "9007199254740993" || finished != "2026-11-01 08:00:00.123456" {
				t.Fatal("operation precision or frozen time lost")
			}
			var requestPayload string
			if reader.QueryRowContext(ctx, "SELECT request_payload,finished_at FROM northbound_operations WHERE operation_id='source-operation-1'").Scan(&requestPayload, &finished) != nil || finished != "2026-10-01 01:02:04.654321" || strings.Contains(requestPayload, "named-source-secret") || !strings.Contains(requestPayload, `": "`) || !strings.Contains(requestPayload, "保留原始参数") {
				t.Fatal("operation existing completion or MySQL JSON redaction/readback fidelity lost")
			}
			exec(targetAdmin, "UPDATE skill_scan_results SET findings_json='changed' WHERE id=15")
			if VerifyDrill(ctx, reader, proof, plan) == nil {
				t.Fatal("tampering passed")
			}
		})
	}
	// Re-open only the owned source with SELECT after all success/failure modes.
	c := *cfg
	c.DBName = sourceName
	c.User, c.Passwd = "osr_"+suffix, suffix+suffix
	afterSource := open(c)
	after, err := Capture(ctx, afterSource, Limits{1000, 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if digest, _ := Digest(after); digest != before {
		t.Fatal("source changed")
	}
	t.Log("local MySQL only; actual Skills, caller 057/066 and operations 045/066/077 migrations; nonempty Teams/instance fixture; authenticated capture; separate target and SELECT verifier; no publication/readiness claim")
}
