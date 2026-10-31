package systembackupexecution

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	mysql "github.com/go-sql-driver/mysql"
)

func aPublicationStartupSQL(t *testing.T, ctx context.Context, connectionOptions ...func(*mysql.Config)) (*sql.DB, *sql.DB, string, string, string) {
	t.Helper()
	file, pin := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" {
		t.Skip("requires independently pinned disposable local MySQL")
	}
	if pin == "" {
		t.Fatal("independent local UUID required")
	}
	raw, err := os.ReadFile(file)
	var cred struct {
		Host, User, Password string
		Port                 int
	}
	if err != nil || json.Unmarshal(raw, &cred) != nil || cred.Host != "127.0.0.1" {
		t.Fatal("local MySQL credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	cfg.User = cred.User
	cfg.Passwd = cred.Password
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local MySQL open failed")
	}
	t.Cleanup(func() { root.Close() })
	var actual string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actual) != nil || actual != pin {
		t.Fatal("local MySQL UUID mismatch")
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	database, user := "ad_a_publication_"+run, "ad_a_pub_"+run[:16]
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal("owned schema creation failed")
	}
	cfg.DBName = database
	owner, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("owned schema open failed")
	}
	t.Cleanup(func() { owner.Close() })
	if _, err = owner.ExecContext(ctx, "CREATE TABLE ad_a_publication_marker(run_id VARCHAR(64) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, "INSERT INTO ad_a_publication_marker VALUES (?)", run); err != nil {
		t.Fatal(err)
	}
	createdUser := false
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var uuid, marker string
		if root.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != pin || owner.QueryRowContext(clean, "SELECT run_id FROM ad_a_publication_marker").Scan(&marker) != nil || marker != run {
			t.Error("owned schema cleanup pin mismatch; preserving")
			return
		}
		if createdUser {
			if _, e := root.ExecContext(clean, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
				t.Error("owned user cleanup failed")
			}
		}
		if _, e := root.ExecContext(clean, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("owned schema cleanup failed")
		}
	})
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_backups(origin_installation_id VARCHAR(128),public_id VARCHAR(128),request_id VARCHAR(128),status VARCHAR(32),controller_owner VARCHAR(128),row_version BIGINT UNSIGNED,controller_lease_expires_at DATETIME(6),deadline_at DATETIME(6),config_version BIGINT UNSIGNED,config_snapshot_sha256 CHAR(64),task_purpose VARCHAR(32),requested_parts VARCHAR(128),PRIMARY KEY(origin_installation_id,public_id)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type VARCHAR(32),target_public_id VARCHAR(128),phase VARCHAR(32),attempt_no INT UNSIGNED,status VARCHAR(32),PRIMARY KEY(target_type,target_public_id,phase,attempt_no)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(128),operation_type VARCHAR(32),status VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(128) PRIMARY KEY,gate_generation BIGINT UNSIGNED,collectors_stopped_at DATETIME(6),source_resumed_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(128),task_public_id VARCHAR(128),attempt_no INT UNSIGNED,phase VARCHAR(32),record_kind VARCHAR(32),payload_sha256 CHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(32),storage_state VARCHAR(32),inline_payload VARBINARY(8192),content_checksum CHAR(64),content_size_bytes BIGINT UNSIGNED,media_type VARCHAR(32),encryption VARCHAR(32),redaction_classification VARCHAR(32),observed_health VARCHAR(32),expires_at DATETIME(6),CHECK(content_checksum=SHA2(inline_payload,256)),CHECK(content_size_bytes=OCTET_LENGTH(inline_payload))) ENGINE=InnoDB`,
	} {
		if _, err = owner.ExecContext(ctx, ddl); err != nil {
			t.Fatal("publication focused DDL failed", err)
		}
	}
	var secret [24]byte
	rand.Read(secret[:])
	password := hex.EncodeToString(secret[:])
	clear(secret[:])
	if _, err = root.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'"); err != nil {
		t.Fatal("owned SQL user creation failed")
	}
	createdUser = true
	for _, table := range []string{"backups", "attempts", "operations", "runtime_captures", "execution_records", "evidence"} {
		verbs := "SELECT"
		if table == "evidence" {
			verbs = "SELECT,INSERT"
		}
		if _, err = root.ExecContext(ctx, "GRANT "+verbs+" ON `"+database+"`.`system_backup_v2_"+table+"` TO '"+user+"'@'127.0.0.1'"); err != nil {
			t.Fatal("owned SQL scope grant failed")
		}
	}
	cfg.User = user
	cfg.Passwd = password
	for _, capture := range connectionOptions {
		capture(cfg.Clone())
	}
	password = ""
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("scoped controller connection failed")
	}
	t.Cleanup(func() { db.Close() })
	var account string
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil {
		t.Fatal("scoped SQL identity unavailable")
	}
	return db, owner, account, pin, database
}

// Full original deployment files and the SAME startup/attach/service entry,
// actual SQL and TLS signatures. Claim is seeded, never called actual Acquire.
func TestAPublicationSignerActualServiceStartupToSQLAndTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, owner, account, uuid, database := aPublicationStartupSQL(t, ctx)
	x := newPublicationStartupFixture(t, account, uuid, database)
	if err := x.service.bindDeploymentStartupInputs(x.inputs); err != nil {
		t.Fatal("actual startup file stage", err)
	}
	if err := x.service.attachPublicationSigners(ctx, db, x.client, x.inputs.ControllerPodName); err != nil {
		t.Fatal("actual startup attach", err)
	}
	backup := "sbk_11111111-2222-4333-8444-555555555555"
	claim := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: backup}, Owner: x.service.PublisherOwner, RowVersion: 11}
	if claim.Owner == x.service.Config.ControllerOwner {
		t.Fatal("publisher owner confused with capture config owner")
	}
	var now time.Time
	if owner.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("SQL clock unavailable")
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := owner.ExecContext(ctx, query, args...); err != nil {
			t.Fatal("original SQL fixture write failed", err)
		}
	}
	exec(`INSERT INTO system_backup_v2_backups VALUES (?,?,?,'validating',?,11,?,?,1,?,'acceptance',?)`, x.grant.InstallationID, backup, "original-publication-request", claim.Owner, now.Add(3*time.Minute), now.Add(4*time.Minute), x.grant.ConfigSHA256, "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle")
	exec(`INSERT INTO system_backup_v2_attempts VALUES ('backup',?,'capture',1,'sealed')`, backup)
	exec(`INSERT INTO system_backup_v2_runtime_captures VALUES (?,17,?,?)`, backup, now.Add(-time.Second), now)
	exec(`INSERT INTO system_backup_v2_execution_records VALUES (?,?,1,'capture','capture_result',?)`, x.grant.InstallationID, backup, strings.Repeat("d", 64))
	q, err := x.service.PublicationSignersForTask(ctx, claim)
	if err != nil {
		t.Fatal("actual service current ClaimToken entry", err)
	}
	defer q.Close()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "public-c-crypto-v1", "signature-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Payload string `json:"payload_json"`
			Trust   struct{ Purpose string }
		}
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Vectors) != 4 {
		t.Fatal("public C vectors unavailable")
	}
	for _, v := range vectors.Vectors[:3] {
		purpose := v.Trust.Purpose
		key, err := q.PublicationSigningKey(ctx, purpose)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if json.Unmarshal([]byte(v.Payload), &payload) != nil {
			t.Fatal("C payload unavailable")
		}
		payload["backup_public_id"] = backup
		payload["attempt_no"] = 1
		payload["signing_key"] = key
		if purpose != "acceptance_record" {
			payload["origin_installation_id"] = x.grant.InstallationID
		}
		field := map[string]string{"capture_certificate": "issued_at", "acceptance_record": "decision_at", "catalog_record": "recorded_at"}[purpose]
		payload[field] = time.Now().UTC().Format(time.RFC3339Nano)
		body, _ := json.Marshal(payload)
		prepared, err := q.PreparePublicationRecord(ctx, purpose, body)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = prepared.Stage(ctx, tx); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		record, expected, err := prepared.SignCommitted(ctx)
		if err != nil {
			t.Fatal("service produced signer could not sign committed original input", err)
		}
		history, err := x.service.PublicationSigningHistory(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := history.VerifyPublicationRecord(record, s.ArtifactSigningTask{BackupPublicID: backup, AttemptNo: 1}, purpose); err != nil || got != expected {
			t.Fatal("independent service readback verification", err)
		}
	}
	if x.logins.Load() != 3 || x.signs.Load() != 3 {
		t.Fatal("actual service did not use three separate JWT/signing purposes")
	}
	exec(`UPDATE system_backup_v2_backups SET row_version=12 WHERE public_id=?`, backup)
	if _, err = x.service.PublicationSignersForTask(ctx, claim); err == nil || x.logins.Load() != 3 {
		t.Fatal("service adopted a new claim version")
	}
	if _, err = q.PublicationSigningKey(ctx, "catalog_record"); err == nil {
		t.Fatal("existing task signer survived claim change")
	}
	x.service.ForwardEnabled = false
	if _, err = x.service.PublicationSignersForTask(ctx, claim); err == nil {
		t.Fatal("disabled service authorized publication")
	}
}
