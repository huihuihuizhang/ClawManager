//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// This gate requires an independently UUID-pinned LOCAL disposable MySQL.
// It creates its own randomly named database and restricted SQL workload and
// proves only the production signing SQL/transactions/grants, not all app DDL.
func TestSQLSigningOwnerMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	path, expectedUUID := os.Getenv("A_SIGNING_MYSQL_DSN_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	credentialsPath := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE")
	if (path == "" && credentialsPath == "") || expectedUUID == "" {
		t.Fatal("local signing MySQL DSN file and independent server UUID pin required")
	}
	if path == "" {
		path = credentialsPath
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		t.Fatal("local signing MySQL DSN file unavailable")
	}
	var cfg *mysql.Config
	if credentialsPath != "" {
		var credentials struct {
			Host, User, Password string
			Port                 int
		}
		if json.Unmarshal(raw, &credentials) != nil {
			clear(raw)
			t.Fatal("local MySQL credentials encoding invalid")
		}
		cfg = mysql.NewConfig()
		cfg.Net = "tcp"
		cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
		cfg.User = credentials.User
		cfg.Passwd = credentials.Password
	} else {
		cfg, err = mysql.ParseDSN(strings.TrimSpace(string(raw)))
	}
	clear(raw)
	if err != nil || cfg.Net != "tcp" {
		t.Fatal("local signing MySQL TCP configuration invalid")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("signing MySQL gate permits only the pinned loopback server")
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	cfg.MultiStatements = false
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local MySQL open failed")
	}
	t.Cleanup(func() { root.Close() })
	var server string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != expectedUUID {
		t.Fatal("local signing MySQL server pin mismatch")
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(random[:])
	database, user := "ad_a_signing_"+run, "ad_a_sign_"+run[:16]
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal("local signing database creation failed")
	}
	ownerCfg := cfg.Clone()
	ownerCfg.DBName = database
	owner, err := sql.Open("mysql", ownerCfg.FormatDSN())
	if err != nil {
		t.Fatal("local owner DB open failed")
	}
	t.Cleanup(func() { owner.Close() })
	if _, err = owner.ExecContext(ctx, "CREATE TABLE _a_signing_owner_marker(run_id VARCHAR(64) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, "INSERT INTO _a_signing_owner_marker(run_id) VALUES (?)", run); err != nil {
		t.Fatal(err)
	}
	createdUser := false
	t.Cleanup(func() {
		cleanup, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		var actual, marker string
		if root.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&actual) != nil || actual != expectedUUID || owner.QueryRowContext(cleanup, "SELECT run_id FROM _a_signing_owner_marker").Scan(&marker) != nil || marker != run {
			t.Error("local signing fixture cleanup pin mismatch; preserving database")
			return
		}
		if createdUser {
			if _, e := root.ExecContext(cleanup, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
				t.Error("local fixture user cleanup failed")
			}
		}
		if _, e := root.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("local fixture database cleanup failed")
		}
	})
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_backups(origin_installation_id VARCHAR(128) NOT NULL,public_id VARCHAR(128) NOT NULL,request_id VARCHAR(128) NOT NULL,status VARCHAR(32) NOT NULL,controller_owner VARCHAR(128) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,controller_lease_expires_at DATETIME(6) NOT NULL,deadline_at DATETIME(6) NOT NULL,config_version BIGINT UNSIGNED NOT NULL,config_snapshot_sha256 CHAR(64) NOT NULL,task_purpose VARCHAR(32) NOT NULL,requested_parts VARCHAR(128) NOT NULL,PRIMARY KEY(origin_installation_id,public_id)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type VARCHAR(32),target_public_id VARCHAR(128),phase VARCHAR(32),attempt_no INT UNSIGNED,status VARCHAR(32),PRIMARY KEY(target_type,target_public_id,phase,attempt_no)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(128),operation_type VARCHAR(32),status VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(128) PRIMARY KEY,gate_generation BIGINT UNSIGNED NOT NULL,collectors_stopped_at DATETIME(6),source_resumed_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(128),task_public_id VARCHAR(128),attempt_no INT UNSIGNED,phase VARCHAR(32),record_kind VARCHAR(32),payload_sha256 CHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(32),storage_state VARCHAR(32),inline_payload VARBINARY(8192),content_checksum CHAR(64),content_size_bytes BIGINT UNSIGNED,media_type VARCHAR(32),encryption VARCHAR(32),redaction_classification VARCHAR(32),observed_health VARCHAR(32),expires_at DATETIME(6),CHECK(content_checksum=SHA2(inline_payload,256)),CHECK(content_size_bytes=OCTET_LENGTH(inline_payload))) ENGINE=InnoDB`,
	} {
		if _, err = owner.ExecContext(ctx, ddl); err != nil {
			t.Fatal("local signing fixture DDL failed", err)
		}
	}
	var secret [24]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret[:])
	clear(secret[:])
	if _, err = root.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'"); err != nil {
		t.Fatal("local restricted signing user creation failed")
	}
	createdUser = true
	for _, table := range []string{"backups", "attempts", "operations", "runtime_captures", "execution_records", "evidence"} {
		if _, err = root.ExecContext(ctx, "GRANT SELECT ON `"+database+"`.`system_backup_v2_"+table+"` TO '"+user+"'@'127.0.0.1'"); err != nil {
			t.Fatal("local SELECT grant failed")
		}
	}
	if _, err = root.ExecContext(ctx, "GRANT INSERT ON `"+database+"`.`system_backup_v2_evidence` TO '"+user+"'@'127.0.0.1'"); err != nil {
		t.Fatal("local evidence INSERT grant failed")
	}
	jobCfg := ownerCfg.Clone()
	jobCfg.User = user
	jobCfg.Passwd = password
	password = ""
	job, err := sql.Open("mysql", jobCfg.FormatDSN())
	if err != nil {
		t.Fatal("restricted signing DB open failed")
	}
	defer job.Close()
	var account string
	if job.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil {
		t.Fatal("restricted signing workload login failed")
	}
	f := newInstallationSigningFixture(t)
	grant := SQLSigningOwnerGrant{ServerUUID: expectedUUID, Database: database, DatabaseAccount: account, ControllerOwner: "original-mysql-controller", ConfigVersion: 3, ConfigSHA256: strings.Repeat("c", 64), Workload: f.task.Workload}
	for i := range f.record.Permissions {
		copy := grant
		f.record.Permissions[i].SQLOwner = &copy
	}
	f.writeRecord(true)
	s, err := NewSQLInstallationArtifactSigners(ctx, job, f.reader, f.pin, f.mounts, f.task, SQLSigningClaim{ControllerOwner: grant.ControllerOwner, RowVersion: 11})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var now time.Time
	if err = owner.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_backups VALUES (?,?,?,'validating',?,11,?,?,3,?,'acceptance',?)`, f.pin.InstallationID, f.task.BackupPublicID, f.task.OperationID, grant.ControllerOwner, now.Add(time.Minute), now.Add(2*time.Minute), grant.ConfigSHA256, "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_attempts VALUES ('backup',?,'capture',?,'sealed')`, f.task.BackupPublicID, f.task.AttemptNo); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_captures VALUES (?,17,?,?)`, f.task.BackupPublicID, now.Add(-time.Second), now); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_records VALUES (?,?,?,'capture','capture_result',?)`, f.pin.InstallationID, f.task.BackupPublicID, f.task.AttemptNo, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	var prepared []*PreparedPublicationRecord
	var signedRecords [][]byte
	for _, mount := range f.mounts {
		payload := publicationFixturePayload(t, f, mount.Binding)
		p, e := s.PreparePublicationRecord(ctx, mount.Binding.Purpose, payload)
		if e != nil {
			t.Fatal(e)
		}
		clear(payload)
		stagePreparedPublication(t, job, p, false)
		if value, _, e := p.SignCommitted(ctx); e == nil || len(value) != 0 {
			t.Fatal("rolled-back MySQL evidence authorized signing")
		}
		if mount.Binding.Purpose == "capture_certificate" {
			var count int
			if owner.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence`).Scan(&count) != nil || count != 0 {
				t.Fatal("rollback retained signing chunks")
			}
		}
		stagePreparedPublication(t, job, p, true)
		stagePreparedPublication(t, job, p, true)
		if mount.Binding.Purpose == "capture_certificate" {
			a := s.owners[mount.Binding.Purpose]
			id := signingInputEvidenceID(a.task, a.binding.InstallationID, a.binding.Purpose)
			var rootBytes []byte
			if owner.QueryRowContext(ctx, `SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&rootBytes) != nil {
				t.Fatal("chunk index unavailable")
			}
			var index frozenSigningChunkIndex
			if !decodeFrozenSigningJSON(rootBytes, &index) || index.Count < 2 || index.Size <= 8192 {
				t.Fatal("large certificate was not chunked")
			}
			var count, maxSize, total int
			prefix := id + "_p"
			if owner.QueryRowContext(ctx, `SELECT COUNT(*),MAX(OCTET_LENGTH(inline_payload)),SUM(OCTET_LENGTH(inline_payload)) FROM system_backup_v2_evidence WHERE public_id=? OR LEFT(public_id,?)=?`, id, len(prefix), prefix).Scan(&count, &maxSize, &total) != nil || count != index.Count+1 || maxSize > 8192 || total <= 8192 {
				t.Fatal("actual SQL chunk boundary not exercised")
			}
			chunkID := signingChunkID(id, 0)
			var original []byte
			var until time.Time
			if owner.QueryRowContext(ctx, `SELECT inline_payload,expires_at FROM system_backup_v2_evidence WHERE public_id=?`, chunkID).Scan(&original, &until) != nil {
				t.Fatal("first chunk unavailable")
			}
			var chunk frozenSigningChunk
			if !decodeFrozenSigningJSON(original, &chunk) {
				t.Fatal("invalid fixture chunk")
			}
			chunk.Index++
			bad, _ := json.Marshal(chunk)
			digest := sha256.Sum256(bad)
			if _, e = owner.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=? WHERE public_id=?`, bad, hex.EncodeToString(digest[:]), len(bad), chunkID); e != nil {
				t.Fatal(e)
			}
			before := f.login
			if _, _, e = p.SignCommitted(ctx); e == nil || f.login != before {
				t.Fatal("wrong chunk ordinal reached provider")
			}
			if _, e = owner.ExecContext(ctx, `DELETE FROM system_backup_v2_evidence WHERE public_id=?`, chunkID); e != nil {
				t.Fatal(e)
			}
			if _, _, e = p.SignCommitted(ctx); e == nil || f.login != before {
				t.Fatal("missing chunk reached provider")
			}
			tx, e := owner.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = a.insertFrozenEvidence(ctx, tx, chunkID, original, until); e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			t.Logf("full local capture: payload=%d input=%d frozen=%d chunks=%d max-inline=%d", len(p.payload), len(p.input), index.Size, index.Count, maxSize)
		}
		value, checksum, e := p.SignCommitted(ctx)
		if e != nil {
			t.Fatal("real restricted MySQL-to-TLS signing failed", mount.Binding.Purpose, e)
		}
		history, e := s.History(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if observed, verifyErr := history.VerifyPublicationRecord(value, f.task, mount.Binding.Purpose); verifyErr != nil || observed != checksum {
			t.Fatal("real SQL signature readback failed", e)
		}
		prepared = append(prepared, p)
		signedRecords = append(signedRecords, value)
	}
	if _, err = job.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='failed' WHERE public_id=?`, f.task.BackupPublicID); err == nil {
		t.Fatal("signing workload can UPDATE source task")
	}
	if _, err = job.ExecContext(ctx, `DELETE FROM system_backup_v2_evidence`); err == nil {
		t.Fatal("signing workload can DELETE retained input")
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES ('sev_local_bad_checksum','backup',?,'diagnostic','inline',?,? ,2,'application/json','none','internal','healthy',?)`, f.task.BackupPublicID, []byte("{}"), strings.Repeat("a", 64), now.Add(time.Minute)); err == nil {
		t.Fatal("MySQL CHECK admitted corrupt frozen input checksum")
	}
	if f.login != 3 || f.signed != 3 || f.authorized != 0 {
		t.Fatal("real SQL gate did not use three automatic owners")
	}
	if _, err = owner.ExecContext(ctx, `UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?`, f.task.BackupPublicID); err != nil {
		t.Fatal(err)
	}
	signer, _ := s.Signer("capture_certificate")
	input := signingSQLInput(t, f.task, f.mounts[0].Binding)
	if _, err = signer.Sign(ctx, input); err == nil || f.login != 3 {
		t.Fatal("old MySQL claim reached provider after takeover")
	}
	// Model the original runtime release and subsequent publisher acquisition.
	// This gate proves the SQL signing adapter, not the controller acquire API.
	if _, err = owner.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_owner='',status='validating' WHERE public_id=?`, f.task.BackupPublicID); err != nil {
		t.Fatal(err)
	}
	for _, p := range prepared {
		if _, _, e := p.SignCommitted(ctx); e == nil || f.login != 3 {
			t.Fatal("released capture claim authorized publication")
		}
	}
	if _, err = owner.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_owner=?,row_version=13,status='publishing' WHERE public_id=?`, grant.ControllerOwner, f.task.BackupPublicID); err != nil {
		t.Fatal(err)
	}
	publisher, e := NewSQLInstallationArtifactSigners(ctx, job, f.reader, f.pin, f.mounts, f.task, SQLSigningClaim{ControllerOwner: grant.ControllerOwner, RowVersion: 13})
	if e != nil {
		t.Fatal(e)
	}
	defer publisher.Close()
	for i, p := range prepared {
		current, e := publisher.PreparePublicationRecord(ctx, p.binding.Purpose, p.payload)
		if e != nil {
			t.Fatal(e)
		}
		stagePreparedPublication(t, job, current, true)
		raw, _, e := current.SignCommitted(ctx)
		if e != nil || string(raw) != string(signedRecords[i]) {
			t.Fatal("new publisher claim changed frozen artifact or could not sign", e)
		}
		if _, _, e = p.SignCommitted(ctx); e == nil {
			t.Fatal("old capture claim reused after publisher acquisition")
		}
	}
	if f.login != 6 || f.signed != 6 {
		t.Fatal("publisher did not use three separate purpose signers")
	}
}
