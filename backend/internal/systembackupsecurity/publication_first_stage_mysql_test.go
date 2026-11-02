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

	"github.com/go-sql-driver/mysql"
)

// The root owner runs this only on its disposable SAN/TLS1.3 server. This
// test never connects to a non-loopback/default-port endpoint, changes TLS
// policy, creates users, or discovers schemas to delete. Cleanup uses only
// this invocation's directly held random name plus independent UUID/marker.
func firstStageNativeDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	file := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if pin == "" || file == "" {
		t.Skip("requires root-owned disposable TLS credentials and independent UUID pin")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(file)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		t.Fatal("disposable credential file unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&credential)
	endErr := decoder.Decode(new(any))
	clear(raw)
	if decodeErr != nil || endErr != io.EOF || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) || credential.ServerUUID != pin || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("disposable endpoint/UUID/SAN pins invalid")
	}
	ca, err := os.ReadFile(credential.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable TLS CA unavailable")
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal("fixture random identity unavailable")
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "a-publication-first-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("disposable TLS registration failed")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credential.User, credential.Password
	cfg.Net, cfg.Addr, cfg.TLSConfig = "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port)), tlsName
	cfg.ParseTime, cfg.Loc, cfg.MultiStatements = true, time.UTC, false
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	credential.Password = ""
	if err != nil {
		t.Fatal("disposable SQL open failed")
	}
	t.Cleanup(func() { root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var uuid, version string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != pin || root.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&version) != nil || version != "TLSv1.3" {
		t.Fatal("disposable UUID/TLS1.3 check failed before schema creation")
	}
	database := "ad_a_pub_first_" + run
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal("owned fixture schema creation failed")
	}
	// Register cleanup immediately. No broad scan or prefix grants ownership.
	markerReady := false
	var db *sql.DB
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		var actual, marker string
		if root.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&actual) != nil || actual != pin {
			t.Error("fixture UUID changed; schema preserved")
			return
		}
		if markerReady && (db == nil || db.QueryRowContext(cleanup, "SELECT run_id FROM _a_publication_first_owner").Scan(&marker) != nil || marker != run) {
			t.Error("fixture owner marker changed; schema preserved")
			return
		}
		if db != nil {
			db.Close()
		}
		if _, err := root.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); err != nil {
			t.Error("exact owned fixture schema cleanup failed")
		}
	})
	cfg.DBName = database
	db, err = sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd = ""
	if err != nil {
		t.Fatal("owned fixture SQL open failed")
	}
	db.SetMaxOpenConns(4)
	if _, err = db.ExecContext(ctx, "CREATE TABLE _a_publication_first_owner(run_id VARCHAR(64) PRIMARY KEY)"); err != nil {
		t.Fatal("fixture marker creation failed")
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO _a_publication_first_owner VALUES (?)", run); err != nil {
		t.Fatal("fixture marker write failed")
	}
	markerReady = true
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_backups(origin_installation_id VARCHAR(128),public_id VARCHAR(128),request_id VARCHAR(128),status VARCHAR(32),controller_owner VARCHAR(128),row_version BIGINT UNSIGNED,controller_lease_expires_at DATETIME(6),deadline_at DATETIME(6),config_version BIGINT UNSIGNED,config_snapshot_sha256 CHAR(64),task_purpose VARCHAR(32),requested_parts VARCHAR(128),PRIMARY KEY(origin_installation_id,public_id)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type VARCHAR(32),target_public_id VARCHAR(128),phase VARCHAR(32),attempt_no BIGINT UNSIGNED,status VARCHAR(32),PRIMARY KEY(target_type,target_public_id,phase,attempt_no)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(128),operation_type VARCHAR(32),status VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(128) PRIMARY KEY,gate_generation BIGINT UNSIGNED,collectors_stopped_at DATETIME(6),source_resumed_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(128),task_public_id VARCHAR(128),attempt_no BIGINT UNSIGNED,phase VARCHAR(32),record_kind VARCHAR(32),payload_sha256 CHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(32),storage_state VARCHAR(32),inline_payload VARBINARY(8192),content_checksum CHAR(64),content_size_bytes BIGINT UNSIGNED,media_type VARCHAR(32),encryption VARCHAR(32),redaction_classification VARCHAR(32),observed_health VARCHAR(32),expires_at DATETIME(6),CHECK(content_checksum=SHA2(inline_payload,256)),CHECK(content_size_bytes=OCTET_LENGTH(inline_payload))) ENGINE=InnoDB`,
	} {
		if _, err = db.ExecContext(ctx, ddl); err != nil {
			t.Fatal("owned fixture DDL failed")
		}
	}
	return db, database
}

func TestPublicationStageFirstTLSMySQL(t *testing.T) {
	db, database := firstStageNativeDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newInstallationSigningFixture(t)
	var account string
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER(),UTC_TIMESTAMP(6)").Scan(&account, &now) != nil {
		t.Fatal("fixture SQL identity unavailable")
	}
	claim := SQLSigningClaim{ControllerOwner: "original-first-stage-owner", RowVersion: 11}
	grant := SQLSigningOwnerGrant{ServerUUID: os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID"), Database: database, DatabaseAccount: account, ControllerOwner: claim.ControllerOwner, ConfigVersion: 3, ConfigSHA256: strings.Repeat("c", 64), Workload: f.task.Workload}
	for n := range f.record.Permissions {
		copy := grant
		f.record.Permissions[n].SQLOwner = &copy
	}
	f.writeRecord(true)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO system_backup_v2_backups VALUES (?,?,?,'publishing',?,11,?,?,3,?,'acceptance',?)`, []any{f.pin.InstallationID, f.task.BackupPublicID, f.task.OperationID, claim.ControllerOwner, now.Add(5 * time.Minute), now.Add(10 * time.Minute), grant.ConfigSHA256, "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle"}},
		{`INSERT INTO system_backup_v2_attempts VALUES ('backup',?,'capture',?,'sealed')`, []any{f.task.BackupPublicID, f.task.AttemptNo}},
		{`INSERT INTO system_backup_v2_runtime_captures VALUES (?,17,?,?)`, []any{f.task.BackupPublicID, now.Add(-time.Second), now}},
		{`INSERT INTO system_backup_v2_execution_records VALUES (?,?,?,'capture','capture_result',?)`, []any{f.pin.InstallationID, f.task.BackupPublicID, f.task.AttemptNo, strings.Repeat("d", 64)}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal("owned fixture source setup failed")
		}
	}
	p := firstStagePrepared(t, f, db, claim, "acceptance_record")
	a := p.task.signers.owners["acceptance_record"]
	clearEvidence := func(t *testing.T) {
		t.Helper()
		if _, err := db.ExecContext(ctx, "DELETE FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=?", f.task.BackupPublicID); err != nil {
			t.Fatal("owned fixture history reset failed")
		}
	}
	for _, test := range []struct {
		name, purpose                                        string
		workload, chunked, orphan, unhealthy, expired, allow bool
	}{
		{name: "same-purpose", purpose: "acceptance_record"},
		{name: "cross-workload", purpose: "acceptance_record", workload: true},
		{name: "unhealthy", purpose: "acceptance_record", workload: true, unhealthy: true},
		{name: "expired", purpose: "acceptance_record", workload: true, expired: true},
		{name: "rootless-chunks", purpose: "acceptance_record", workload: true, chunked: true, orphan: true},
		{name: "normal-capture-chunks", purpose: "capture_certificate", chunked: true, allow: true},
		{name: "other-purpose-orphan", purpose: "capture_certificate", chunked: true, orphan: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearEvidence(t)
			id, rows := firstStageHistoryRows(t, a, test.purpose, test.workload, false, test.chunked)
			if test.orphan {
				delete(rows, id)
			}
			if test.unhealthy {
				rows[id][7] = "unknown"
			}
			if test.expired {
				rows[id][9] = now.Add(-time.Minute)
			}
			for key, row := range rows {
				if _, err := db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES (?,'backup',?,'diagnostic','inline',?,?,?,'application/json','none','internal',?,?)`, key, row[4], row[0], row[1], row[2], row[7], row[9]); err != nil {
					t.Fatal("fixture original history insertion failed")
				}
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = p.StageFirst(ctx, tx)
			if test.allow && err != nil || !test.allow && !errors.Is(err, ErrPublicationFirstStage) {
				t.Fatalf("StageFirst allow=%v error=%v", test.allow, err)
			}
		})
	}
	t.Run("rollback-legacy-and-exclusive-task-lock", func(t *testing.T) {
		clearEvidence(t)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.StageFirst(ctx, tx); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = p.StageFirst(ctx, tx); err != nil {
			t.Fatal("rollback consumed first stage", err)
		}
		waiting, done := make(chan struct{}), make(chan error, 1)
		go func() {
			other, err := db.BeginTx(ctx, nil)
			if err != nil {
				close(waiting)
				done <- err
				return
			}
			defer other.Rollback()
			close(waiting)
			done <- p.StageFirst(ctx, other)
		}()
		<-waiting
		select {
		case err := <-done:
			t.Fatal("second first-stage escaped original task lock", err)
		case <-time.After(50 * time.Millisecond):
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrPublicationFirstStage) {
				t.Fatal("committed first input re-admitted", err)
			}
		case <-ctx.Done():
			t.Fatal("second first-stage did not finish after original commit")
		}
		stagePreparedPublication(t, db, p, true) // old Stage remains idempotent
	})
	t.Run("catalog-first-keeps-existing-acceptance", func(t *testing.T) {
		binding := p.task.signers.owners["catalog_record"].binding
		catalog, err := p.task.PreparePublicationRecord(ctx, "catalog_record", publicationFixturePayload(t, f, binding))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = catalog.StageFirst(ctx, tx); err != nil {
			t.Fatal("other purpose blocked catalog", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = catalog.StageFirst(ctx, tx); !errors.Is(err, ErrPublicationFirstStage) {
			t.Fatal("catalog input first twice", err)
		}
	})
	t.Run("stale-claim-and-readonly", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE system_backup_v2_backups SET row_version=12 WHERE origin_installation_id=? AND public_id=?`, f.pin.InstallationID, f.task.BackupPublicID); err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.StageFirst(ctx, tx); err == nil {
			tx.Rollback()
			t.Fatal("stale claim admitted")
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE system_backup_v2_backups SET row_version=11 WHERE origin_installation_id=? AND public_id=?`, f.pin.InstallationID, f.task.BackupPublicID); err != nil {
			t.Fatal(err)
		}
		tx, err = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = p.StageFirst(ctx, tx); err == nil {
			t.Fatal("readonly transaction admitted first stage")
		}
	})
	if f.login != 0 || f.signed != 0 {
		t.Fatal("StageFirst contacted provider")
	}
}
