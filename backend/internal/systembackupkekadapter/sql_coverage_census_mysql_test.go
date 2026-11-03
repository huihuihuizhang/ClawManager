//go:build systembackup_mysql

package systembackupkekadapter

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

	appdb "clawreef/internal/db"
	"clawreef/internal/migrationcatalog"
	reg "clawreef/internal/systembackupkekregistry"
	mysql "github.com/go-sql-driver/mysql"
)

func censusOriginalMySQL(t *testing.T, ctx context.Context) (*sql.DB, reg.DatabaseIdentity) {
	t.Helper()
	file := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE")
	pin := os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" {
		t.Skip("requires pinned disposable local MySQL")
	}
	if pin == "" {
		t.Fatal("independent local server UUID pin required")
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 2 || info.Size() > 16384 {
		t.Fatal("private disposable credential file required")
	}
	raw, err := os.ReadFile(file)
	if err != nil || len(raw) > 16384 {
		t.Fatal("private disposable credential file unavailable")
	}
	defer clear(raw)
	var credentials struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&credentials)
	if err != nil || decoder.Decode(new(any)) != io.EOF || credentials.Host != "127.0.0.1" || credentials.Port < 1024 || credentials.Port > 65535 || credentials.Port == 3306 || credentials.User == "" || credentials.Password == "" || credentials.TLSServerName == "" || !filepath.IsAbs(credentials.CAFile) || credentials.ServerUUID != pin || !regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("unexpected disposable SAN/TLS identity")
	}
	caInfo, err := os.Lstat(credentials.CAFile)
	if err != nil || !caInfo.Mode().IsRegular() || caInfo.Size() < 1 || caInfo.Size() > 65536 {
		t.Fatal("private disposable CA unavailable")
	}
	ca, err := os.ReadFile(credentials.CAFile)
	roots := x509.NewCertPool()
	if err != nil || len(ca) > 65536 || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("private disposable CA invalid")
	}
	cfg := mysql.NewConfig()
	cfg.User = credentials.User
	cfg.Passwd = credentials.Password
	credentials.Password = ""
	cfg.Net = "tcp"
	cfg.TLS = &tls.Config{RootCAs: roots, ServerName: credentials.TLSServerName, MinVersion: tls.VersionTLS13}
	cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 90 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	rootConnector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal("local MySQL connection unavailable")
	}
	root := sql.OpenDB(rootConnector)
	t.Cleanup(func() { root.Close() })
	var actual string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actual) != nil || actual != pin {
		t.Fatal("local server UUID mismatch")
	}
	var actualTLS string
	if root.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&actualTLS) != nil || actualTLS != "TLSv1.3" {
		t.Fatal("disposable TLS1.3 identity mismatch before schema creation")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := "ad_a_census_" + hex.EncodeToString(random[:])
	marker := hex.EncodeToString(random[:])
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+name+"`"); err != nil {
		t.Fatal("test database creation failed")
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var gotUUID, gotMarker string
		if root.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&gotUUID) != nil || gotUUID != pin || root.QueryRowContext(clean, "SELECT marker FROM `"+name+"`.ad_a_owner_marker").Scan(&gotMarker) != nil || gotMarker != marker {
			t.Error("cleanup ownership check failed; keeping this test database")
			return
		}
		if _, err := root.ExecContext(clean, "DROP DATABASE `"+name+"`"); err != nil {
			t.Error("owned test database cleanup failed")
		}
	})
	cfg.DBName = name
	schemaConnector, err := mysql.NewConnector(cfg)
	cfg.Passwd = ""
	if err != nil {
		t.Fatal("owned MySQL schema connection failed")
	}
	database := sql.OpenDB(schemaConnector)
	t.Cleanup(func() { database.Close() })
	if _, err = database.ExecContext(ctx, "CREATE TABLE ad_a_owner_marker(marker VARCHAR(64) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(ctx, "INSERT INTO ad_a_owner_marker VALUES (?)", marker); err != nil {
		t.Fatal(err)
	}
	identity := reg.DatabaseIdentity{ServerUUID: pin, Database: name}
	if err = appdb.ApplyPinnedMigrations(ctx, database, appdb.MigrationTarget{ServerUUID: pin, Database: name, CatalogSHA256: migrationcatalog.ReviewedHash}); err != nil {
		t.Fatal("full pinned migration catalog failed", err)
	}
	return database, identity
}

func TestSQLCoverageCensusOriginalSourcesMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	scanner, err := NewSQLCoverageCensus(db, identity, "installation_census")
	if err != nil {
		t.Fatal(err)
	}
	first, err := scanner.Observe(ctx)
	if err != nil {
		t.Fatal("full original source census failed", err)
	}
	facts := first.Facts()
	var ownerTables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('system_backup_installation_owner_heads','system_backup_installation_owner_grants','system_backup_minio_owner_heads','system_backup_minio_owner_grants','system_backup_minio_owner_refs','system_backup_signing_resource_heads','system_backup_signing_resource_grants')`).Scan(&ownerTables); err != nil || ownerTables != 7 {
		t.Fatal("actual migrations134/135/136 authority tables unavailable", err)
	}
	authorityTables := map[string]bool{"system_backup_installation_owner_heads": true, "system_backup_installation_owner_grants": true, "system_backup_minio_owner_heads": true, "system_backup_minio_owner_grants": true, "system_backup_minio_owner_refs": true, "system_backup_signing_resource_heads": true, "system_backup_signing_resource_grants": true}
	for _, table := range facts.Tables {
		if authorityTables[table.Table] {
			t.Fatal("independent authorization rows entered lifecycle payload", table.Table)
		}
	}
	if len(facts.Tables) < 45 {
		t.Fatal("original sources missing from census", len(facts.Tables))
	}
	facts.Tables[0].RowsSHA256 = "changed by caller"
	if first.Facts().Tables[0].RowsSHA256 == facts.Tables[0].RowsSHA256 {
		t.Fatal("source facts alias caller memory")
	}
	second, err := scanner.Observe(ctx)
	if err != nil || !sameSQLCensus(first.Facts(), second.Facts()) {
		t.Fatal("unchanged original SQL source set unstable", err)
	}
	t.Run("empty_original_source_gap_blocks_exact_old_writer", func(t *testing.T) {
		empty := false
		for _, table := range first.Facts().Tables {
			if table.Table == "system_backup_config_versions" {
				empty = table.Rows == 0
			}
		}
		if !empty {
			t.Fatal("original legacy source must actually be empty")
		}
		original, err := scanner.BeginOriginalTransaction(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tx := original.Tx()
		defer tx.Rollback()
		locked, err := scanner.LockOriginalSources(ctx, original, first)
		if err != nil {
			t.Fatal(err)
		}
		var blockerID uint64
		if tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&blockerID) != nil {
			t.Fatal("source lock owner unavailable")
		}
		oldWriter, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		// Release the source owner FIRST, including on Fatal, so rollback never
		// waits for its own blocked operation while retaining the blocker locks.
		defer func() { tx.Rollback(); oldWriter.Rollback() }()
		var writerID uint64
		if oldWriter.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&writerID) != nil {
			t.Fatal("old writer identity unavailable")
		}
		finished := make(chan error, 1)
		go func() {
			_, err := oldWriter.ExecContext(ctx, `INSERT INTO system_backup_config_versions(version,config_json,actor_id) VALUES (1,'{"old_writer":"before_adoption"}',1)`)
			finished <- err
		}()
		waitUntil := time.Now().Add(5 * time.Second)
		waiting := false
		for time.Now().Before(waitUntil) {
			select {
			case err := <-finished:
				t.Fatal("old writer completed before source freeze release", err)
			default:
			}
			var count uint64
			err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
				JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
				JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
				JOIN performance_schema.threads rt ON rt.THREAD_ID=w.REQUESTING_THREAD_ID
				JOIN performance_schema.threads bt ON bt.THREAD_ID=w.BLOCKING_THREAD_ID
				WHERE r.OBJECT_SCHEMA=? AND r.OBJECT_NAME='system_backup_config_versions' AND b.OBJECT_SCHEMA=r.OBJECT_SCHEMA AND b.OBJECT_NAME=r.OBJECT_NAME
				AND rt.PROCESSLIST_ID=? AND bt.PROCESSLIST_ID=? AND r.LOCK_TYPE='RECORD' AND r.LOCK_STATUS='WAITING'
				AND r.LOCK_MODE LIKE '%INSERT_INTENTION%' AND b.LOCK_STATUS='GRANTED' AND b.LOCK_DATA='supremum pseudo-record'`, identity.Database, writerID, blockerID).Scan(&count)
			if err != nil {
				t.Fatal("test-root lock-wait observation unavailable", err)
			}
			if count > 0 {
				waiting = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting {
			t.Fatal("exact old writer was not observed waiting on the empty source supremum range")
		}
		if err = locked.Recheck(ctx, tx); err != nil {
			t.Fatal("empty source changed while old writer waited", err)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal("SAME old insert did not succeed after source owner released", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("old writer remained blocked after source release")
		}
		if err = oldWriter.Rollback(); err != nil {
			t.Fatal(err)
		}
	})
	// This legacy table is intentionally absent from the new KEK index. Its
	// bytes must invalidate the preparation; MAX(id)/new-index empty must fail.
	if _, err = db.ExecContext(ctx, `INSERT INTO system_backup_config_versions(version,config_json,actor_id) VALUES (1,'{"legacy_key":"original-v1"}',1)`); err != nil {
		t.Fatal(err)
	}
	original, err := scanner.BeginOriginalTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := original.Tx()
	if _, err = scanner.LockOriginalSources(ctx, original, first); err == nil {
		tx.Rollback()
		t.Fatal("legacy source inserted after observation was accepted")
	}
	tx.Rollback()
	current, err := scanner.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err = scanner.BeginOriginalTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx = original.Tx()
	defer tx.Rollback()
	locked, err := scanner.LockOriginalSources(ctx, original, current)
	if err != nil {
		t.Fatal("original SQL sources could not be locked", err)
	}
	if err = locked.Recheck(ctx, tx); err != nil {
		t.Fatal("same original transaction recheck failed", err)
	}
	other, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = locked.Recheck(ctx, other); err == nil {
		other.Rollback()
		t.Fatal("new transaction substituted for original source locks")
	}
	other.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_config_versions SET config_json='{"legacy_key":"changed"}' WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if err = locked.Recheck(ctx, tx); err == nil {
		t.Fatal("original owner changed source after freeze without detection")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO system_backup_config_versions(version,config_json,actor_id) VALUES (3,'{}',1)`); err != nil {
		t.Fatal("rollback leaked source locks", err)
	}
	for _, unknown := range []string{"system_backup_unreviewed_source", "system_backup_installation_owner_grants_history", "system_backup_minio_owner_heads_history", "system_backup_minio_owner_grants_history", "system_backup_minio_owner_refs_history", "system_backup_signing_resource_heads_history", "system_backup_signing_resource_grants_history"} {
		if _, err = db.ExecContext(ctx, "CREATE TABLE `"+unknown+"`(id BIGINT PRIMARY KEY)"); err != nil {
			t.Fatal(err)
		}
		if _, err = scanner.Observe(ctx); err == nil {
			t.Fatal("unknown backup source silently omitted", unknown)
		}
		if _, err = db.ExecContext(ctx, "DROP TABLE `"+unknown+"`"); err != nil {
			t.Fatal(err)
		}
	}
	wrong := identity
	wrong.Database = "different_database"
	wrongScanner, _ := NewSQLCoverageCensus(db, wrong, "installation_census")
	if _, err = wrongScanner.Observe(ctx); err == nil {
		t.Fatal("cross-database census admitted")
	}
	// An external RC transaction still reports the default session RR. It is
	// deliberately not a factory-minted original transaction capability.
	rc, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	var reported string
	if rc.QueryRowContext(ctx, "SELECT @@transaction_isolation").Scan(&reported) != nil || reported != "REPEATABLE-READ" {
		rc.Rollback()
		t.Fatal("test session no longer exposes the reported-isolation pitfall")
	}
	if _, err = scanner.LockOriginalSources(ctx, &OriginalSQLCoverageTransaction{tx: rc}, current); err == nil {
		rc.Rollback()
		t.Fatal("external RC transaction with RR session default admitted")
	}
	rc.Rollback()
	// No four-row fabrication: even a complete local SQL census does not
	// implement PreparedCoverage or bypass external catalog/unknown-write EOF.
	if _, ok := any(current).(reg.PreparedCoverage); ok {
		t.Fatal("raw SQL census became complete KEK coverage")
	}
}
