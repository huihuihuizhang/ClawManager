package db

import (
	"clawreef/internal/config"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"clawreef/internal/migrationcoord"
)

func TestMigrationCaptureExclusionRealMySQL(t *testing.T) {
	port, err := strconv.Atoi(os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PORT"))
	if err != nil || port <= 0 {
		t.Skip("requires disposable local MySQL")
	}
	root, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/?parseTime=true", os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), port))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name := fmt.Sprintf("cm_migration_guard_%d", time.Now().UnixNano())
	if _, err = root.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal(err)
	}
	defer root.Exec("DROP DATABASE `" + name + "`")
	db, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/%s?parseTime=true", os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), port, name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	release, err := acquireMigrationLocks(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = (migrationcoord.SQLLocker{DB: db, Timeout: time.Second}).Acquire(short)
	cancel()
	if err == nil {
		t.Fatal("capture admitted while migration owned exclusion")
	}
	if err = release(); err != nil {
		t.Fatal(err)
	}

	capture, err := (migrationcoord.SQLLocker{DB: db, Timeout: time.Second}).Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = acquireMigrationLocks(short, second)
	cancel()
	second.Close()
	if err == nil {
		t.Fatal("migration admitted while capture owned exclusion")
	}
	if err = capture.Release(ctx); err != nil {
		t.Fatal(err)
	}
	// The failed dual acquire must not leak the earlier legacy lock.
	third, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	release, err = acquireMigrationLocks(ctx, third)
	if err != nil {
		t.Fatal("canceled lock leaked", err)
	}
	defer release()
	if err = assertBackupCaptureIdle(ctx, third); err != nil {
		t.Fatal("fresh installation rejected", err)
	}
	if _, err = third.ExecContext(ctx, "CREATE TABLE system_backup_gate(scope VARCHAR(128) PRIMARY KEY,phase VARCHAR(16) NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err = third.ExecContext(ctx, "INSERT INTO system_backup_gate VALUES('source','held')"); err != nil {
		t.Fatal(err)
	}
	if err = assertBackupCaptureIdle(ctx, third); err == nil {
		t.Fatal("active capture did not block migration")
	}
	if _, err = third.ExecContext(ctx, "UPDATE system_backup_gate SET phase='idle'"); err != nil {
		t.Fatal(err)
	}
	if err = assertBackupCaptureIdle(ctx, third); err != nil {
		t.Fatal("released source did not unblock migration", err)
	}
	before := Session
	utc, err := OpenSystemBackupRead(config.DatabaseConfig{Host: "127.0.0.1", Port: port, User: "root", Password: os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), Database: name})
	if err != nil {
		t.Fatal(err)
	}
	defer utc.Close()
	if Session != before {
		t.Fatal("independent UTC pool replaced the business session")
	}
	utcPool := utc.Driver().(*sql.DB)
	// Keep both checked out: this must be configured on every physical
	// connection, not a one-time SET on whichever pooled connection was first.
	for range 2 {
		physical, err := utcPool.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer physical.Close()
		var zone string
		if err = physical.QueryRowContext(ctx, "SELECT @@session.time_zone").Scan(&zone); err != nil || zone != "+00:00" {
			t.Fatal("UTC pool session not configured", zone, err)
		}
	}
	if _, err = OpenSystemBackupRead(config.DatabaseConfig{Database: "cm_restore_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("UTC pool bypassed isolated-restore business startup rejection")
	}
	if _, err = third.ExecContext(ctx, "CREATE TABLE system_backup_installation_state(id BIGINT PRIMARY KEY,origin_installation_id VARCHAR(128))"); err != nil {
		t.Fatal(err)
	}
	if _, err = third.ExecContext(ctx, "INSERT INTO system_backup_installation_state VALUES(7,'original-backup-installation')"); err != nil {
		t.Fatal(err)
	}
	if _, err = Initialize(config.DatabaseConfig{Host: "127.0.0.1", Port: port, User: "root", Password: os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), Database: name}); !errors.Is(err, ErrBackupControlImportRequired) {
		t.Fatal("different backup schema entered migration", err)
	}
	var ledgerCount int
	if err = third.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='schema_migrations'").Scan(&ledgerCount); err != nil || ledgerCount != 0 {
		t.Fatal("guard executed migration DDL", ledgerCount, err)
	}
	var original string
	if err = third.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_installation_state WHERE id=7").Scan(&original); err != nil || original != "original-backup-installation" {
		t.Fatal("guard altered original state", err)
	}

}
