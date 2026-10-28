package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func backupSourceCopy(t *testing.T) *sql.DB {
	t.Helper()
	port, _ := strconv.Atoi(os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PORT"))
	directory := os.Getenv("CLAWMANAGER_BACKUP_SOURCE_MIGRATIONS")
	if port <= 0 || directory == "" {
		t.Skip("requires owned disposable MySQL and exact backup-source migrations")
	}
	root, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/?parseTime=true", os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	name := fmt.Sprintf("cm_import_%032x", time.Now().UnixNano())
	if _, err = root.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := root.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error(err)
		}
	})
	pool, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/%s?parseTime=true", os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), port, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	conn, err := pool.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = ensureSchemaMigrationsTable(conn); err != nil {
		t.Fatal(err)
	}
	var mapping backupImportMap
	if err = json.Unmarshal(backupImportMapJSON, &mapping); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if mapping.Migrations[file.Name()] != hashImportFile(raw) {
			t.Fatal("source fixture differs from reviewed SQL", file.Name())
		}
		for i, statement := range splitSQLStatements(string(raw)) {
			if _, err = conn.ExecContext(context.Background(), statement); err != nil {
				t.Fatalf("source migration %s statement%d: %v", file.Name(), i+1, err)
			}
		}
		if _, err = conn.ExecContext(context.Background(), "INSERT INTO schema_migrations(filename) VALUES(?)", file.Name()); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != len(mapping.Migrations) {
		t.Fatal("incomplete source migration fixture", count)
	}
	return pool
}

func TestGenerateReviewedBackupSourceSchema(t *testing.T) {
	if os.Getenv("UPDATE_BACKUP_IMPORT_PROFILE") != "1" {
		t.Skip("explicit profile generation only")
	}
	pool := backupSourceCopy(t)
	schema, err := readImportSchema(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("backup_source_schema.json", append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("reviewed source schema", len(schema.Tables), importDigest(schema))
}

func TestBackupCopyImportPreservesRowsLedgerAndReentry(t *testing.T) {
	pool := backupSourceCopy(t)
	ctx := context.Background()
	for _, statement := range []string{
		`INSERT INTO users(id,username,email,password_hash,role) VALUES(90001,'import-fixture','import@fixture.invalid','not-a-credential','user')`,
		`INSERT INTO system_backup_events(id,origin_installation_id,target_type,target_public_id,event_type,level,message) VALUES(70001,'installation_import_fixture','system','installation_import_fixture','diagnostic.d.import','info','原始历史保留')`,
	} {
		if _, err := pool.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	interrupted := errors.New("injected post-rename interruption")
	if _, err := importBackupCopy(ctx, pool, func() error { return interrupted }); !errors.Is(err, interrupted) {
		t.Fatal("rename failure not retained", err)
	}
	var phase string
	if err := pool.QueryRow("SELECT state FROM system_backup_v2_import_journal WHERE singleton_id=1").Scan(&phase); err != nil || phase != "renamed" {
		t.Fatal("durable resume phase missing", phase, err)
	}
	report, err := ImportBackupCopy(ctx, pool)
	if err != nil || report.State != "verified" {
		t.Fatal(report, err)
	}
	again, err := ImportBackupCopy(ctx, pool)
	if err != nil || again != report {
		t.Fatal("reentry changed import", again, report, err)
	}
	var id int
	var message string
	if err = pool.QueryRow("SELECT id FROM system_backup_v2_events WHERE origin_installation_id='installation_import_fixture'").Scan(&id); err != nil || id != 70001 {
		t.Fatal("control identity lost", id, err)
	}
	if err = pool.QueryRow("SELECT message FROM system_backup_v2_events WHERE origin_installation_id='installation_import_fixture'").Scan(&message); err != nil || message != "原始历史保留" {
		t.Fatal("history lost", err)
	}
	var legacy int
	if err = pool.QueryRow("SELECT COUNT(*) FROM system_backup_installation_state").Scan(&legacy); err != nil || legacy != 0 {
		t.Fatal("source record became legacy work", legacy, err)
	}
}

func TestBackupCopyImportRejectsUnknownSchemaBeforeDDL(t *testing.T) {
	pool := backupSourceCopy(t)
	ctx := context.Background()
	if _, err := pool.Exec("ALTER TABLE users ADD COLUMN unexpected_private_field TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportBackupCopy(ctx, pool); err == nil {
		t.Fatal("unknown source schema was imported")
	}
	var journals int
	if err := pool.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_import_journal'").Scan(&journals); err != nil || journals != 0 {
		t.Fatal("refusal performed DDL", journals, err)
	}
}

func TestBackupCopyImportRejectsNonisolatedDatabase(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PORT"))
	if port <= 0 {
		t.Skip("owned MySQL required")
	}
	pool, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/mysql", os.Getenv("CLAWMANAGER_MERGE_TEST_MYSQL_PASSWORD"), port))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = ImportBackupCopy(context.Background(), pool); err == nil {
		t.Fatal("nonisolated database entered import")
	}
}
