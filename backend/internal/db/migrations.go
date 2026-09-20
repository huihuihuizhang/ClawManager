package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"
	"time"

	"clawreef/internal/migrationcatalog"
	"clawreef/internal/migrationcoord"
	"github.com/upper/db/v4"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

const schemaMigrationsTable = "schema_migrations"

const captureGateMigration = "068_add_system_backup_coordination_observability.sql"

type migrationSQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// EmbeddedMigrationCatalog returns the exact catalog compiled into this
// binary. It does not inspect or mutate the database.
func EmbeddedMigrationCatalog() (migrationcatalog.Catalog, error) {
	return migrationcatalog.Compute(embeddedMigrations, "migrations")
}

func applyEmbeddedMigrations(session db.Session) (returnErr error) {
	if session == nil {
		return fmt.Errorf("nil database migration session")
	}
	rawDB, ok := session.Driver().(*sql.DB)
	if !ok || rawDB == nil {
		return fmt.Errorf("database migration driver is not *sql.DB")
	}
	ctx := context.Background()
	guard, err := (migrationcoord.SQLLocker{DB: rawDB}).AcquireSQL(ctx)
	if err != nil {
		return fmt.Errorf("acquire application migration exclusion: %w", err)
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := guard.Release(releaseCtx); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("release application migration exclusion: %w", err)
		}
	}()

	if err := ensureSchemaMigrationsTable(ctx, guard); err != nil {
		return err
	}

	applied, err := listAppliedMigrations(ctx, guard)
	if err != nil {
		return err
	}

	entries, err := embeddedMigrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to list embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if _, ok := applied[entry.Name()]; ok {
			continue
		}
		// Once the capture-gate schema exists, every later application migration
		// rechecks it while holding the same server-wide exclusion that gate
		// acquisition must hold. This makes the check and DDL race-free even
		// though MySQL DDL may implicitly commit.
		if _, gateSchemaApplied := applied[captureGateMigration]; gateSchemaApplied {
			if err := assertCaptureGateIdle(ctx, guard); err != nil {
				return fmt.Errorf("migration %s blocked by system backup capture gate: %w", entry.Name(), err)
			}
		}

		rawSQL, err := embeddedMigrations.ReadFile(path.Join("migrations", entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read embedded migration %s: %w", entry.Name(), err)
		}

		statements := splitSQLStatements(string(rawSQL))
		for idx, statement := range statements {
			if _, err := guard.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("failed to execute migration %s statement %d: %w", entry.Name(), idx+1, err)
			}
		}

		if _, err := guard.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s (filename, applied_at) VALUES (?, ?)", schemaMigrationsTable),
			entry.Name(),
			time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("failed to record applied migration %s: %w", entry.Name(), err)
		}

		applied[entry.Name()] = struct{}{}
		log.Printf("Applied database migration %s", entry.Name())
	}

	return nil
}

func ensureSchemaMigrationsTable(ctx context.Context, executor migrationSQL) error {
	exists, err := migrationTableExists(ctx, executor, schemaMigrationsTable)
	if err != nil {
		return fmt.Errorf("inspect schema migrations table: %w", err)
	}
	if exists {
		// A normal app restart must not issue even an IF NOT EXISTS DDL while
		// a system-backup capture gate may already be held.
		return nil
	}
	gateExists, err := migrationTableExists(ctx, executor, "system_maintenance_locks")
	if err != nil {
		return fmt.Errorf("inspect system backup maintenance gate table: %w", err)
	}
	if gateExists {
		return errors.New("schema migrations table is missing while system backup maintenance gate exists")
	}
	_, err = executor.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INT AUTO_INCREMENT PRIMARY KEY,
			filename VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uk_schema_migrations_filename (filename)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
	`, schemaMigrationsTable))
	if err != nil {
		return fmt.Errorf("failed to ensure schema migrations table: %w", err)
	}
	return nil
}

func migrationTableExists(ctx context.Context, executor migrationSQL, table string) (bool, error) {
	rows, err := executor.QueryContext(ctx, `SELECT COUNT(*)
FROM information_schema.tables
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table)
	if err != nil {
		return false, err
	}
	if !rows.Next() {
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil {
			return false, errors.Join(readErr, closeErr)
		}
		return false, errors.Join(errors.New("schema table existence check returned no row"), closeErr)
	}
	var count uint64
	if err := rows.Scan(&count); err != nil {
		return false, errors.Join(err, rows.Close())
	}
	if rows.Next() {
		return false, errors.Join(errors.New("schema table existence check returned multiple rows"), rows.Close())
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return false, err
	}
	if count > 1 {
		return false, errors.New("schema table existence check returned duplicate table")
	}
	return count == 1, nil
}

func listAppliedMigrations(ctx context.Context, executor migrationSQL) (map[string]struct{}, error) {
	rows, err := executor.QueryContext(ctx, fmt.Sprintf("SELECT filename FROM %s", schemaMigrationsTable))
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]struct{})
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			return nil, fmt.Errorf("failed to scan applied migration: %w", err)
		}
		applied[filename] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate applied migrations: %w", err)
	}

	return applied, nil
}

func assertCaptureGateIdle(ctx context.Context, executor migrationSQL) error {
	var active uint64
	rows, err := executor.QueryContext(ctx, `SELECT COUNT(*)
FROM system_maintenance_locks
WHERE gate_state <> 'idle'
   OR lock_owner IS NOT NULL
   OR heartbeat_at IS NOT NULL
   OR lease_expires_at IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("read system backup maintenance gate: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read system backup maintenance gate: %w", err)
		}
		return errors.New("system backup maintenance gate count returned no row")
	}
	if err := rows.Scan(&active); err != nil {
		return fmt.Errorf("scan system backup maintenance gate count: %w", err)
	}
	if rows.Next() {
		return errors.New("system backup maintenance gate count returned multiple rows")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read system backup maintenance gate: %w", err)
	}
	if active != 0 {
		return fmt.Errorf("%d system backup capture gate(s) are active", active)
	}
	return nil
}

func splitSQLStatements(input string) []string {
	statements := make([]string, 0)
	var current strings.Builder

	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(input); i++ {
		ch := input[i]
		var next byte
		if i+1 < len(input) {
			next = input[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}

		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
			}
			continue
		}

		if inSingleQuote {
			current.WriteByte(ch)
			if ch == '\\' && next != 0 {
				i++
				current.WriteByte(next)
				continue
			}
			if ch == '\'' {
				if next == '\'' {
					i++
					current.WriteByte(next)
					continue
				}
				inSingleQuote = false
			}
			continue
		}

		if inDoubleQuote {
			current.WriteByte(ch)
			if ch == '\\' && next != 0 {
				i++
				current.WriteByte(next)
				continue
			}
			if ch == '"' {
				if next == '"' {
					i++
					current.WriteByte(next)
					continue
				}
				inDoubleQuote = false
			}
			continue
		}

		if inBacktick {
			current.WriteByte(ch)
			if ch == '`' {
				inBacktick = false
			}
			continue
		}

		if ch == '-' && next == '-' {
			var afterNext byte
			if i+2 < len(input) {
				afterNext = input[i+2]
			}
			if afterNext == 0 || afterNext == ' ' || afterNext == '\t' || afterNext == '\r' || afterNext == '\n' {
				inLineComment = true
				i++
				continue
			}
		}

		if ch == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}

		switch ch {
		case '\'':
			inSingleQuote = true
			current.WriteByte(ch)
		case '"':
			inDoubleQuote = true
			current.WriteByte(ch)
		case '`':
			inBacktick = true
			current.WriteByte(ch)
		case ';':
			statement := strings.TrimSpace(current.String())
			if statement != "" {
				statements = append(statements, statement)
			}
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}

	if statement := strings.TrimSpace(current.String()); statement != "" {
		statements = append(statements, statement)
	}

	return statements
}
