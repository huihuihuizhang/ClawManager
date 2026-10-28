package db

import (
	"context"
	"database/sql"
	"errors"

	"clawreef/internal/config"
	"clawreef/internal/migrationcatalog"
	upper "github.com/upper/db/v4"
)

type migrationSQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func EmbeddedMigrationCatalog() (migrationcatalog.Catalog, error) {
	return migrationcatalog.Compute(embeddedMigrations, "migrations")
}

// This independent UTC connection cannot migrate or initialize business services.
func ConnectSystemBackupController(cfg config.DatabaseConfig) (upper.Session, error) {
	return OpenSystemBackupRead(cfg)
}

func applyEmbeddedMigrationsSQL(ctx context.Context, pool *sql.DB, target *MigrationTarget) (result error) {
	if pool == nil || target == nil {
		return errors.New("pinned migration target required")
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	release, err := acquireMigrationLocks(ctx, conn)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, release()) }()
	if err = verifyMigrationTarget(ctx, conn, *target); err != nil {
		return err
	}
	if err = checkBackupControlSchema(ctx, conn); err != nil {
		return err
	}
	var count int
	if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='schema_migrations'").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		applied, err := listAppliedMigrations(conn)
		if err != nil {
			return err
		}
		if target.HistoryReview != nil {
			if err = target.HistoryReview.verifyLedger(applied); err != nil {
				return err
			}
		} else {
			catalog, err := EmbeddedMigrationCatalog()
			if err != nil {
				return err
			}
			known := map[string]bool{}
			for _, name := range catalog.Filenames {
				known[name] = true
			}
			for name := range applied {
				if !known[name] {
					return errors.New("target migration ledger contains unknown migration; use reviewed offline copy import")
				}
			}
		}
	} else if target.HistoryReview != nil {
		return errors.New("reviewed installation migration ledger missing")
	}
	return applyEmbeddedMigrationsLockedContext(ctx, conn)
}
