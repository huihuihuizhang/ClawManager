package db

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

// MigrationTarget is deployment-owned authorization for an exact server,
// database and embedded catalog. It is never populated from an HTTP request.
type MigrationTarget struct {
	ServerUUID, Database, CatalogSHA256 string
	HistoryReview                       *MigrationHistoryReview
}

// ApplyPinnedMigrations is the standalone deployment entrypoint. It uses the
// application's migration runner, connection-scoped exclusion and capture-gate
// checks. Target identity is checked on that SAME locked connection before DDL.
func ApplyPinnedMigrations(ctx context.Context, database *sql.DB, target MigrationTarget) error {
	if database == nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(target.ServerUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(target.Database) {
		return errors.New("invalid migration target")
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil || target.CatalogSHA256 != catalog.Hash {
		return errors.New("migration catalog pin mismatch")
	}
	if target.HistoryReview != nil && !target.HistoryReview.matchesTarget(target) {
		return errors.New("historical review target mismatch")
	}
	return applyEmbeddedMigrationsSQL(ctx, database, &target)
}

func verifyMigrationTarget(ctx context.Context, executor migrationSQL, target MigrationTarget) error {
	rows, err := executor.QueryContext(ctx, "SELECT @@server_uuid,DATABASE()")
	if err != nil {
		return errors.New("migration target check failed")
	}
	defer rows.Close()
	var server, database string
	if !rows.Next() || rows.Scan(&server, &database) != nil || server != target.ServerUUID || database != target.Database {
		return errors.New("migration target mismatch")
	}
	if rows.Next() || rows.Err() != nil {
		return errors.New("migration target check failed")
	}
	return rows.Close()
}
