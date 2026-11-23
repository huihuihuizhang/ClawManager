package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	upper "github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/mysql"
)

// InitializeVerifiedTrialRuntime adopts a dedicated pool after the trial's
// independent artifact readback. It never applies migrations. The normal
// business connection paths still reject all drill schemas before I/O.
func InitializeVerifiedTrialRuntime(ctx context.Context, pool *sql.DB, database, serverUUID string) (upper.Session, error) {
	if pool == nil || !strings.HasPrefix(database, "cm_drill_trial_") || serverUUID == "" || SQLGateScope() != "" {
		return nil, errors.New("verified trial runtime database required")
	}
	var actualDB, actualUUID string
	if pool.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&actualDB, &actualUUID) != nil ||
		actualDB != database || actualUUID != serverUUID {
		return nil, errors.New("trial runtime database identity mismatch")
	}
	if err := checkBackupControlSchema(ctx, pool); err != nil {
		return nil, err
	}
	session, err := mysql.New(pool)
	if err != nil {
		return nil, err
	}
	if err := verifyEmbeddedMigrationsApplied(session); err != nil {
		_ = session.Close()
		return nil, err
	}
	Session = session
	return session, nil
}
