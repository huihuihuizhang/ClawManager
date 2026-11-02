package systembackupapi

import (
	"context"
	"database/sql"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// Opt-in production current reader. A missing current dependency fails closed;
// it never upgrades the existing explicit persisted-history reader silently.
type CurrentSQLTaskDetails struct {
	DB      *sql.DB
	Current read.CurrentTaskFacts
}

func (d CurrentSQLTaskDetails) Backup(ctx context.Context, scope *security.SystemBackupReadScope, id string) (contract.BackupDetailResource, error) {
	r, e := read.NewReader(d.DB, scope)
	if e != nil {
		return contract.BackupDetailResource{}, e
	}
	return r.ReadBackupDetailCurrentV1(ctx, id, d.Current)
}

func (d CurrentSQLTaskDetails) Preflight(ctx context.Context, scope *security.SystemBackupReadScope, id string) (contract.PreflightDetailResource, error) {
	return (SQLTaskDetails{DB: d.DB}).Preflight(ctx, scope, id)
}

var _ TaskDetails = CurrentSQLTaskDetails{}
