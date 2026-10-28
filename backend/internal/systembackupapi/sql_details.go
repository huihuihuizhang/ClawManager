package systembackupapi

import (
	"context"
	"database/sql"
	"encoding/json"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

type SQLTaskDetails struct{ DB *sql.DB }

func (d SQLTaskDetails) Backup(ctx context.Context, scope *security.SystemBackupReadScope, id string) (contract.BackupDetailResource, error) {
	r, err := read.NewReader(d.DB, scope)
	if err != nil {
		return contract.BackupDetailResource{}, err
	}
	return r.ReadBackupDetail(ctx, id)
}
func (d SQLTaskDetails) Preflight(ctx context.Context, scope *security.SystemBackupReadScope, id string) (contract.PreflightDetailResource, error) {
	r, err := read.NewReader(d.DB, scope)
	if err != nil {
		return contract.PreflightDetailResource{}, err
	}
	return r.ReadPreflightDetail(ctx, id)
}

// Read-only installations still expose authorized history. Missing execution
// configuration disables submission without disabling its independent reader.
type DisabledTaskWriter struct{}

func (DisabledTaskWriter) Prepare(context.Context, read.TaskKind, string, json.RawMessage) (PreparedTaskWrite, error) {
	return nil, &Error{"not_ready"}
}
