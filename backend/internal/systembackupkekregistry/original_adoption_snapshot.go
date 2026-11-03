package systembackupkekregistry

import (
	"context"
	"database/sql"
	"errors"
)

// ReadOriginalAdoptionSnapshotTx reads comparison DATA using the original
// caller transaction and shared locks. It never creates a missing fence or
// grants admission. The caller locks its original maintenance gate/fence before
// using it to resolve an unknown COMMIT, so that a pending original transaction
// must finish before a rolled-back outcome can be declared.
func (SQLStore) ReadOriginalAdoptionSnapshotTx(ctx context.Context, tx *sql.Tx, installationID string) (Snapshot, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || installationID == "" || len(installationID) > 128 {
		return Snapshot{}, ErrKEKFacts
	}
	s := Snapshot{InstallationID: installationID, Bindings: []BindingFacts{}, Coverage: []CoverageSource{}, References: []Reference{}}
	err := tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, installationID).Scan(&s.Epoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrKEKFacts
	}
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&s.Database.ServerUUID, &s.Database.Database, &s.ObservedAt) != nil || s.Database.ServerUUID == "" || s.Database.Database == "" || s.ObservedAt.IsZero() {
		return Snapshot{}, ErrKEKFacts
	}
	if err = readBindings(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err = readReferences(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err = readCoverage(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	return cloneSnapshot(s), nil
}
