package systembackupevidence

import (
	"context"
	"database/sql"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// This private HTTP cleanup boundary accepts only the server-held snapshot of
// an already committed public/internal claim. It grants no read/provider/audit
// authority. Concrete owner locks and exact CAS let cleanup survive session
// revocation, request cancellation and expiry without releasing another claim.
func (s SQLRegistry) finishPublicDownload(ctx context.Context, original Record) (bool, error) {
	owners, ok := s.Policy.(*SQLTaskDownloadOwners)
	if combined, combinedOK := s.Policy.(*SQLDownloadOwners); combinedOK && combined != nil {
		owners, ok = combined.SQLTaskDownloadOwners, true
	}
	if !ok || owners == nil {
		return false, nil
	} // Existing unrelated policies keep their own finisher.
	i := original.Manifest.Identity
	if ctx == nil || ctx.Err() != nil || !validRecord(original) || !oneOf(i.Classification, "public", "internal") || original.State != "ready" || original.Failure != "none" || !downloadAdmissionClaimID.MatchString(original.Claim) || !downloadAdmissionContentTime(original.ClaimUntil) || original.RowVersion < 1 || original.RowVersion >= 9007199254740991 || owners.c.Registry.DB != s.DB || owners.c.Registry.Installation != s.Installation || owners.c.Registry.ServerUUID != s.ServerUUID || owners.c.Registry.Database != s.Database {
		return true, ErrDenied
	}
	tx, _, err := s.begin(ctx)
	if err != nil {
		return true, err
	}
	defer tx.Rollback()
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, sec.DatabaseIdentity{ServerUUID: s.ServerUUID, Database: s.Database}, s.Installation)
	if err != nil {
		return true, ErrDownloadAdmissionNotReady
	}
	config, err := scope.LoadConfig(ctx, tx)
	if err != nil {
		return true, ErrDownloadAdmissionNotReady
	}
	if err = owners.LockOwnerReferences(ctx, tx, original); err != nil {
		return true, err
	}
	id, _, err := owners.evidenceKey(ctx, tx, i)
	if err != nil {
		return true, err
	}
	var installation sql.NullString
	if tx.QueryRowContext(ctx, downloadAdmissionInstallationSQL, i.ID).Scan(&installation) != nil || !installation.Valid || installation.String != i.Installation {
		return true, ErrDenied
	}
	current, err := s.loadManifest(ctx, tx, i.ID, true, func(context.Context, *sql.Tx, Identity) (time.Time, error) { return original.OwnerDeadline, nil })
	if err != nil || !sameDownloadAdmissionImmutable(current, original) || current.RowVersion != original.RowVersion || current.Claim != original.Claim || !current.ClaimUntil.Equal(original.ClaimUntil) {
		return true, ErrConflict
	}
	updated, err := tx.ExecContext(ctx, downloadResultReleaseSQL, id, i.ID, i.Installation, i.OwnerType, i.OwnerID, original.RowVersion, original.Claim, original.ClaimUntil)
	if !downloadAdmissionOne(updated, err) {
		return true, ErrConflict
	}
	var version int64
	var claim sql.NullString
	var until sql.NullTime
	if tx.QueryRowContext(ctx, downloadResultReleaseReadSQL, id, i.ID).Scan(&installation, &version, &claim, &until) != nil || !installation.Valid || installation.String != i.Installation || version != original.RowVersion+1 || claim.Valid || until.Valid || config.Recheck(ctx, tx) != nil || ctx.Err() != nil {
		return true, ErrIntegrity
	}
	if tx.Commit() != nil {
		return true, ErrDownloadResultCommitUnknown
	}
	return true, nil
}
