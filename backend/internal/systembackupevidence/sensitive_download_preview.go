package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DownloadPreviewOwner is a deployment-owned CURRENT visibility/owner resolver.
// It must authorize the authenticated actor captured by its caller, resolve the
// actual owner's deadline, and use only read-only SQL on this transaction. It
// must not commit, refresh authority, acquire L3+ locks or perform provider I/O.
// A deadline or installation match alone is not authorization.
type DownloadPreviewOwner func(context.Context, *sql.Tx, Identity) (time.Time, error)

// PreviewDownloadEvidence loads the actual stored immutable Manifest for MFA
// and the pre-admission hint. The caller already holds L0/L1 and current session
// locks. The required owner callback runs before any chunk read. This method
// deliberately bypasses legacy SQLPolicy, whose callbacks may take L3+ locks.
// It returns metadata only: no claim, receipt, download or provider authority.
// Missing candidate ownership schema, NULL historical ownership, foreign rows
// or absent owner authorization fail closed; no historical row is backfilled.
func (s SQLRegistry) PreviewDownloadEvidence(ctx context.Context, tx *sql.Tx, id string, authorizeOwner DownloadPreviewOwner) (Record, error) {
	return s.previewDownloadEvidence(ctx, tx, id, authorizeOwner, true)
}

// Admission classification may also inspect public/internal rows; the MFA
// issuance API above remains private-only and does not change its contract.
func (s SQLRegistry) previewDownloadEvidence(ctx context.Context, tx *sql.Tx, id string, authorizeOwner DownloadPreviewOwner, privateOnly bool) (Record, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !idPattern.MatchString(id) || !installationPattern.MatchString(s.Installation) || s.ServerUUID == "" || s.Database == "" || authorizeOwner == nil {
		return Record{}, ErrDownloadAdmissionNotReady
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != s.ServerUUID || database != s.Database {
		return Record{}, ErrDownloadAdmissionNotReady
	}
	var installation sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&installation)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrDenied
		}
		return Record{}, ErrDownloadAdmissionNotReady
	}
	if !installation.Valid || installation.String != s.Installation {
		return Record{}, ErrDenied
	}
	var ownerFailure error
	r, err := s.loadManifest(ctx, tx, id, false, func(ctx context.Context, tx *sql.Tx, identity Identity) (time.Time, error) {
		if !identity.validExternal() || identity.Installation != s.Installation || identity.ID != id {
			ownerFailure = ErrDenied
			return time.Time{}, ownerFailure
		}
		until, err := authorizeOwner(ctx, tx, identity)
		if err != nil {
			ownerFailure = boundary(err)
			return time.Time{}, ownerFailure
		}
		if !downloadAdmissionContentTime(until) {
			ownerFailure = ErrDownloadAdmissionNotReady
			return time.Time{}, ownerFailure
		}
		return until, nil
	})
	if err != nil {
		if ownerFailure != nil {
			return Record{}, ownerFailure
		}
		return Record{}, err
	}
	if r.State != "ready" || r.Failure != "none" || !r.Ref.valid(true) || privateOnly && !oneOf(r.Manifest.Identity.Classification, "confidential", "sensitive") || r.RowVersion < 1 || r.RowVersion >= 9007199254740991 || ctx.Err() != nil {
		return Record{}, ErrState
	}
	return r, nil
}
