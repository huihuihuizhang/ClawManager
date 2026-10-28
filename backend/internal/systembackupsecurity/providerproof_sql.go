package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

var providerEvidenceID = regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrProviderEvidenceStorage is mapped to an internal service failure by the
// transaction owner. Database faults must not masquerade as invalid proofs.
var ErrProviderEvidenceStorage = errors.New("provider_evidence_storage_failed")

// StageProviderProofEvidence writes into the caller's existing transaction.
// It neither commits nor changes the target conclusion. Call only after D has
// locked config/issuer registry and admitted destructive permission, recent
// strong-auth, nonce and operation idempotency in this SAME transaction.
// On ANY error the caller must roll back; on retry it must use D's existing
// operation result rather than call this again with a new evidence ID.
func StageProviderProofEvidence(ctx context.Context, tx *sql.Tx, evidenceID string, p PreparedProviderEvidence) error {
	if tx == nil || !p.prepared || !providerEvidenceID.MatchString(evidenceID) {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	if ctx.Err() != nil {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	table := map[string]string{"external_action": "system_backup_v2_external_actions", "backup_staging": "system_backup_v2_staging_resources", "restore_resource": "system_backup_v2_restore_drill_resources"}[p.target.TargetType]
	if table == "" {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	// Table identifiers are closed constants. Installation and public ID are bound parameters.
	var version int64
	err := tx.QueryRowContext(ctx, "SELECT row_version FROM "+table+" WHERE origin_installation_id = ? AND public_id = ? FOR UPDATE", p.installationID, p.target.TargetPublicID).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrProviderEvidenceStorage
	}
	if errors.Is(err, sql.ErrNoRows) || version != p.rowVersion {
		return &ProviderProofError{Code: ProviderVersionConflict}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence
		(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,
		content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at)
		SELECT ?,?,?,?,'inline',?,?,?,'application/json','none','internal','healthy',?
		WHERE UTC_TIMESTAMP(6) >= ? AND UTC_TIMESTAMP(6) < ?`, evidenceID, p.target.TargetType, p.target.TargetPublicID, p.evidenceType,
		p.payload, p.checksum, len(p.payload), p.retainUntil.UTC(), p.validFrom.UTC(), p.validUntil.UTC())
	if err != nil {
		return ErrProviderEvidenceStorage
	}
	n, err := result.RowsAffected()
	if err != nil || n > 1 || n < 0 {
		return ErrProviderEvidenceStorage
	}
	if n != 1 {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	return nil
}
