package systembackupsecurity

import (
	"context"
	"database/sql"
	"sort"

	reg "clawreef/internal/systembackupkekregistry"
)

// The config operation's own inline response is included with A's actual
// original adoption/witness and Generate/Unwrap evidence. Only their public-ID
// union/ranges are locked here; original signed bytes/current source checks
// still run through the SAME prepared object before the KEK fence.
func lockConfigMutationKEKOriginalEvidence(ctx context.Context, tx *sql.Tx, prepared reg.PreparedAdmission, responsePublicID string) error {
	if candidateAuthorityNil(ctx) || ctx.Err() != nil || tx == nil || candidateAuthorityNil(prepared) || !bootstrapOriginalEvidenceID.MatchString(responsePublicID) {
		return ErrRegistrationUnavailable
	}
	original, ok := prepared.(bootstrapKEKOriginalEvidence)
	if !ok || candidateAuthorityNil(original) || candidateAuthorityNil(original.OriginalCoverage()) {
		return ErrRegistrationUnavailable
	}
	ids := original.OriginalEvidenceIDs()
	if len(ids) < 1 || len(ids) > 128 {
		return ErrRegistrationUnavailable
	}
	observation := prepared.Observation()
	ids = append(append([]string(nil), ids...), observation.GenerateCapabilitySource.RecordID, observation.UnwrapCapabilitySource.RecordID, responsePublicID)
	unique := map[string]bool{}
	for _, id := range ids {
		if !bootstrapOriginalEvidenceID.MatchString(id) {
			return ErrRegistrationUnavailable
		}
		unique[id] = true
	}
	ids = ids[:0]
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var nativeID int64
		var observed string
		if tx.QueryRowContext(ctx, "SELECT id,public_id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&nativeID, &observed) != nil || nativeID < 1 || observed != id {
			return ErrRegistrationUnavailable
		}
		rows, e := tx.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE", nativeID)
		if e != nil {
			return ErrRegistrationUnavailable
		}
		count := int64(0)
		for rows.Next() {
			var index int64
			if rows.Scan(&index) != nil || index != count || count >= 1024 {
				rows.Close()
				return ErrRegistrationUnavailable
			}
			count++
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil || closeErr != nil || ctx.Err() != nil {
			return ErrRegistrationUnavailable
		}
	}
	return original.LockOriginalEvidence(ctx, tx)
}

// The caller already holds the complete original evidence union. Bind and
// CompleteScan precede StageAdmission, in the original mutation transaction.
// Merely having persisted four coverage rows never supplies a complete scan.
func stageConfigMutationOriginalKEK(ctx context.Context, tx *sql.Tx, installation, operation string, version uint64, prepared reg.PreparedAdmission) (*reg.Bound, error) {
	original, ok := prepared.(bootstrapKEKOriginalEvidence)
	if ctx == nil || ctx.Err() != nil || tx == nil || !ok || candidateAuthorityNil(original) || candidateAuthorityNil(original.OriginalCoverage()) {
		return nil, ErrRegistrationUnavailable
	}
	bound, _, e := (reg.SQLStore{}).Bind(ctx, tx, installation)
	if e != nil {
		return nil, ErrRegistrationUnavailable
	}
	if _, e = bound.CompleteScan(ctx, original.OriginalCoverage()); e != nil {
		return nil, ErrRegistrationUnavailable
	}
	if bound.StageAdmission(ctx, operation, version, prepared) != nil {
		return nil, ErrRegistrationUnavailable
	}
	return bound, nil
}
