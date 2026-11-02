package systembackupsecurity

import (
	"context"
	"regexp"
	"sort"

	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
)

// Structural match for A's concrete BootstrapOriginalEvidenceAdmission, without
// importing the adapter back into security. This remains a trusted Go source,
// never a DTO/approval or a source receipt constructor.
type bootstrapKEKOriginalEvidence interface {
	reg.PreparedAdmission
	OriginalEvidenceIDs() []string
	LockOriginalEvidence(context.Context, reg.SQLReadView) error
	OriginalCoverage() reg.PreparedCoverage
}

var bootstrapOriginalEvidenceID = regexp.MustCompile(`^sev_[A-Za-z0-9._:-]{1,124}$`)

// Historical success is a receipt read, never a new KEK admission. Original
// current grant/RBAC and complete config checks have already run, as has L3's
// exact operation-key lookup. Compare only the immutable prior joined record;
// do not acquire fresh source/KEK locks or demand that old material be live.
func (s *configBootstrapCandidateSession) recheckHistoricalBootstrapKEK(ctx context.Context, tx pd.BootstrapReadSQL, facts pd.BootstrapConsumptionFacts) error {
	if s == nil || !s.kekRequired || !facts.Replayed || !facts.Operation.Found || facts.Operation.Status != "succeeded" || facts.Operation.Version != 1 || facts.Operation.RequestHash != s.hash || facts.Operation.PublicID == "" || s.kekBound != nil || s.kekWrite != nil {
		return pd.ErrGuardRequired
	}
	grant := s.plan.grant
	binding, observation, err := (reg.SQLStore{}).ReadCommittedInView(ctx, tx, grant.InstallationID, facts.Operation.PublicID)
	if err != nil || observation.InstallationID != grant.InstallationID || observation.ConfigSHA256 != grant.ConfigSHA256 || binding.InstallationID != grant.InstallationID || binding.ConfigRef.IdentityHash != binding.Key.IdentityHash || binding.ConfigRef.Version != binding.Key.RegistryVersion {
		return pd.ErrGuardRequired
	}
	count := 0
	for _, reference := range s.plan.config.References() {
		if reference.Purpose == "kek" {
			if reference.IdentityHash != binding.ConfigRef.IdentityHash || reference.Version != binding.ConfigRef.Version {
				return pd.ErrGuardRequired
			}
			count++
		}
	}
	if count != 1 {
		return pd.ErrGuardRequired
	}
	return nil
}

// Bootstrap candidate evidence/chunks and original KEK source evidence share
// L8. Lock their complete selected union in public-ID order BEFORE A checks
// current bytes and BEFORE stageBootstrapKEK takes the KEK fence. Neither this
// row lock nor an evidence ID authenticates a source: A's real checks follow.
func lockBootstrapKEKOriginalEvidence(ctx context.Context, tx pd.BootstrapSQL, prepared reg.PreparedAdmission, facts pd.BootstrapConsumptionFacts) error {
	if candidateAuthorityNil(ctx) || ctx.Err() != nil || candidateAuthorityNil(tx) || !pd.SameBootstrapTransaction(tx, tx) {
		return ErrRegistrationUnavailable
	}
	original, ok := prepared.(bootstrapKEKOriginalEvidence)
	if !ok || candidateAuthorityNil(original) || candidateAuthorityNil(original.OriginalCoverage()) {
		return ErrRegistrationUnavailable
	}
	ids := original.OriginalEvidenceIDs()
	if len(ids) == 0 || len(ids) > 128 || len(facts.Candidates) == 0 || len(facts.Candidates) > 20 {
		return ErrRegistrationUnavailable
	}
	observation := prepared.Observation()
	ids = append(append([]string(nil), ids...), observation.GenerateCapabilitySource.RecordID, observation.UnwrapCapabilitySource.RecordID)
	for _, candidate := range facts.Candidates {
		if candidate.Receipt == nil {
			return ErrRegistrationUnavailable
		}
		ids = append(ids, string(candidate.Receipt.Request.Evidence.EvidenceID))
	}
	unique := make(map[string]bool, len(ids))
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
		if tx.QueryRowContext(ctx, "SELECT id,public_id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&nativeID, &observed) != nil || nativeID <= 0 || observed != id {
			return ErrRegistrationUnavailable
		}
		// Include each original chunk range, including empty inline-source
		// ranges, so later candidate readback adds no L8 range.
		rows, err := tx.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE", nativeID)
		if err != nil {
			return ErrRegistrationUnavailable
		}
		count := 0
		for rows.Next() {
			var index int64
			if rows.Scan(&index) != nil || index < 0 || index != int64(count) || count >= 1024 {
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
