package systembackupread

import (
	"context"
	"time"
)

// These records describe persisted bindings. Creation health is historical;
// current artifact/provider/evidence health and recovery readiness still need
// the reviewed Owner adapters. None of these contributions is a wire resource.
type PromotionControlRecord struct {
	PublicID, InstallationID, MatrixKey, BackupPublicID, DrillPublicID                    string
	ManifestSHA256, AcceptanceSHA256, RegistrationID, RegistrationSHA256                  string
	EligibilityDecisionSHA256, DrillEvidencePublicID, DrillEvidenceSHA256                 string
	SourceBackupRowVersion, SourceDrillRowVersion, SourcePruneGuardVersion, ConfigVersion uint64
	CreationHealth                                                                        [7]string
	CreationHealthSHA256                                                                  string
	CreationHealthObservedAt                                                              time.Time
	CreatedBy                                                                             string
	RowVersion                                                                            uint64
	CreatedAt, UpdatedAt                                                                  time.Time
	Backup                                                                                PromotionBackupBinding
	Drill                                                                                 PromotionDrillBinding
	Evidence                                                                              PromotionEvidenceBinding
}

func (PromotionControlRecord) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type PromotionBackupBinding struct {
	PublicID, InstallationID, MatrixKey, ManifestSHA256, AcceptanceSHA256, RegistrationID, RegistrationSHA256, EligibilityDecisionSHA256 string
	RowVersion, PruneGuardVersion                                                                                                        uint64
	ArtifactState, ArtifactUnusableReason                                                                                                string
	ArtifactUsable                                                                                                                       bool
}

func (PromotionBackupBinding) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type PromotionDrillBinding struct {
	PublicID, InstallationID, SourcePublicID, SourceManifestSHA256, SourceAcceptanceSHA256, EligibilityDecisionSHA256 string
	RowVersion                                                                                                        uint64
}

func (PromotionDrillBinding) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type PromotionEvidenceBinding struct {
	PublicID, OwnerPublicID, EvidenceType, ContentSHA256 string
	RowVersion                                           uint64
}

func (PromotionEvidenceBinding) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// CurrentPromotion's boolean reports a validated database record for the currently
// authorized installation/matrix was read. It is not acceptance-ready or a
// substitute for a complete OverviewResource/PromotionResource.
type OverviewPromotionControlSnapshot struct {
	control   OverviewControlSnapshot
	promotion *PromotionControlRecord
}

func (OverviewPromotionControlSnapshot) MarshalJSON() ([]byte, error)       { return nil, ErrInvalid }
func (s OverviewPromotionControlSnapshot) Control() OverviewControlSnapshot { return s.control }
func (s OverviewPromotionControlSnapshot) CurrentPromotion() (PromotionControlRecord, bool) {
	if s.promotion == nil {
		return PromotionControlRecord{}, false
	}
	return *s.promotion, true
}

// Complete overview builders use this boundary so the promotion, source rows
// and Owner contributions are not assembled after a separate committed read.
func readOverviewPromotionInTransaction[T any](ctx context.Context, r *Reader,
	build func(context.Context, overviewReadSQL, OverviewPromotionControlSnapshot) (T, error)) (T, error) {
	if build == nil {
		var zero T
		return zero, ErrUnavailable
	}
	return readOverviewInTransaction(ctx, r, func(ctx context.Context, q overviewReadSQL, control OverviewControlSnapshot) (T, error) {
		var zero T
		promotion, err := readCurrentPromotionControl(ctx, q, control.state)
		if err != nil {
			return zero, err
		}
		return build(ctx, q, OverviewPromotionControlSnapshot{control: control, promotion: promotion})
	})
}
func (r *Reader) ReadOverviewPromotionControl(ctx context.Context) (OverviewPromotionControlSnapshot, error) {
	return readOverviewPromotionInTransaction(ctx, r, func(_ context.Context, _ overviewReadSQL, s OverviewPromotionControlSnapshot) (OverviewPromotionControlSnapshot, error) {
		return s, nil
	})
}

const currentPromotionSQL = `SELECT schema_version,public_id,origin_installation_id,matrix_key,record_status,
backup_public_id,drill_public_id,manifest_checksum,acceptance_checksum,artifact_registration_id,artifact_registration_hash,
eligibility_decision_hash,drill_evidence_public_id,drill_evidence_hash,source_backup_row_version,source_drill_row_version,
source_prune_guard_version,config_version,creation_artifact_health,creation_artifact_access_health,creation_kek_health,
creation_signature_health,creation_catalog_health,creation_evidence_health,creation_attestation_health,
creation_health_snapshot_sha256,creation_health_observed_at,created_by,row_version,created_at,updated_at,
(superseded_by_public_id IS NULL AND superseded_reason IS NULL AND superseded_at IS NULL
 AND revoked_by IS NULL AND revoked_reason IS NULL AND revoked_at IS NULL)
FROM system_backup_v2_promotions WHERE origin_installation_id=? AND matrix_key=? AND record_status='active'`
const promotionBackupSQL = `SELECT schema_version,public_id,origin_installation_id,matrix_key,task_type,status,task_purpose,
acceptance_eligible,eligibility_reason_codes,eligibility_decision_hash,manifest_checksum,acceptance_checksum,
artifact_registration_id,artifact_registration_hash,row_version,prune_guard_version,artifact_state,artifact_usable,artifact_unusable_reason
FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`
const promotionDrillSQL = `SELECT schema_version,public_id,origin_installation_id,task_type,status,task_purpose,
source_artifact_type,source_public_id,source_manifest_checksum,source_acceptance_checksum,acceptance_eligible,
eligibility_reason_codes,eligibility_decision_hash,cleanup_policy,cleanup_status,cleanup_failure_code,row_version
FROM system_backup_v2_restore_drills WHERE origin_installation_id=? AND public_id=?`
const promotionEvidenceSQL = `SELECT schema_version,public_id,owner_target_type,owner_target_public_id,evidence_type,content_checksum,row_version
FROM system_backup_v2_evidence WHERE public_id=?`
const promotionConfigSQL = `SELECT schema_version,origin_installation_id,version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?`

func readCurrentPromotionControl(ctx context.Context, q overviewReadSQL, state OverviewInstallationState) (*PromotionControlRecord, error) {
	rows, err := q.QueryContext(ctx, currentPromotionSQL, state.InstallationID, state.MatrixKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	var p *PromotionControlRecord
	for rows.Next() {
		var record PromotionControlRecord
		var schema, status string
		var cleanLifecycle bool
		err = rows.Scan(&schema, &record.PublicID, &record.InstallationID, &record.MatrixKey, &status, &record.BackupPublicID, &record.DrillPublicID,
			&record.ManifestSHA256, &record.AcceptanceSHA256, &record.RegistrationID, &record.RegistrationSHA256, &record.EligibilityDecisionSHA256,
			&record.DrillEvidencePublicID, &record.DrillEvidenceSHA256, &record.SourceBackupRowVersion, &record.SourceDrillRowVersion,
			&record.SourcePruneGuardVersion, &record.ConfigVersion, &record.CreationHealth[0], &record.CreationHealth[1], &record.CreationHealth[2],
			&record.CreationHealth[3], &record.CreationHealth[4], &record.CreationHealth[5], &record.CreationHealth[6], &record.CreationHealthSHA256,
			&record.CreationHealthObservedAt, &record.CreatedBy, &record.RowVersion, &record.CreatedAt, &record.UpdatedAt, &cleanLifecycle)
		if err != nil || p != nil || schema != "system-backup-promotion.v1" || status != "active" || !cleanLifecycle || !validPromotionControl(record, state) {
			rows.Close()
			return nil, ErrUnavailable
		}
		p = &record
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return nil, ErrUnavailable
	}
	if p == nil {
		return nil, nil
	} // An actual query established the absence.
	if err = readPromotionBindings(ctx, q, p); err != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}

func validPromotionControl(p PromotionControlRecord, state OverviewInstallationState) bool {
	if p.InstallationID != state.InstallationID || p.MatrixKey != state.MatrixKey ||
		!prefixedOperationUUID(p.PublicID, "spm_") || !prefixedOperationUUID(p.BackupPublicID, "sbk_") ||
		!prefixedOperationUUID(p.DrillPublicID, "sdr_") || !prefixedOperationUUID(p.DrillEvidencePublicID, "sev_") ||
		len(p.RegistrationID) == 0 || len(p.RegistrationID) > 128 || !validExecutionNumber(p.RowVersion) ||
		!validExecutionNumber(p.SourceBackupRowVersion) || !validExecutionNumber(p.SourceDrillRowVersion) ||
		!validExecutionNumber(p.SourcePruneGuardVersion) || !validExecutionNumber(p.ConfigVersion) || !operationActorID.MatchString(p.CreatedBy) ||
		p.CreatedAt.IsZero() || p.UpdatedAt.Before(p.CreatedAt) || p.CreationHealthObservedAt.IsZero() || p.CreationHealthObservedAt.After(p.CreatedAt) {
		return false
	}
	for _, hash := range []string{p.ManifestSHA256, p.AcceptanceSHA256, p.RegistrationSHA256, p.EligibilityDecisionSHA256, p.DrillEvidenceSHA256, p.CreationHealthSHA256} {
		if !taskHash.MatchString(hash) {
			return false
		}
	}
	for _, health := range p.CreationHealth {
		if health != "healthy" {
			return false
		}
	}
	return true
}

func readPromotionBindings(ctx context.Context, q overviewReadSQL, p *PromotionControlRecord) error {
	b := &p.Backup
	var schema, kind, status, purpose, reasons string
	var eligible bool
	err := q.QueryRowContext(ctx, promotionBackupSQL, p.InstallationID, p.BackupPublicID).Scan(&schema, &b.PublicID, &b.InstallationID, &b.MatrixKey,
		&kind, &status, &purpose, &eligible, &reasons, &b.EligibilityDecisionSHA256, &b.ManifestSHA256, &b.AcceptanceSHA256,
		&b.RegistrationID, &b.RegistrationSHA256, &b.RowVersion, &b.PruneGuardVersion, &b.ArtifactState, &b.ArtifactUsable, &b.ArtifactUnusableReason)
	if err != nil || schema != "system-backup-task.v1" || kind != "backup" || b.PublicID != p.BackupPublicID || b.InstallationID != p.InstallationID ||
		b.MatrixKey != p.MatrixKey || status != "succeeded" || purpose != "acceptance" || !eligible || reasons != "eligible" ||
		!taskHash.MatchString(b.EligibilityDecisionSHA256) || b.ManifestSHA256 != p.ManifestSHA256 || b.AcceptanceSHA256 != p.AcceptanceSHA256 ||
		b.RegistrationID != p.RegistrationID || b.RegistrationSHA256 != p.RegistrationSHA256 ||
		!validExecutionNumber(b.RowVersion) || !validExecutionNumber(b.PruneGuardVersion) || b.RowVersion < p.SourceBackupRowVersion || b.PruneGuardVersion < p.SourcePruneGuardVersion ||
		!validPromotionArtifactAvailability(*b) {
		return ErrUnavailable
	}
	d := &p.Drill
	var sourceType, policy, cleanup, failure string
	err = q.QueryRowContext(ctx, promotionDrillSQL, p.InstallationID, p.DrillPublicID).Scan(&schema, &d.PublicID, &d.InstallationID, &kind, &status, &purpose,
		&sourceType, &d.SourcePublicID, &d.SourceManifestSHA256, &d.SourceAcceptanceSHA256, &eligible, &reasons, &d.EligibilityDecisionSHA256, &policy, &cleanup, &failure, &d.RowVersion)
	if err != nil || schema != "system-backup-task.v1" || kind != "drill" || d.PublicID != p.DrillPublicID || d.InstallationID != p.InstallationID ||
		status != "succeeded" || purpose != "acceptance" || sourceType != "backup" || d.SourcePublicID != p.BackupPublicID ||
		d.SourceManifestSHA256 != p.ManifestSHA256 || d.SourceAcceptanceSHA256 != p.AcceptanceSHA256 || !eligible || reasons != "eligible" ||
		!taskHash.MatchString(d.EligibilityDecisionSHA256) || policy != "delete-on-success" || cleanup != "succeeded" || failure != "none" ||
		!validExecutionNumber(d.RowVersion) || d.RowVersion < p.SourceDrillRowVersion {
		return ErrUnavailable
	}
	e := &p.Evidence
	var owner string
	err = q.QueryRowContext(ctx, promotionEvidenceSQL, p.DrillEvidencePublicID).Scan(&schema, &e.PublicID, &owner, &e.OwnerPublicID, &e.EvidenceType, &e.ContentSHA256, &e.RowVersion)
	// Evidence has no installation column. The scoped promotion/drill bind the
	// globally unique evidence ID, owner and immutable content checksum first.
	if err != nil || schema != "system-backup-evidence.v1" || e.PublicID != p.DrillEvidencePublicID || owner != "drill" || e.OwnerPublicID != p.DrillPublicID ||
		e.ContentSHA256 != p.DrillEvidenceSHA256 || !validExecutionNumber(e.RowVersion) ||
		!statusSet("verifier_report", "cleanup_result", "job_log_chunk", "diagnostic")[e.EvidenceType] {
		return ErrUnavailable
	}
	var installation string
	var version uint64
	if q.QueryRowContext(ctx, promotionConfigSQL, p.InstallationID, p.ConfigVersion).Scan(&schema, &installation, &version) != nil || schema != "system-backup-config.v1" || installation != p.InstallationID || version != p.ConfigVersion {
		return ErrUnavailable
	}
	// Saved source versions describe creation, not equality with mutable current
	// health/hold row versions. Historical eligibility hashes remain distinct;
	// their decision semantics are not substituted with a recomputed digest.
	return nil
}

func validPromotionArtifactAvailability(b PromotionBackupBinding) bool {
	if b.ArtifactState == "committed" {
		return statusSet("none", "finalization_pending", "provider_unavailable", "credential_unavailable", "kek_unavailable", "evidence_unavailable", "verification_inconclusive")[b.ArtifactUnusableReason] && b.ArtifactUsable == (b.ArtifactUnusableReason == "none")
	}
	// A historically eligible artifact cannot return to staging. Loss of its
	// present availability does not erase the active promotion record.
	return !b.ArtifactUsable && statusSet("deleting", "delete_failed", "deleted", "corrupt")[b.ArtifactState] && b.ArtifactUnusableReason == b.ArtifactState
}
