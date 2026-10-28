package systembackupread

import (
	"context"
	"database/sql"
	"strings"
)

// Detail control records are persisted D-owned contributions, not public
// DetailResources. In particular saved usability, eligibility and verifier
// fields do not prove current C/A/B health or replace their reviewed readers.
// Raw hold text, configuration, provider locators and resource inventories are
// deliberately absent. Complete DTO builders must use the transaction below.
type DetailChecksums struct {
	Manifest, Index, Marker, Acceptance, Catalog sql.NullString
}

func (DetailChecksums) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type DetailSourceControl struct {
	Type, PublicID string
	Checksums      DetailChecksums
}

func (DetailSourceControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type DetailEvidenceControl struct{ PublicID, SHA256 sql.NullString }

func (DetailEvidenceControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type DetailVerifierControl struct {
	AggregateStatus                  string
	Passed, Warning, Failed, Skipped uint64
	Report                           DetailEvidenceControl
}

func (DetailVerifierControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type DetailEligibilityControl struct {
	Eligible    bool
	Reasons     []string
	DecisionSHA sql.NullString
	DecidedAt   sql.NullTime
}

func (DetailEligibilityControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type BackupDetailControl struct {
	Purpose, Orchestrator, Profile, Matrix, Topology, Runner string
	RequestedParts, TargetRisks                              []string
	TargetClass, FailureDomain                               string
	Consistency                                              sql.NullString
	ArtifactState, UnusableReason                            string
	ArtifactUsable                                           bool
	CommittedAt                                              sql.NullTime
	Checksums                                                DetailChecksums
	RegistrationID, RegistrationSHA                          sql.NullString
	Eligibility                                              DetailEligibilityControl
	ManualHold, PromotionHold                                bool
	ManualHoldAt                                             sql.NullTime
	Bytes                                                    sql.Null[uint64]
	PruneGuardVersion                                        uint64
}

func (BackupDetailControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type DrillDetailControl struct {
	Source                                       DetailSourceControl
	Purpose, TargetProfile, TargetConfigSHA      string
	CleanupPolicy, CleanupStatus, CleanupFailure string
	Preflight, Diff                              DetailEvidenceControl
	Verifier                                     DetailVerifierControl
	Consistency                                  sql.NullString
	Eligibility                                  DetailEligibilityControl
}

func (DrillDetailControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type PreflightDetailControl struct {
	Source                               DetailSourceControl
	Mode, TargetProfile, TargetConfigSHA string
	Compatibility, ValidityReason        string
	Report, Diff                         DetailEvidenceControl
	Verifier                             DetailVerifierControl
}

func (PreflightDetailControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type VerificationDetailControl struct {
	Source                                                    DetailSourceControl
	Scope                                                     string
	Checksums                                                 DetailChecksums
	HealthReport                                              DetailEvidenceControl
	StateBefore, StateAfter                                   sql.NullString
	UsableBefore, UsableAfter                                 bool
	UnusableReasonBefore, UnusableReasonAfter, DecisionReason string
	Verifier                                                  DetailVerifierControl
}

func (VerificationDetailControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type TaskDetailControlSnapshot struct {
	execution    TaskExecutionSnapshot
	backup       *BackupDetailControl
	drill        *DrillDetailControl
	preflight    *PreflightDetailControl
	verification *VerificationDetailControl
}

func (TaskDetailControlSnapshot) MarshalJSON() ([]byte, error)       { return nil, ErrInvalid }
func (s TaskDetailControlSnapshot) Execution() TaskExecutionSnapshot { return s.execution }
func (s TaskDetailControlSnapshot) Backup() (BackupDetailControl, bool) {
	if s.backup == nil {
		return BackupDetailControl{}, false
	}
	b := *s.backup
	b.RequestedParts = append([]string{}, b.RequestedParts...)
	b.TargetRisks = append([]string{}, b.TargetRisks...)
	b.Eligibility.Reasons = append([]string{}, b.Eligibility.Reasons...)
	return b, true
}
func (s TaskDetailControlSnapshot) Drill() (DrillDetailControl, bool) {
	if s.drill == nil {
		return DrillDetailControl{}, false
	}
	d := *s.drill
	d.Eligibility.Reasons = append([]string{}, d.Eligibility.Reasons...)
	return d, true
}
func (s TaskDetailControlSnapshot) Preflight() (PreflightDetailControl, bool) {
	if s.preflight == nil {
		return PreflightDetailControl{}, false
	}
	return *s.preflight, true
}
func (s TaskDetailControlSnapshot) Verification() (VerificationDetailControl, bool) {
	if s.verification == nil {
		return VerificationDetailControl{}, false
	}
	return *s.verification, true
}

// The task, attempts, jobs, detail control columns and future Owner readers
// share one RepeatableRead snapshot and final authority/commit boundary. Never
// append Owner facts to a separately committed ReadTaskDetailControl result.
func readTaskDetailControlInTransaction[T any](ctx context.Context, r *Reader, kind TaskKind, publicID string,
	build func(context.Context, detailReadSQL, TaskDetailControlSnapshot) (T, error)) (T, error) {
	if build == nil {
		var zero T
		return zero, ErrUnavailable
	}
	return readTaskExecutionInTransaction(ctx, r, kind, publicID,
		func(ctx context.Context, q detailReadSQL, execution TaskExecutionSnapshot) (T, error) {
			var zero T
			s, err := readTaskDetailControl(ctx, q, execution)
			if err != nil {
				return zero, err
			}
			return build(ctx, q, s)
		})
}

func (r *Reader) ReadTaskDetailControl(ctx context.Context, kind TaskKind, publicID string) (TaskDetailControlSnapshot, error) {
	return readTaskDetailControlInTransaction(ctx, r, kind, publicID,
		func(_ context.Context, _ detailReadSQL, s TaskDetailControlSnapshot) (TaskDetailControlSnapshot, error) {
			return s, nil
		})
}

const detailIdentityColumns = "schema_version,public_id,origin_installation_id,task_type,row_version,config_version,status"
const backupDetailControlColumns = "task_purpose,source_orchestrator,source_profile,matrix_key,datasource_topology,runner,requested_parts,target_class,target_risks,target_failure_domain_id,consistency,artifact_state,artifact_usable,artifact_unusable_reason,artifact_committed_at,manifest_checksum,index_checksum,marker_checksum,acceptance_checksum,artifact_registration_id,artifact_registration_hash,acceptance_eligible,eligibility_reason_codes,eligibility_decision_hash,eligibility_decided_at,manual_hold,manual_hold_at,promotion_hold,artifact_bytes,prune_guard_version"
const detailSourceColumns = "source_artifact_type,source_public_id,source_manifest_checksum,source_acceptance_checksum,source_catalog_checksum"
const detailVerifierColumns = "verifier_aggregate_status,verifier_passed,verifier_warning,verifier_failed,verifier_skipped,verifier_report_evidence_public_id,verifier_report_evidence_sha256"
const drillDetailControlColumns = detailSourceColumns + ",task_purpose,target_profile,restore_target_config_hash,cleanup_policy,cleanup_status,cleanup_failure_code,preflight_evidence_public_id,preflight_evidence_sha256,diff_evidence_public_id,diff_evidence_sha256," + detailVerifierColumns + ",consistency,acceptance_eligible,eligibility_reason_codes,eligibility_decision_hash,eligibility_decided_at"
const preflightDetailControlColumns = detailSourceColumns + ",preflight_mode,target_profile,restore_target_config_hash,artifact_compatibility,report_validity_reason,report_evidence_public_id,report_evidence_sha256,diff_evidence_public_id,diff_evidence_sha256," + detailVerifierColumns
const verificationDetailControlColumns = "source_artifact_type,source_public_id,verification_scope,observed_manifest_checksum,observed_index_checksum,observed_marker_checksum,observed_acceptance_checksum,observed_catalog_checksum,health_report_evidence_public_id,health_report_evidence_sha256,artifact_state_before,artifact_state_after,usable_before,usable_after,unusable_reason_before,unusable_reason_after,decision_reason," + detailVerifierColumns

func taskDetailControlSQL(kind TaskKind) string {
	columns := map[TaskKind]string{BackupTask: backupDetailControlColumns, DrillTask: drillDetailControlColumns,
		PreflightTask: preflightDetailControlColumns, VerificationTask: verificationDetailControlColumns}[kind]
	if columns == "" {
		return ""
	}
	return "SELECT " + detailIdentityColumns + "," + columns + " FROM " + taskTables[kind].name + " WHERE origin_installation_id=? AND public_id=?"
}

func readTaskDetailControl(ctx context.Context, q detailReadSQL, execution TaskExecutionSnapshot) (TaskDetailControlSnapshot, error) {
	var zero TaskDetailControlSnapshot
	task := execution.Task()
	query := taskDetailControlSQL(task.Kind)
	if query == "" {
		return zero, ErrUnavailable
	}
	var schema, id, installation, kind, status string
	var version, config uint64
	args := []any{&schema, &id, &installation, &kind, &version, &config, &status}
	s := TaskDetailControlSnapshot{execution: execution}
	var parts, risks, reasons string
	switch task.Kind {
	case BackupTask:
		b := &BackupDetailControl{}
		s.backup = b
		args = append(args, &b.Purpose, &b.Orchestrator, &b.Profile, &b.Matrix, &b.Topology, &b.Runner, &parts,
			&b.TargetClass, &risks, &b.FailureDomain, &b.Consistency, &b.ArtifactState, &b.ArtifactUsable, &b.UnusableReason,
			&b.CommittedAt, &b.Checksums.Manifest, &b.Checksums.Index, &b.Checksums.Marker, &b.Checksums.Acceptance,
			&b.RegistrationID, &b.RegistrationSHA, &b.Eligibility.Eligible, &reasons, &b.Eligibility.DecisionSHA,
			&b.Eligibility.DecidedAt, &b.ManualHold, &b.ManualHoldAt, &b.PromotionHold, &b.Bytes, &b.PruneGuardVersion)
	case DrillTask:
		d := &DrillDetailControl{}
		s.drill = d
		args = append(args, detailSourceScan(&d.Source)...)
		args = append(args, &d.Purpose, &d.TargetProfile, &d.TargetConfigSHA, &d.CleanupPolicy, &d.CleanupStatus,
			&d.CleanupFailure, &d.Preflight.PublicID, &d.Preflight.SHA256, &d.Diff.PublicID, &d.Diff.SHA256)
		args = append(args, detailVerifierScan(&d.Verifier)...)
		args = append(args, &d.Consistency, &d.Eligibility.Eligible, &reasons, &d.Eligibility.DecisionSHA, &d.Eligibility.DecidedAt)
	case PreflightTask:
		p := &PreflightDetailControl{}
		s.preflight = p
		args = append(args, detailSourceScan(&p.Source)...)
		args = append(args, &p.Mode, &p.TargetProfile, &p.TargetConfigSHA, &p.Compatibility, &p.ValidityReason,
			&p.Report.PublicID, &p.Report.SHA256, &p.Diff.PublicID, &p.Diff.SHA256)
		args = append(args, detailVerifierScan(&p.Verifier)...)
	case VerificationTask:
		v := &VerificationDetailControl{}
		s.verification = v
		args = append(args, &v.Source.Type, &v.Source.PublicID, &v.Scope, &v.Checksums.Manifest, &v.Checksums.Index,
			&v.Checksums.Marker, &v.Checksums.Acceptance, &v.Checksums.Catalog, &v.HealthReport.PublicID, &v.HealthReport.SHA256,
			&v.StateBefore, &v.StateAfter, &v.UsableBefore, &v.UsableAfter, &v.UnusableReasonBefore, &v.UnusableReasonAfter, &v.DecisionReason)
		args = append(args, detailVerifierScan(&v.Verifier)...)
	}
	if err := q.QueryRowContext(ctx, query, task.InstallationID, task.PublicID).Scan(args...); err != nil ||
		schema != "system-backup-task.v1" || id != task.PublicID || installation != task.InstallationID ||
		kind != string(task.Kind) || status != task.Status || version != task.RowVersion || config != task.ConfigVersion {
		return zero, ErrUnavailable
	}
	if b := s.backup; b != nil {
		var ok bool
		if b.RequestedParts, ok = detailSet(parts, false, "mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"); !ok {
			return zero, ErrUnavailable
		}
		if b.TargetRisks, ok = detailSet(risks, true, "source_overlap", "same_failure_domain", "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent", "attestation_missing", "attestation_expired", "conditional_commit_unavailable", "transport_unverified", "broad_egress", "provider_capability_degraded"); !ok {
			return zero, ErrUnavailable
		}
		if !validDetailEligibility(&b.Eligibility, reasons, task, b.Purpose) || !validBackupDetailControl(*b) {
			return zero, ErrUnavailable
		}
	}
	if d := s.drill; d != nil {
		if !validDetailEligibility(&d.Eligibility, reasons, task, d.Purpose) || !validDrillDetailControl(*d) {
			return zero, ErrUnavailable
		}
	}
	if p := s.preflight; p != nil {
		if !validDetailSource(p.Source) || !detailTarget(p.TargetProfile, p.TargetConfigSHA) || !statusSet("production_readonly", "functional_test")[p.Mode] ||
			!statusSet("supported", "compatible_with_warnings", "unsupported")[p.Compatibility] ||
			!statusSet("pending", "valid", "functional_test_only", "source_changed", "dependency_unhealthy", "report_expired", "evidence_unavailable", "incomplete")[p.ValidityReason] ||
			!validDetailEvidence(p.Report) || !validDetailEvidence(p.Diff) || !validDetailVerifier(p.Verifier) {
			return zero, ErrUnavailable
		}
	}
	if v := s.verification; v != nil {
		if !validDetailSource(v.Source) || !statusSet("health", "full")[v.Scope] || !validDetailChecksums(v.Checksums) ||
			!validDetailEvidence(v.HealthReport) || !validDetailVerifier(v.Verifier) ||
			v.StateBefore.Valid != (v.Source.Type == "backup") || v.StateAfter.Valid != (v.Source.Type == "backup") ||
			!validDetailObservedArtifact(v.StateBefore, v.UsableBefore, v.UnusableReasonBefore) ||
			!validDetailObservedArtifact(v.StateAfter, v.UsableAfter, v.UnusableReasonAfter) ||
			!statusSet("pending", "unchanged", "restored_usable", "marked_unusable", "marked_corrupt", "catalog_tombstoned", "verification_inconclusive")[v.DecisionReason] || !validDetailVerificationTransition(*v) {
			return zero, ErrUnavailable
		}
	}
	return s, nil
}

func detailSourceScan(s *DetailSourceControl) []any {
	return []any{&s.Type, &s.PublicID, &s.Checksums.Manifest, &s.Checksums.Acceptance, &s.Checksums.Catalog}
}
func detailVerifierScan(v *DetailVerifierControl) []any {
	return []any{&v.AggregateStatus, &v.Passed, &v.Warning, &v.Failed, &v.Skipped, &v.Report.PublicID, &v.Report.SHA256}
}
func detailSet(raw string, empty bool, allowed ...string) ([]string, bool) {
	if raw == "" {
		return []string{}, empty
	}
	values, seen, choices := strings.Split(raw, ","), map[string]bool{}, statusSet(allowed...)
	for _, value := range values {
		if !choices[value] || seen[value] {
			return nil, false
		}
		seen[value] = true
	}
	return values, true
}
func detailHash(h sql.NullString) bool { return !h.Valid || taskHash.MatchString(h.String) }
func validDetailChecksums(c DetailChecksums) bool {
	return detailHash(c.Manifest) && detailHash(c.Index) && detailHash(c.Marker) && detailHash(c.Acceptance) && detailHash(c.Catalog)
}
func validDetailEvidence(e DetailEvidenceControl) bool {
	return e.PublicID.Valid == e.SHA256.Valid && (!e.PublicID.Valid || validDetailPublicID(e.PublicID.String, "sev_") && taskHash.MatchString(e.SHA256.String))
}
func validDetailPublicID(id, prefix string) bool {
	return len(id) == len(prefix)+36 && strings.HasPrefix(id, prefix) && taskUUID.MatchString(id[len(prefix):])
}
func validDetailSource(s DetailSourceControl) bool {
	return (s.Type == "backup" && validDetailPublicID(s.PublicID, "sbk_") || s.Type == "catalog_import" && validDetailPublicID(s.PublicID, "sci_")) && validDetailChecksums(s.Checksums)
}
func detailTarget(profile, hash string) bool {
	return statusSet("cluster", "single-node")[profile] && taskHash.MatchString(hash)
}
func validDetailVerifier(v DetailVerifierControl) bool {
	// Counts and aggregate are persisted A report summaries. Do not derive a
	// different aggregate or assert that a report is currently available.
	return statusSet("passed", "warning", "failed", "skipped")[v.AggregateStatus] &&
		v.Passed <= 1<<32-1 && v.Warning <= 1<<32-1 && v.Failed <= 1<<32-1 && v.Skipped <= 1<<32-1 && validDetailEvidence(v.Report)
}
func validDetailEligibility(e *DetailEligibilityControl, reasons string, task TaskHeader, purpose string) bool {
	var ok bool
	e.Reasons, ok = detailSet(reasons, false, "eligible", "functional_test", "task_not_succeeded", "artifact_not_committed", "required_part_failed", "required_verifier_failed", "staging_cleanup_failed", "consistency_not_strong", "disqualifying_warning", "target_not_external", "target_risk", "attestation_invalid", "kek_not_recoverable", "catalog_unavailable", "source_backup_not_eligible", "source_artifact_unusable", "manifest_drift", "isolation_invalid", "evidence_incomplete")
	if !ok || !statusSet("acceptance", "functional_test")[purpose] || !detailHash(e.DecisionSHA) || e.DecisionSHA.Valid != e.DecidedAt.Valid || e.DecidedAt.Valid && e.DecidedAt.Time.IsZero() {
		return false
	}
	if e.Eligible {
		return task.Status == "succeeded" && purpose == "acceptance" && reasons == "eligible" && e.DecisionSHA.Valid
	}
	for _, reason := range e.Reasons {
		if reason == "eligible" {
			return false
		}
	}
	return true
}
func validBackupDetailControl(b BackupDetailControl) bool {
	expectedRunner := map[string]string{"kubernetes": "k8s", "k3s": "k3s"}[b.Orchestrator]
	if expectedRunner == "" || b.Runner != expectedRunner || !statusSet("cluster", "single-node")[b.Profile] || b.Matrix != expectedRunner+"-"+b.Profile ||
		b.Topology != "in_cluster" || !statusSet("dr-ready-external", "same-cluster-copy")[b.TargetClass] ||
		len(b.FailureDomain) < 1 || len(b.FailureDomain) > 128 || !taskToken.MatchString(b.FailureDomain) ||
		b.Consistency.Valid && !statusSet("strong", "bounded", "weak")[b.Consistency.String] ||
		!validDetailChecksums(b.Checksums) || b.RegistrationID.Valid != b.RegistrationSHA.Valid || !detailHash(b.RegistrationSHA) ||
		b.RegistrationID.Valid && (len(b.RegistrationID.String) < 1 || len(b.RegistrationID.String) > 128) ||
		b.Eligibility.Eligible && !b.RegistrationID.Valid || !validExecutionNumber(b.PruneGuardVersion) ||
		b.ManualHold != b.ManualHoldAt.Valid || b.ManualHoldAt.Valid && b.ManualHoldAt.Time.IsZero() ||
		b.CommittedAt.Valid && b.CommittedAt.Time.IsZero() {
		return false
	}
	switch b.ArtifactState {
	case "staging":
		return !b.ArtifactUsable && b.UnusableReason == "not_committed" && !b.CommittedAt.Valid
	case "committed":
		return b.CommittedAt.Valid && b.Checksums.Manifest.Valid && b.Checksums.Index.Valid && b.Checksums.Marker.Valid &&
			statusSet("none", "finalization_pending", "provider_unavailable", "credential_unavailable", "kek_unavailable", "evidence_unavailable", "verification_inconclusive")[b.UnusableReason] && b.ArtifactUsable == (b.UnusableReason == "none")
	case "deleting", "delete_failed", "deleted", "corrupt":
		return !b.ArtifactUsable && b.UnusableReason == b.ArtifactState
	default:
		return false
	}
}
func validDrillDetailControl(d DrillDetailControl) bool {
	failed := d.CleanupStatus == "failed" || d.CleanupStatus == "partial_failed"
	return validDetailSource(d.Source) && detailTarget(d.TargetProfile, d.TargetConfigSHA) &&
		statusSet("delete-on-success", "retain-always")[d.CleanupPolicy] &&
		statusSet("not_started", "pending", "running", "succeeded", "failed", "partial_failed", "retained")[d.CleanupStatus] &&
		statusSet("none", "deadline_exceeded", "provider_unavailable", "permission_denied", "identity_mismatch", "checksum_mismatch", "ownership_unknown", "residual_data", "internal")[d.CleanupFailure] &&
		failed == (d.CleanupFailure != "none") && validDetailEvidence(d.Preflight) && validDetailEvidence(d.Diff) && validDetailVerifier(d.Verifier) &&
		(!d.Consistency.Valid || statusSet("strong", "bounded", "weak")[d.Consistency.String]) &&
		(!d.Eligibility.Eligible || d.CleanupPolicy == "delete-on-success" && d.CleanupStatus == "succeeded")
}
func validDetailObservedArtifact(state sql.NullString, usable bool, reason string) bool {
	if !statusSet("none", "not_committed", "finalization_pending", "deleting", "delete_failed", "deleted", "corrupt", "verification_pending", "catalog_tombstoned", "acceptance_invalid", "provider_unavailable", "credential_unavailable", "kek_unavailable", "signing_key_unavailable", "catalog_unavailable", "evidence_unavailable", "verification_inconclusive")[reason] {
		return false
	}
	// Imported artifacts have no local backup artifact_state, even when usable.
	// The source/type binding is checked by the caller; availability is a saved
	// result, not a current provider assertion.
	return usable == (reason == "none") && (!state.Valid ||
		statusSet("staging", "committed", "deleting", "delete_failed", "deleted", "corrupt")[state.String] && (!usable || state.String == "committed"))
}

// A saved observation may describe a failed or still-running verification, but
// a restoration label must describe an actual false-to-true full verification.
// This validates historical field consistency, not current provider health or
// proof that the writer verified the same immutable version.
func validDetailVerificationTransition(v VerificationDetailControl) bool {
	if v.Scope != "full" && !v.UsableBefore && v.UsableAfter {
		return false
	}
	if v.DecisionReason == "restored_usable" {
		return v.Scope == "full" && !v.UsableBefore && v.UsableAfter
	}
	return true
}
