package systembackupread

import (
	"context"
	"database/sql"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

const backupTaskTimesSQL = "SELECT row_version,heartbeat_at,next_reconcile_at,started_at,finished_at FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?"
const preflightTaskTimesSQL = "SELECT row_version,heartbeat_at,next_reconcile_at,started_at,finished_at FROM system_backup_v2_preflights WHERE origin_installation_id=? AND public_id=?"

// ReadBackupDetail returns recorded facts, not a fresh provider health check.
// AcceptanceReady is deliberately false: a later operation must independently
// verify current artifact/provider availability before using a recovery point.
func (r *Reader) ReadBackupDetail(ctx context.Context, id string) (contract.BackupDetailResource, error) {
	return readTaskCheckEvidenceControlInTransaction(ctx, r, BackupTask, id, buildBackupDetail)
}

func (r *Reader) ReadPreflightDetail(ctx context.Context, id string) (contract.PreflightDetailResource, error) {
	return readTaskCheckEvidenceControlInTransaction(ctx, r, PreflightTask, id, buildPreflightDetail)
}

func detailEnvelope(ctx context.Context, q detailReadSQL, s TaskCheckEvidenceControlSnapshot) (contract.Task, contract.ExecutionProjection, contract.VerifierSummary, uint64, time.Time, error) {
	h := s.checks.detail.execution.task
	var task contract.Task
	var execution contract.ExecutionProjection
	summary := contract.VerifierSummary{AggregateStatus: "skipped"}
	base, err := ProjectTask(h)
	if err != nil {
		return task, execution, summary, 0, time.Time{}, err
	}
	query := backupTaskTimesSQL
	if h.Kind == PreflightTask {
		query = preflightTaskTimesSQL
	}
	var version uint64
	var heartbeat, reconcile, started, finished sql.NullTime
	if q.QueryRowContext(ctx, query, h.InstallationID, h.PublicID).Scan(&version, &heartbeat, &reconcile, &started, &finished) != nil || version != h.RowVersion {
		return task, execution, summary, 0, time.Time{}, ErrUnavailable
	}
	for _, t := range []sql.NullTime{heartbeat, reconcile, started, finished} {
		if t.Valid && (t.Time.IsZero() || t.Time.Year() < 1 || t.Time.Year() > 9999) {
			return task, execution, summary, 0, time.Time{}, ErrUnavailable
		}
	}
	terminal := statusSet("succeeded", "failed", "canceled")[h.Status]
	if (h.Status != "pending") != started.Valid || terminal != finished.Valid ||
		started.Valid && started.Time.Before(h.CreatedAt) || finished.Valid && finished.Time.Before(started.Time) {
		return task, execution, summary, 0, time.Time{}, ErrUnavailable
	}
	execution, current, attemptStart, err := taskExecutionProjection(s.checks.detail.execution, h.Kind)
	if err != nil {
		return task, execution, summary, 0, time.Time{}, err
	}
	var progress time.Time
	if execution.LastBusinessProgressAt != nil {
		progress, _ = time.Parse(time.RFC3339Nano, *execution.LastBusinessProgressAt)
	}
	for _, c := range s.checks.checks {
		if c.AttemptNumber != current {
			continue
		}
		if c.CheckedAt.After(progress) {
			progress = c.CheckedAt
		}
		switch c.Status {
		case "passed":
			summary.Passed++
		case "warning":
			summary.Warning++
		case "failed":
			summary.Failed++
		case "skipped":
			summary.Skipped++
		default:
			return task, execution, summary, 0, time.Time{}, ErrUnavailable
		}
	}
	switch {
	case summary.Failed > 0:
		summary.AggregateStatus = "failed"
	case summary.Warning > 0:
		summary.AggregateStatus = "warning"
	case summary.Passed > 0:
		summary.AggregateStatus = "passed"
	}
	if !progress.IsZero() {
		execution.LastBusinessProgressAt = verificationTime(sql.NullTime{Time: progress, Valid: true})
	}
	task = contract.Task{
		SchemaVersion: base.SchemaVersion, PublicID: base.PublicID, OriginInstallationID: base.OriginInstallationID,
		TaskType: string(base.TaskType), ActorType: base.ActorType, ActorID: base.ActorID, Endpoint: base.Endpoint,
		IdempotencyKey: base.IdempotencyKey, RequestHash: base.RequestHash, RequestID: base.RequestID, RetryOfPublicID: base.RetryOfPublicID,
		Status: base.Status, PendingReason: base.PendingReason, AttentionReason: base.AttentionReason, CanCancel: base.CanCancel,
		ConfigVersion: int64(base.ConfigVersion), RowVersion: int64(base.RowVersion), Retryable: base.Retryable, FailureCategory: base.FailureCategory,
		DeadlineAt: base.DeadlineAt, CreatedAt: base.CreatedAt, UpdatedAt: base.UpdatedAt,
		HeartbeatAt: verificationTime(heartbeat), NextReconcileAt: verificationTime(reconcile), StartedAt: verificationTime(started), FinishedAt: verificationTime(finished),
	}
	return task, execution, summary, current, attemptStart, nil
}

func buildBackupDetail(ctx context.Context, q detailReadSQL, s TaskCheckEvidenceControlSnapshot) (contract.BackupDetailResource, error) {
	var zero contract.BackupDetailResource
	b, ok := s.checks.detail.Backup()
	if !ok {
		return zero, ErrUnavailable
	}
	task, execution, summary, _, _, err := detailEnvelope(ctx, q, s)
	if err != nil {
		return zero, err
	}
	var size *int64
	var holdReason, holdActor *string
	if b.ManualHold {
		// This reader has no reviewed free-text redactor. Explicitly withhold
		// stored hold text/actor instead of leaking it or failing the whole row.
		redacted := "[redacted]"
		holdReason, holdActor = &redacted, &redacted
	}
	if b.Bytes.Valid {
		if b.Bytes.V > maxJSONSafeInteger {
			return zero, ErrUnavailable
		}
		n := int64(b.Bytes.V)
		size = &n
	}
	return contract.BackupDetailResource{
		SchemaVersion: "system-backup-backup-detail.v1", Task: task, Execution: execution,
		TaskPurpose: b.Purpose, SourceOrchestrator: b.Orchestrator, SourceProfile: b.Profile, Matrix: b.Matrix, DatasourceTopology: b.Topology,
		Runner: b.Runner, RequestedParts: b.RequestedParts, ArtifactState: b.ArtifactState, ArtifactUsable: b.ArtifactUsable,
		ArtifactUnusableReason: b.UnusableReason, ArtifactCommittedAt: verificationTime(b.CommittedAt), AcceptanceReady: false,
		AcceptanceEligible: b.Eligibility.Eligible, EligibilityReasonCodes: b.Eligibility.Reasons, EligibilityDecisionHash: verificationString(b.Eligibility.DecisionSHA),
		TargetClass: b.TargetClass, TargetRisks: b.TargetRisks, TargetFailureDomainID: b.FailureDomain, Consistency: verificationString(b.Consistency),
		Checksums:              contract.NullableArtifactChecksumSet{Manifest: verificationString(b.Checksums.Manifest), Index: verificationString(b.Checksums.Index), Marker: verificationString(b.Checksums.Marker), Acceptance: verificationString(b.Checksums.Acceptance), Catalog: verificationString(b.Checksums.Catalog)},
		ArtifactRegistrationID: verificationString(b.RegistrationID), ArtifactRegistrationHash: verificationString(b.RegistrationSHA), VerifierSummary: summary,
		ManualHold: b.ManualHold, ManualHoldReason: holdReason, ManualHoldActor: holdActor, ManualHoldAt: verificationTime(b.ManualHoldAt), PromotionHold: b.PromotionHold, Bytes: size, PruneGuardVersion: int64(b.PruneGuardVersion),
	}, nil
}

func buildPreflightDetail(ctx context.Context, q detailReadSQL, s TaskCheckEvidenceControlSnapshot) (contract.PreflightDetailResource, error) {
	var zero contract.PreflightDetailResource
	p, ok := s.checks.detail.Preflight()
	if !ok {
		return zero, ErrUnavailable
	}
	task, execution, summary, attempt, attemptStart, err := detailEnvelope(ctx, q, s)
	if err != nil {
		return zero, err
	}
	if p.Verifier.AggregateStatus != summary.AggregateStatus || p.Verifier.Passed != uint64(summary.Passed) || p.Verifier.Warning != uint64(summary.Warning) || p.Verifier.Failed != uint64(summary.Failed) || p.Verifier.Skipped != uint64(summary.Skipped) {
		return zero, ErrUnavailable
	}
	for _, ref := range []DetailEvidenceControl{p.Report, p.Diff, p.Verifier.Report} {
		if !ref.PublicID.Valid {
			continue
		}
		if attempt == 0 {
			return zero, ErrUnavailable
		}
		var schema, kind, owner, hash string
		var created time.Time
		if q.QueryRowContext(ctx, verificationReportReferenceSQL, ref.PublicID.String).Scan(&schema, &kind, &owner, &hash, &created) != nil ||
			schema != "system-backup-evidence.v1" || kind != string(PreflightTask) || owner != task.PublicID || hash != ref.SHA256.String || created.Before(attemptStart) {
			return zero, ErrUnavailable
		}
	}
	if p.ValidityReason == "valid" && (task.Status != "succeeded" || p.Mode != "production_readonly" || !p.Report.PublicID.Valid || summary.Failed > 0) {
		return zero, ErrUnavailable
	}
	summary.ReportEvidence = verificationEvidence(p.Verifier.Report)
	return contract.PreflightDetailResource{
		SchemaVersion: "system-backup-preflight-detail.v1", Task: task, Execution: execution,
		Source:          contract.SourceArtifactReference{SourceArtifactType: p.Source.Type, SourcePublicID: p.Source.PublicID},
		SourceChecksums: contract.NullableArtifactChecksumSet{Manifest: verificationString(p.Source.Checksums.Manifest), Acceptance: verificationString(p.Source.Checksums.Acceptance), Catalog: verificationString(p.Source.Checksums.Catalog)},
		PreflightMode:   p.Mode, TargetProfile: p.TargetProfile, RestoreTargetConfigHash: p.TargetConfigSHA, ArtifactCompatibility: p.Compatibility,
		ReportEvidence: verificationEvidence(p.Report), DiffEvidence: verificationEvidence(p.Diff), ReportValidityReason: p.ValidityReason, VerifierSummary: summary,
	}, nil
}
