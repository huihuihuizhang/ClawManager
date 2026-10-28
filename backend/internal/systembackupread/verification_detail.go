package systembackupread

import (
	"context"
	"database/sql"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

// Verification details describe the recorded before/after observation of this
// verification. They do not assert that its artifact or report is usable now.
// Every contributing query runs before the existing final authority check.
func (r *Reader) ReadVerificationDetail(ctx context.Context, publicID string) (contract.ArtifactVerificationDetailResource, error) {
	return readTaskCheckEvidenceControlInTransaction(ctx, r, VerificationTask, publicID,
		func(ctx context.Context, q detailReadSQL, snapshot TaskCheckEvidenceControlSnapshot) (contract.ArtifactVerificationDetailResource, error) {
			return buildVerificationDetail(ctx, q, snapshot)
		})
}

func (s *Service) ReadVerificationDetailDTO(ctx context.Context, publicID string) (contract.ArtifactVerificationDetailResource, error) {
	if s == nil || s.reader == nil {
		return contract.ArtifactVerificationDetailResource{}, ErrDenied
	}
	return s.reader.ReadVerificationDetail(ctx, publicID)
}

const verificationTaskTimesSQL = "SELECT row_version,heartbeat_at,next_reconcile_at,started_at,finished_at FROM system_backup_v2_artifact_verifications WHERE origin_installation_id=? AND public_id=?"
const verificationReportReferenceSQL = "SELECT schema_version,owner_target_type,owner_target_public_id,content_checksum,created_at FROM system_backup_v2_evidence WHERE public_id=?"

func buildVerificationDetail(ctx context.Context, q detailReadSQL, snapshot TaskCheckEvidenceControlSnapshot) (contract.ArtifactVerificationDetailResource, error) {
	var zero contract.ArtifactVerificationDetailResource
	detail := snapshot.checks.detail
	v, ok := detail.Verification()
	if !ok || detail.execution.task.Kind != VerificationTask || ctx == nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	header := detail.execution.task
	base, err := ProjectTask(header)
	if err != nil {
		return zero, err
	}
	var rowVersion uint64
	var heartbeat, reconcile, started, finished sql.NullTime
	if q.QueryRowContext(ctx, verificationTaskTimesSQL, header.InstallationID, header.PublicID).
		Scan(&rowVersion, &heartbeat, &reconcile, &started, &finished) != nil || rowVersion != header.RowVersion {
		return zero, ErrUnavailable
	}
	for _, value := range []sql.NullTime{heartbeat, reconcile, started, finished} {
		if value.Valid && (value.Time.IsZero() || value.Time.Year() < 1 || value.Time.Year() > 9999) {
			return zero, ErrUnavailable
		}
	}
	if started.Valid && started.Time.Before(header.CreatedAt) || finished.Valid &&
		(finished.Time.Before(header.CreatedAt) || started.Valid && finished.Time.Before(started.Time)) {
		return zero, ErrUnavailable
	}
	// Source type/ID and the observed checksums are the task's immutable
	// historical reference, already validated by the control reader. Current
	// source availability is outside this DTO; do not replace its before/after
	// facts by querying today's backup/import lifecycle or provider.
	execution, current, currentCreated, err := verificationExecution(detail.execution)
	if err != nil {
		return zero, err
	}
	var progress time.Time
	if execution.LastBusinessProgressAt != nil {
		progress, err = time.Parse(time.RFC3339Nano, *execution.LastBusinessProgressAt)
		if err != nil {
			return zero, ErrUnavailable
		}
	}
	summary := contract.VerifierSummary{AggregateStatus: "skipped"}
	for _, check := range snapshot.checks.checks {
		if check.AttemptNumber != current {
			continue
		}
		// A committed owner check is business progress even when verification
		// runs without a Kubernetes Job. Task heartbeats never enter this value.
		if check.CheckedAt.After(progress) {
			progress = check.CheckedAt
		}
		switch check.Status {
		case "passed":
			summary.Passed++
		case "warning":
			summary.Warning++
		case "failed":
			summary.Failed++
		case "skipped":
			summary.Skipped++
		default:
			return zero, ErrUnavailable
		}
	}
	if !progress.IsZero() {
		execution.LastBusinessProgressAt = verificationTime(sql.NullTime{Time: progress, Valid: true})
	}
	switch {
	case summary.Failed > 0:
		summary.AggregateStatus = "failed"
	case summary.Warning > 0:
		summary.AggregateStatus = "warning"
	case summary.Passed > 0:
		summary.AggregateStatus = "passed"
	}
	// Persisted aggregate columns are a consistency check, not a substitute for
	// owner-submitted check rows or a sum of all historical attempts.
	if v.Verifier.AggregateStatus != summary.AggregateStatus || v.Verifier.Passed != uint64(summary.Passed) ||
		v.Verifier.Warning != uint64(summary.Warning) || v.Verifier.Failed != uint64(summary.Failed) || v.Verifier.Skipped != uint64(summary.Skipped) {
		return zero, ErrUnavailable
	}
	if v.Scope != "full" && !v.UsableBefore && v.UsableAfter {
		return zero, ErrUnavailable
	}
	refs := make(map[string]string)
	for _, ref := range []DetailEvidenceControl{v.HealthReport, v.Verifier.Report} {
		if !ref.PublicID.Valid {
			continue
		}
		id, digest := ref.PublicID.String, ref.SHA256.String
		if old, exists := refs[id]; exists {
			if old != digest {
				return zero, ErrUnavailable
			}
			continue
		}
		if current == 0 {
			return zero, ErrUnavailable
		}
		var evidenceSchema, ownerKind, ownerID, contentHash string
		var created time.Time
		if q.QueryRowContext(ctx, verificationReportReferenceSQL, id).
			Scan(&evidenceSchema, &ownerKind, &ownerID, &contentHash, &created) != nil ||
			evidenceSchema != "system-backup-evidence.v1" || ownerKind != string(VerificationTask) || ownerID != header.PublicID ||
			contentHash != digest || created.IsZero() || created.Before(currentCreated) {
			return zero, ErrUnavailable
		}
		refs[id] = digest
	}
	summary.ReportEvidence = verificationEvidence(v.Verifier.Report)
	return contract.ArtifactVerificationDetailResource{
		SchemaVersion: "system-backup-artifact-verification-detail.v1",
		Task: contract.Task{
			SchemaVersion: base.SchemaVersion, PublicID: base.PublicID, OriginInstallationID: base.OriginInstallationID,
			TaskType: string(base.TaskType), ActorType: base.ActorType, ActorID: base.ActorID, Endpoint: base.Endpoint,
			IdempotencyKey: base.IdempotencyKey, RequestHash: base.RequestHash, RequestID: base.RequestID, RetryOfPublicID: base.RetryOfPublicID,
			Status: base.Status, PendingReason: base.PendingReason, AttentionReason: base.AttentionReason, CanCancel: base.CanCancel,
			ConfigVersion: int64(base.ConfigVersion), Retryable: base.Retryable, FailureCategory: base.FailureCategory,
			RowVersion: int64(base.RowVersion), DeadlineAt: base.DeadlineAt, CreatedAt: base.CreatedAt, UpdatedAt: base.UpdatedAt,
			HeartbeatAt: verificationTime(heartbeat), NextReconcileAt: verificationTime(reconcile),
			StartedAt: verificationTime(started), FinishedAt: verificationTime(finished),
			// Failure text is deliberately redacted; the typed failure category
			// above remains available without selecting raw owner diagnostics.
			FailureMessage: nil,
		},
		Execution: execution, VerificationScope: v.Scope,
		Source: contract.SourceArtifactReference{SourceArtifactType: v.Source.Type, SourcePublicID: v.Source.PublicID},
		ObservedChecksums: contract.NullableArtifactChecksumSet{
			Manifest: verificationString(v.Checksums.Manifest), Index: verificationString(v.Checksums.Index), Marker: verificationString(v.Checksums.Marker),
			Acceptance: verificationString(v.Checksums.Acceptance), Catalog: verificationString(v.Checksums.Catalog),
		},
		HealthReportEvidence: verificationEvidence(v.HealthReport), ArtifactStateBefore: verificationString(v.StateBefore), ArtifactStateAfter: verificationString(v.StateAfter),
		UsableBefore: v.UsableBefore, UsableAfter: v.UsableAfter, UnusableReasonBefore: v.UnusableReasonBefore,
		UnusableReasonAfter: v.UnusableReasonAfter, DecisionReason: v.DecisionReason, VerifierSummary: summary,
	}, nil
}

func verificationExecution(snapshot TaskExecutionSnapshot) (contract.ExecutionProjection, uint64, time.Time, error) {
	var result contract.ExecutionProjection
	var current uint64
	var created time.Time
	for _, attempt := range snapshot.attempts {
		if attempt.Phase != "verify" || !validExecutionNumber(attempt.Number) {
			return result, 0, created, ErrUnavailable
		}
		if attempt.Number > current {
			current, created = attempt.Number, attempt.CreatedAt
		}
	}
	if current == 0 {
		return result, 0, created, nil
	}
	number, phase := int64(current), "verify"
	result.CurrentAttemptNumber, result.CurrentPhase = &number, &phase
	var jobs int
	var progress time.Time
	for _, job := range snapshot.jobs {
		if job.AttemptNumber != current {
			continue
		}
		jobs++
		generation := int64(job.Generation)
		result.JobGeneration = &generation
		if job.BusinessProgressAt.Valid && job.BusinessProgressAt.Time.After(progress) {
			progress = job.BusinessProgressAt.Time
		}
	}
	// A singular generation does not identify multiple parallel Job units.
	if jobs != 1 {
		result.JobGeneration = nil
	}
	if !progress.IsZero() {
		result.LastBusinessProgressAt = verificationTime(sql.NullTime{Time: progress, Valid: true})
	}
	return result, current, created, nil
}

func verificationString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	copy := value.String
	return &copy
}
func verificationTime(value sql.NullTime) *string {
	if !value.Valid {
		return nil
	}
	text := value.Time.UTC().Format(time.RFC3339Nano)
	return &text
}
func verificationEvidence(ref DetailEvidenceControl) *contract.EvidenceReference {
	if !ref.PublicID.Valid {
		return nil
	}
	return &contract.EvidenceReference{PublicID: ref.PublicID.String, SHA256: ref.SHA256.String}
}
