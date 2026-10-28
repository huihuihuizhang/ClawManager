package systembackupread

import (
	"context"
	"database/sql"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

// A drill detail describes this task's persisted execution and decision. It
// does not assert current source/provider health or authenticate B's target
// inventory. The contract exposes only the target config hash, cleanup summary
// and registered references; their bytes/download authority remain separate.
func (r *Reader) ReadDrillDetail(ctx context.Context, publicID string) (contract.DrillDetailResource, error) {
	return readTaskCheckEvidenceControlInTransaction(ctx, r, DrillTask, publicID, buildDrillDetail)
}

func (s *Service) ReadDrillDetailDTO(ctx context.Context, publicID string) (contract.DrillDetailResource, error) {
	if s == nil || s.reader == nil {
		return contract.DrillDetailResource{}, ErrDenied
	}
	return s.reader.ReadDrillDetail(ctx, publicID)
}

const drillTaskTimesSQL = "SELECT row_version,heartbeat_at,next_reconcile_at,started_at,finished_at FROM system_backup_v2_restore_drills WHERE origin_installation_id=? AND public_id=?"

func buildDrillDetail(ctx context.Context, q detailReadSQL, snapshot TaskCheckEvidenceControlSnapshot) (contract.DrillDetailResource, error) {
	var zero contract.DrillDetailResource
	detail := snapshot.checks.detail
	d, ok := detail.Drill()
	if !ok || detail.execution.task.Kind != DrillTask || ctx == nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	header := detail.execution.task
	base, err := ProjectTask(header)
	if err != nil {
		return zero, err
	}
	var version uint64
	var heartbeat, reconcile, started, finished sql.NullTime
	if q.QueryRowContext(ctx, drillTaskTimesSQL, header.InstallationID, header.PublicID).
		Scan(&version, &heartbeat, &reconcile, &started, &finished) != nil || version != header.RowVersion {
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
	execution, current, reportStart, err := drillExecution(detail.execution)
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
	if d.Verifier.AggregateStatus != summary.AggregateStatus || d.Verifier.Passed != uint64(summary.Passed) ||
		d.Verifier.Warning != uint64(summary.Warning) || d.Verifier.Failed != uint64(summary.Failed) || d.Verifier.Skipped != uint64(summary.Skipped) {
		return zero, ErrUnavailable
	}
	// Preflight/diff may predate the latest restore retry; they are task-bound
	// historical references. The verifier report must belong to this attempt,
	// not an older retry. Use the strictest cutoff when references are shared.
	type reportBinding struct {
		hash string
		at   time.Time
	}
	refs := map[string]reportBinding{}
	var ids []string
	for i, ref := range []DetailEvidenceControl{d.Preflight, d.Diff, d.Verifier.Report} {
		if !ref.PublicID.Valid {
			continue
		}
		cutoff := header.CreatedAt
		if i == 2 {
			if current == 0 || reportStart.IsZero() {
				return zero, ErrUnavailable
			}
			cutoff = reportStart
		}
		id, hash := ref.PublicID.String, ref.SHA256.String
		old, exists := refs[id]
		if exists {
			if old.hash != hash {
				return zero, ErrUnavailable
			}
			if cutoff.After(old.at) {
				old.at = cutoff
				refs[id] = old
			}
			continue
		}
		refs[id] = reportBinding{hash, cutoff}
		ids = append(ids, id)
	}
	for _, id := range ids {
		var schema, kind, owner, hash string
		var created time.Time
		if q.QueryRowContext(ctx, verificationReportReferenceSQL, id).Scan(&schema, &kind, &owner, &hash, &created) != nil ||
			schema != "system-backup-evidence.v1" || kind != string(DrillTask) || owner != header.PublicID ||
			hash != refs[id].hash || created.IsZero() || created.Before(refs[id].at) {
			return zero, ErrUnavailable
		}
	}
	summary.ReportEvidence = verificationEvidence(d.Verifier.Report)
	return contract.DrillDetailResource{
		SchemaVersion: "system-backup-drill-detail.v1",
		Task: contract.Task{
			SchemaVersion: base.SchemaVersion, PublicID: base.PublicID, OriginInstallationID: base.OriginInstallationID,
			TaskType: string(base.TaskType), ActorType: base.ActorType, ActorID: base.ActorID, Endpoint: base.Endpoint,
			IdempotencyKey: base.IdempotencyKey, RequestHash: base.RequestHash, RequestID: base.RequestID, RetryOfPublicID: base.RetryOfPublicID,
			Status: base.Status, PendingReason: base.PendingReason, AttentionReason: base.AttentionReason, CanCancel: base.CanCancel,
			ConfigVersion: int64(base.ConfigVersion), Retryable: base.Retryable, FailureCategory: base.FailureCategory,
			RowVersion: int64(base.RowVersion), DeadlineAt: base.DeadlineAt, CreatedAt: base.CreatedAt, UpdatedAt: base.UpdatedAt,
			HeartbeatAt: verificationTime(heartbeat), NextReconcileAt: verificationTime(reconcile),
			StartedAt: verificationTime(started), FinishedAt: verificationTime(finished), FailureMessage: nil,
		},
		Execution: execution, Source: contract.SourceArtifactReference{SourceArtifactType: d.Source.Type, SourcePublicID: d.Source.PublicID},
		SourceChecksums: contract.NullableArtifactChecksumSet{
			Manifest: verificationString(d.Source.Checksums.Manifest), Acceptance: verificationString(d.Source.Checksums.Acceptance),
			Catalog: verificationString(d.Source.Checksums.Catalog), Index: nil, Marker: nil,
		},
		TaskPurpose: d.Purpose, TargetProfile: d.TargetProfile, RestoreTargetConfigHash: d.TargetConfigSHA,
		CleanupPolicy: d.CleanupPolicy, CleanupStatus: d.CleanupStatus, CleanupFailureCode: d.CleanupFailure,
		PreflightEvidence: verificationEvidence(d.Preflight), DiffEvidence: verificationEvidence(d.Diff), VerifierSummary: summary,
		Consistency: verificationString(d.Consistency), AcceptanceEligible: d.Eligibility.Eligible,
		EligibilityReasonCodes: append([]string{}, d.Eligibility.Reasons...), EligibilityDecisionHash: verificationString(d.Eligibility.DecisionSHA),
	}, nil
}

// Attempt numbers span phases. Keep a singular phase/generation only when the
// latest attempt rows identify one; do not impose a guessed phase ordering or
// merge independent Job unit generations. Progress excludes old retries.
func drillExecution(snapshot TaskExecutionSnapshot) (contract.ExecutionProjection, uint64, time.Time, error) {
	return taskExecutionProjection(snapshot, DrillTask)
}

func taskExecutionProjection(snapshot TaskExecutionSnapshot, kind TaskKind) (contract.ExecutionProjection, uint64, time.Time, error) {
	var result contract.ExecutionProjection
	var current uint64
	var reportStart time.Time
	for _, a := range snapshot.attempts {
		if !validTaskPhase(kind, a.Phase) || !validExecutionNumber(a.Number) {
			return result, 0, reportStart, ErrUnavailable
		}
		if a.Number > current {
			current = a.Number
		}
	}
	if current == 0 {
		return result, 0, reportStart, nil
	}
	number := int64(current)
	result.CurrentAttemptNumber = &number
	var phase string
	var phases int
	for _, a := range snapshot.attempts {
		if a.Number != current {
			continue
		}
		phases++
		phase = a.Phase
		if a.CreatedAt.After(reportStart) {
			reportStart = a.CreatedAt
		}
	}
	if phases == 1 {
		result.CurrentPhase = &phase
	}
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
	if jobs != 1 || phases != 1 {
		result.JobGeneration = nil
	}
	if !progress.IsZero() {
		result.LastBusinessProgressAt = verificationTime(sql.NullTime{Time: progress, Valid: true})
	}
	return result, current, reportStart, nil
}
