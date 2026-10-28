package systembackupread

import (
	"context"
	"database/sql"
	"regexp"
	"time"
)

// TaskAttempt and TaskJobObservation are private-read contributions, not wire
// resources. They omit failure text, certificates, relay identity references,
// command slots, provider payloads and resource inventories.
type TaskAttempt struct {
	Kind                           TaskKind
	PublicID                       string
	Number                         uint64
	Phase, Status, FailureCategory string
	RowVersion                     uint64
	StartedAt, FinishedAt          sql.NullTime
	CreatedAt, UpdatedAt           time.Time
}

func (TaskAttempt) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type TaskJobObservation struct {
	InstallationID                                     string
	Kind                                               TaskKind
	PublicID                                           string
	AttemptNumber                                      uint64
	Phase, JobUnitKey, JobUID                          string
	Generation, AcceptedSequence                       uint64
	AcceptedBodySHA256, ObservedStatus                 sql.NullString
	ObservedAt                                         sql.NullTime
	ProgressSequence                                   uint64
	ProgressDigestSHA256                               sql.NullString
	BusinessProgressAt                                 sql.NullTime
	RowVersion                                         uint64
	RelayBoundAt, RelayExpiresAt, CreatedAt, UpdatedAt time.Time
}

func (TaskJobObservation) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// TaskExecutionSnapshot preserves all attempts and all current Job units.
// Multiple capture units/phases may coexist: it deliberately does not invent a
// single current phase/generation or use heartbeats as business progress.
type TaskExecutionSnapshot struct {
	task     TaskHeader
	attempts []TaskAttempt
	jobs     []TaskJobObservation
}

func (TaskExecutionSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (s TaskExecutionSnapshot) Task() TaskHeader           { return s.task }
func (s TaskExecutionSnapshot) Attempts() []TaskAttempt {
	return append([]TaskAttempt{}, s.attempts...)
}
func (s TaskExecutionSnapshot) JobObservations() []TaskJobObservation {
	return append([]TaskJobObservation{}, s.jobs...)
}

// Complete detail builders must use this boundary, rather than attach owner
// results after ReadTaskExecution has committed a separately observed snapshot.
func readTaskExecutionInTransaction[T any](ctx context.Context, r *Reader, kind TaskKind, publicID string,
	build func(context.Context, detailReadSQL, TaskExecutionSnapshot) (T, error)) (T, error) {
	if build == nil {
		var zero T
		return zero, ErrUnavailable
	}
	return readTaskInTransaction(ctx, r, kind, publicID,
		func(ctx context.Context, q detailReadSQL, task TaskHeader) (T, error) {
			var zero T
			snapshot, err := readTaskExecution(ctx, q, task)
			if err != nil {
				return zero, err
			}
			return build(ctx, q, snapshot)
		})
}

func (r *Reader) ReadTaskExecution(ctx context.Context, kind TaskKind, publicID string) (TaskExecutionSnapshot, error) {
	return readTaskExecutionInTransaction(ctx, r, kind, publicID,
		func(_ context.Context, _ detailReadSQL, s TaskExecutionSnapshot) (TaskExecutionSnapshot, error) {
			return s, nil
		})
}

// Bound each complete contribution independently. An extra row rejects the whole
// authorized snapshot; historical execution records are never silently truncated.
const maxTaskExecutionRows = 10000

const taskAttemptColumns = "a.target_type,a.target_public_id,a.attempt_no,a.phase,a.status,a.failure_category,a.row_version,a.started_at,a.finished_at,a.created_at,a.updated_at"
const taskJobColumns = "schema_version,origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key,job_uid,job_generation,last_accepted_sequence,last_accepted_body_sha256,last_observed_status,last_observed_at,progress_sequence,progress_digest_sha256,last_business_progress_at,row_version,relay_identity_bound_at,relay_identity_expires_at,created_at,updated_at"
const taskJobsSQL = "SELECT " + taskJobColumns + " FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type=? AND target_public_id=? ORDER BY attempt_no,phase,job_unit_key LIMIT 10001"

func taskAttemptsSQL(table taskTable) string {
	// Attempts have no installation column. Rejoin the already authorized task
	// at this transaction snapshot before using its globally unique public ID.
	return "SELECT " + taskAttemptColumns + " FROM system_backup_v2_attempts AS a JOIN " + table.name +
		" AS t ON a.target_public_id=t.public_id AND a.target_type=t.task_type WHERE t.origin_installation_id=? AND t.public_id=? AND a.target_type=? ORDER BY a.attempt_no,a.phase LIMIT 10001"
}

type taskAttemptKey struct {
	number uint64
	phase  string
}
type taskJobKey struct {
	attempt taskAttemptKey
	unit    string
}

var taskJobUnitPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:-]{0,127}$`)
var taskJobStatusPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func readTaskExecution(ctx context.Context, q detailReadSQL, task TaskHeader) (TaskExecutionSnapshot, error) {
	var zero TaskExecutionSnapshot
	table, ok := taskTables[task.Kind]
	if !ok || !installationID.MatchString(task.InstallationID) || !validTaskProjection(task, table) {
		return zero, ErrUnavailable
	}
	s := TaskExecutionSnapshot{task: task, attempts: []TaskAttempt{}, jobs: []TaskJobObservation{}}
	attempts := make(map[taskAttemptKey]TaskAttempt)
	rows, err := q.QueryContext(ctx, taskAttemptsSQL(table), task.InstallationID, task.PublicID, string(task.Kind))
	if err != nil {
		return zero, ErrUnavailable
	}
	for rows.Next() {
		if len(s.attempts) == maxTaskExecutionRows {
			rows.Close()
			return zero, ErrUnavailable
		}
		var a TaskAttempt
		err = rows.Scan(&a.Kind, &a.PublicID, &a.Number, &a.Phase, &a.Status, &a.FailureCategory, &a.RowVersion, &a.StartedAt, &a.FinishedAt, &a.CreatedAt, &a.UpdatedAt)
		key := taskAttemptKey{a.Number, a.Phase}
		_, duplicate := attempts[key]
		if err != nil || duplicate || !validTaskAttempt(a, task) {
			rows.Close()
			return zero, ErrUnavailable
		}
		attempts[key] = a
		s.attempts = append(s.attempts, a)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return zero, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	rows, err = q.QueryContext(ctx, taskJobsSQL, task.InstallationID, string(task.Kind), task.PublicID)
	if err != nil {
		return zero, ErrUnavailable
	}
	units, uids := make(map[taskJobKey]bool), make(map[string]bool)
	for rows.Next() {
		if len(s.jobs) == maxTaskExecutionRows {
			rows.Close()
			return zero, ErrUnavailable
		}
		var j TaskJobObservation
		var schema string
		err = rows.Scan(&schema, &j.InstallationID, &j.Kind, &j.PublicID, &j.AttemptNumber, &j.Phase, &j.JobUnitKey, &j.JobUID, &j.Generation, &j.AcceptedSequence, &j.AcceptedBodySHA256, &j.ObservedStatus, &j.ObservedAt, &j.ProgressSequence, &j.ProgressDigestSHA256, &j.BusinessProgressAt, &j.RowVersion, &j.RelayBoundAt, &j.RelayExpiresAt, &j.CreatedAt, &j.UpdatedAt)
		a, exists := attempts[taskAttemptKey{j.AttemptNumber, j.Phase}]
		key := taskJobKey{taskAttemptKey{j.AttemptNumber, j.Phase}, j.JobUnitKey}
		if err != nil || schema != "system-backup-job-observation.v1" || !exists || units[key] || uids[j.JobUID] || !validTaskJob(j, a, task) {
			rows.Close()
			return zero, ErrUnavailable
		}
		units[key], uids[j.JobUID] = true, true
		s.jobs = append(s.jobs, j)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return zero, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	return s, nil
}

func validTaskAttempt(a TaskAttempt, task TaskHeader) bool {
	if a.Kind != task.Kind || a.PublicID != task.PublicID || !validExecutionNumber(a.Number) || a.Number > 1<<32-1 || !validExecutionNumber(a.RowVersion) ||
		!validTaskPhase(a.Kind, a.Phase) || a.CreatedAt.IsZero() || a.CreatedAt.Before(task.CreatedAt) || a.UpdatedAt.Before(a.CreatedAt) ||
		!operationFailureCategory(a.FailureCategory) {
		return false
	}
	if a.StartedAt.Valid && (a.StartedAt.Time.IsZero() || a.StartedAt.Time.Before(a.CreatedAt)) ||
		a.FinishedAt.Valid && (a.FinishedAt.Time.IsZero() || a.FinishedAt.Time.Before(a.CreatedAt) || a.StartedAt.Valid && a.FinishedAt.Time.Before(a.StartedAt.Time)) {
		return false
	}
	if (a.Status == "preparing") != !a.StartedAt.Valid {
		return false
	}
	switch a.Status {
	case "preparing", "running":
		return a.FailureCategory == "none" && !a.FinishedAt.Valid
	case "sealed":
		return a.Kind == BackupTask && (a.Phase == "capture" || a.Phase == "secret_capture") && a.FailureCategory == "none" && a.FinishedAt.Valid
	case "succeeded":
		return !(a.Kind == BackupTask && (a.Phase == "capture" || a.Phase == "secret_capture")) && a.FailureCategory == "none" && a.FinishedAt.Valid
	case "failed":
		return a.FailureCategory != "none" && a.FailureCategory != "canceled_by_actor" && a.FailureCategory != "canceled_by_shutdown" && a.FinishedAt.Valid
	case "canceled":
		return (a.FailureCategory == "canceled_by_actor" || a.FailureCategory == "canceled_by_shutdown") && a.FinishedAt.Valid
	default:
		return false
	}
}
func validExecutionNumber(n uint64) bool { return n > 0 && n <= maxJSONSafeInteger }
func validTaskPhase(kind TaskKind, phase string) bool {
	switch kind {
	case BackupTask:
		return phase == "capture" || phase == "secret_capture" || phase == "publish"
	case DrillTask:
		return phase == "restore" || phase == "normalize" || phase == "verify"
	case PreflightTask:
		return phase == "preflight"
	case VerificationTask:
		return phase == "verify"
	default:
		return false
	}
}
func validTaskJob(j TaskJobObservation, a TaskAttempt, task TaskHeader) bool {
	if j.InstallationID != task.InstallationID || j.Kind != task.Kind || j.PublicID != task.PublicID ||
		!validExecutionNumber(j.Generation) || !validExecutionNumber(j.RowVersion) || j.AcceptedSequence > maxJSONSafeInteger || j.ProgressSequence > j.AcceptedSequence ||
		!taskJobUnitPattern.MatchString(j.JobUnitKey) || !taskUUID.MatchString(j.JobUID) || j.CreatedAt.IsZero() || j.CreatedAt.Before(a.CreatedAt) || j.UpdatedAt.Before(j.CreatedAt) ||
		j.RelayBoundAt.Before(j.CreatedAt) || !j.RelayExpiresAt.After(j.RelayBoundAt) {
		return false
	}
	if j.AcceptedSequence == 0 {
		if j.AcceptedBodySHA256.Valid || j.ObservedStatus.Valid || j.ObservedAt.Valid {
			return false
		}
	} else if !j.AcceptedBodySHA256.Valid || !taskHash.MatchString(j.AcceptedBodySHA256.String) || !j.ObservedStatus.Valid ||
		!taskJobStatusPattern.MatchString(j.ObservedStatus.String) || !j.ObservedAt.Valid || j.ObservedAt.Time.IsZero() || j.ObservedAt.Time.Before(j.RelayBoundAt) {
		return false
	}
	if j.ProgressSequence == 0 {
		return !j.ProgressDigestSHA256.Valid && !j.BusinessProgressAt.Valid
	}
	return j.ProgressDigestSHA256.Valid && taskHash.MatchString(j.ProgressDigestSHA256.String) && j.BusinessProgressAt.Valid &&
		!j.BusinessProgressAt.Time.IsZero() && !j.BusinessProgressAt.Time.After(j.ObservedAt.Time)
}
