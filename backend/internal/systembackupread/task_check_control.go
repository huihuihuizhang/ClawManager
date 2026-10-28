package systembackupread

import (
	"context"
	"database/sql"
	"regexp"
	"time"
)

// TaskCheckControl contains only the persisted check identity and outcome.
// Expected/actual payloads and their digests are deliberately not selected.
// A reference is a stored binding, not proof of current evidence availability.
type TaskCheckControl struct {
	ID, AttemptNumber                       uint64
	InstallationID                          string
	Kind                                    TaskKind
	PublicID, Category, Mode, Code, Status  string
	SkipReason, WarningCode, Classification sql.NullString
	FailureCategory                         string
	Evidence                                DetailEvidenceControl
	CheckedAt, CreatedAt                    time.Time
}

func (TaskCheckControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// Preserve all original attempts; selecting a current report/attempt and
// deriving a public VerifierSummary remain responsibilities of the complete
// detail builder. Historical rows must never be silently summed as current.
type TaskCheckControlSnapshot struct {
	detail TaskDetailControlSnapshot
	checks []TaskCheckControl
}

func (TaskCheckControlSnapshot) MarshalJSON() ([]byte, error)        { return nil, ErrInvalid }
func (s TaskCheckControlSnapshot) Detail() TaskDetailControlSnapshot { return s.detail }
func (s TaskCheckControlSnapshot) Checks() []TaskCheckControl {
	return append([]TaskCheckControl{}, s.checks...)
}

func readTaskCheckControlInTransaction[T any](ctx context.Context, r *Reader, kind TaskKind, publicID string,
	build func(context.Context, detailReadSQL, TaskCheckControlSnapshot) (T, error)) (T, error) {
	if build == nil {
		var zero T
		return zero, ErrUnavailable
	}
	return readTaskDetailControlInTransaction(ctx, r, kind, publicID,
		func(ctx context.Context, q detailReadSQL, detail TaskDetailControlSnapshot) (T, error) {
			var zero T
			s, err := readTaskCheckControl(ctx, q, detail)
			if err != nil {
				return zero, err
			}
			return build(ctx, q, s)
		})
}

// Full detail assembly must use the transaction builder above, rather than
// append current Owner facts after this independent snapshot has committed.
func (r *Reader) ReadTaskCheckControl(ctx context.Context, kind TaskKind, publicID string) (TaskCheckControlSnapshot, error) {
	return readTaskCheckControlInTransaction(ctx, r, kind, publicID,
		func(_ context.Context, _ detailReadSQL, s TaskCheckControlSnapshot) (TaskCheckControlSnapshot, error) {
			return s, nil
		})
}

const maxTaskCheckControlRows = 10000
const taskCheckControlColumns = "id,schema_version,origin_installation_id,target_type,target_public_id,attempt_no,category,mode,check_code,status,skip_reason,evidence_public_id,evidence_sha256,warning_code,check_classification,failure_category,checked_at,created_at"
const taskCheckControlSQL = "SELECT " + taskCheckControlColumns + " FROM system_backup_v2_check_results WHERE origin_installation_id=? AND target_type=? AND target_public_id=? ORDER BY checked_at,id LIMIT 10001"

var taskCheckCode = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var taskCheckBusinessCategories = statusSet("users", "instances", "ai_gateway", "teams", "resources", "skill_hub", "control_plane")
var taskCheckClassifications = statusSet("validation", "permission", "capacity", "network_timeout", "rate_limited", "dependency", "transient_provider", "permanent_provider", "integrity", "coordination", "internal")

type taskCheckKey struct {
	attempt              uint64
	category, mode, code string
}

func taskCheckMode(detail TaskDetailControlSnapshot) string {
	switch detail.execution.task.Kind {
	case BackupTask:
		return "backup_validate"
	case DrillTask:
		return "restore_validate"
	case PreflightTask:
		return "preflight_diff"
	case VerificationTask:
		if v, ok := detail.Verification(); ok {
			if v.Scope == "health" {
				return "artifact_health"
			}
			if v.Scope == "full" {
				return "artifact_full"
			}
		}
	}
	return ""
}

func readTaskCheckControl(ctx context.Context, q detailReadSQL, detail TaskDetailControlSnapshot) (TaskCheckControlSnapshot, error) {
	var zero TaskCheckControlSnapshot
	task := detail.execution.task
	mode := taskCheckMode(detail)
	if mode == "" {
		return zero, ErrUnavailable
	}
	attempts := make(map[uint64]time.Time)
	for _, a := range detail.execution.attempts {
		if before, exists := attempts[a.Number]; !exists || a.CreatedAt.Before(before) {
			attempts[a.Number] = a.CreatedAt
		}
	}
	rows, err := q.QueryContext(ctx, taskCheckControlSQL, task.InstallationID, string(task.Kind), task.PublicID)
	if err != nil {
		return zero, ErrUnavailable
	}
	defer rows.Close()
	s := TaskCheckControlSnapshot{detail: detail, checks: []TaskCheckControl{}}
	keys := make(map[taskCheckKey]bool)
	ids := make(map[uint64]bool)
	var previous uint64
	var previousChecked time.Time
	for rows.Next() {
		if len(s.checks) == maxTaskCheckControlRows {
			return zero, ErrUnavailable
		}
		var c TaskCheckControl
		var schema string
		err := rows.Scan(&c.ID, &schema, &c.InstallationID, &c.Kind, &c.PublicID, &c.AttemptNumber,
			&c.Category, &c.Mode, &c.Code, &c.Status, &c.SkipReason, &c.Evidence.PublicID, &c.Evidence.SHA256,
			&c.WarningCode, &c.Classification, &c.FailureCategory, &c.CheckedAt, &c.CreatedAt)
		key := taskCheckKey{c.AttemptNumber, c.Category, c.Mode, c.Code}
		outOfOrder := c.CheckedAt.Before(previousChecked) || c.CheckedAt.Equal(previousChecked) && c.ID <= previous
		if err != nil || schema != "system-backup-check-result.v1" || c.ID == 0 || ids[c.ID] || outOfOrder || keys[key] || !validTaskCheckControl(c, task, mode, attempts) {
			return zero, ErrUnavailable
		}
		previous, previousChecked = c.ID, c.CheckedAt
		ids[c.ID], keys[key] = true, true
		s.checks = append(s.checks, c)
	}
	if err := rows.Err(); err != nil {
		return zero, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	return s, nil
}

func validTaskCheckControl(c TaskCheckControl, task TaskHeader, mode string, attempts map[uint64]time.Time) bool {
	created, exists := attempts[c.AttemptNumber]
	if !exists || c.AttemptNumber == 0 || c.AttemptNumber > 1<<32-1 || c.InstallationID != task.InstallationID || c.Kind != task.Kind || c.PublicID != task.PublicID ||
		c.Mode != mode || !taskCheckCode.MatchString(c.Code) || !validDetailEvidence(c.Evidence) || !operationFailureCategory(c.FailureCategory) ||
		c.CheckedAt.IsZero() || c.CreatedAt.IsZero() || c.CheckedAt.Before(created) || c.CheckedAt.Before(task.CreatedAt) || c.CreatedAt.Before(c.CheckedAt) {
		return false
	}
	if mode == "artifact_health" || mode == "artifact_full" {
		if c.Category != "artifact" {
			return false
		}
	} else if !taskCheckBusinessCategories[c.Category] && !(mode == "preflight_diff" && c.Category == "isolation") {
		return false
	}
	switch c.Status {
	case "passed":
		return !c.SkipReason.Valid && !c.WarningCode.Valid && !c.Classification.Valid && c.FailureCategory == "none"
	case "warning":
		return !c.SkipReason.Valid && c.WarningCode.Valid && taskCheckCode.MatchString(c.WarningCode.String) && !c.Classification.Valid && c.FailureCategory == "none"
	case "failed":
		return !c.SkipReason.Valid && !c.WarningCode.Valid && c.Classification.Valid && taskCheckClassifications[c.Classification.String] && c.FailureCategory != "none"
	case "skipped":
		return c.SkipReason.Valid && (c.SkipReason.String == "optional" || c.SkipReason.String == "not_applicable") && !c.WarningCode.Valid && !c.Classification.Valid && c.FailureCategory == "none"
	}
	return false
}
