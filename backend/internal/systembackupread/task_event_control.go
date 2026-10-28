package systembackupread

import (
	"context"
	"database/sql"
	"regexp"
	"time"
)

// TaskEventControl contains private pagination and structured event metadata.
// The public DTO builder reads the persisted, already-redacted message in the
// same authorized transaction, as required by the v12 EventResource contract.
type TaskEventControl struct {
	ID                                    uint64 // Internal pagination identity.
	InstallationID                        string
	Kind                                  TaskKind
	PublicID, EventType, Level            string
	TaskStatus                            sql.NullString
	DetailsPresent                        bool
	PreviousStatus, CurrentStatus, Reason sql.NullString
	AttemptNumber                         sql.Null[uint64]
	OperationPublicID, EvidencePublicID   sql.NullString
	Truncated                             sql.NullBool
	OriginalSize                          sql.Null[uint64]
	ContentHash, RequestID                sql.NullString
	CreatedAt                             time.Time
}

func (TaskEventControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type TaskEventPageRequest struct {
	InstallationID     string
	Kind               TaskKind
	PublicID           string
	Limit              int
	CutoffID, BeforeID uint64
	BeforeCreatedAt    time.Time
}

type TaskEventControlPage struct {
	task            TaskHeader
	events          []TaskEventControl
	installation    string
	cutoff, before  uint64
	beforeCreatedAt time.Time
	hasMore         bool
	consistency     string
}

func (TaskEventControlPage) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (p TaskEventControlPage) Task() TaskHeader           { return p.task }
func (p TaskEventControlPage) Events() []TaskEventControl {
	return append([]TaskEventControl{}, p.events...)
}
func (p TaskEventControlPage) HasMore() bool       { return p.hasMore }
func (p TaskEventControlPage) Consistency() string { return p.consistency }

type TaskEventControlResult struct {
	Page       TaskEventControlPage
	NextCursor string
}

func (TaskEventControlResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

const taskEventControlColumns = "id,schema_version,origin_installation_id,target_type,target_public_id,event_type,level,task_status,details_present,detail_previous_status,detail_current_status,detail_reason,detail_attempt_number,detail_operation_public_id,detail_evidence_public_id,detail_truncated,detail_original_size,detail_content_hash,request_id,created_at"
const taskEventCutoffSQL = "SELECT COALESCE(MAX(id),0) FROM system_backup_v2_events WHERE origin_installation_id=? AND target_type=? AND target_public_id=?"

func taskEventControlSQL(continuation bool) string {
	query := "SELECT " + taskEventControlColumns + " FROM system_backup_v2_events WHERE origin_installation_id=? AND target_type=? AND target_public_id=? AND id<=?"
	if continuation {
		query += " AND (created_at<? OR (created_at=? AND id<?))"
	}
	return query + " ORDER BY created_at DESC,id DESC LIMIT ?"
}

// Pin an authenticated cursor's installation during initial authorization,
// before reading even the task row. The task still comes from current authority,
// never from an installation identifier selected by the HTTP request.
type taskEventPageScope struct {
	base         ScopeProvider
	installation string
}

func (s taskEventPageScope) AuthorizeRead(ctx context.Context, tx *sql.Tx) (string, error) {
	installation, err := s.base.AuthorizeRead(ctx, tx)
	if err != nil {
		return "", err
	}
	if s.installation != "" && s.installation != installation {
		return "", ErrDenied
	}
	return installation, nil
}
func (s taskEventPageScope) RecheckRead(ctx context.Context, tx *sql.Tx, installation string) error {
	return s.base.RecheckRead(ctx, tx, installation)
}

func validTaskEventRequest(r TaskEventPageRequest) bool {
	table, ok := taskTables[r.Kind]
	if !ok || !validDetailPublicID(r.PublicID, table.prefix) || r.Limit < 1 || r.Limit > 500 {
		return false
	}
	if r.CutoffID == 0 {
		return r.InstallationID == "" && r.BeforeID == 0 && r.BeforeCreatedAt.IsZero()
	}
	return installationID.MatchString(r.InstallationID) && r.BeforeID > 0 && r.BeforeID <= r.CutoffID && validEventCursorTime(r.BeforeCreatedAt)
}

// The public event builder receives the task and event identities in this
// transaction and reads persisted messages before commit. Builder failure, cancellation and final revocation
// all discard its result through the existing task transaction boundary.
func readTaskEventControlInTransaction[T any](ctx context.Context, r *Reader, request TaskEventPageRequest,
	build func(context.Context, detailReadSQL, TaskEventControlPage) (T, error)) (T, error) {
	var zero T
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return zero, ErrDenied
	}
	if build == nil || !validTaskEventRequest(request) {
		return zero, ErrInvalid
	}
	pinned := &Reader{db: r.db, scope: taskEventPageScope{r.scope, request.InstallationID}}
	return readTaskInTransaction(ctx, pinned, request.Kind, request.PublicID,
		func(ctx context.Context, q detailReadSQL, task TaskHeader) (T, error) {
			page, err := readTaskEventControlPage(ctx, q, task, request)
			if err != nil {
				return zero, err
			}
			return build(ctx, q, page)
		})
}

func (r *Reader) ReadTaskEventControlPage(ctx context.Context, request TaskEventPageRequest) (TaskEventControlPage, error) {
	return readTaskEventControlInTransaction(ctx, r, request,
		func(_ context.Context, _ detailReadSQL, page TaskEventControlPage) (TaskEventControlPage, error) {
			return page, nil
		})
}

func (s *Service) ListTaskEventControl(ctx context.Context, kind TaskKind, publicID string, limit int, token string) (TaskEventControlResult, error) {
	if s == nil || s.reader == nil || s.cursor == nil {
		return TaskEventControlResult{}, ErrDenied
	}
	request := TaskEventPageRequest{Kind: kind, PublicID: publicID, Limit: limit}
	if token != "" {
		var err error
		request, err = s.cursor.DecodeTaskEvents(token, kind, publicID, limit)
		if err != nil {
			return TaskEventControlResult{}, err
		}
	}
	page, err := s.reader.ReadTaskEventControlPage(ctx, request)
	if err != nil {
		return TaskEventControlResult{}, err
	}
	result := TaskEventControlResult{Page: page}
	if page.hasMore {
		result.NextCursor, err = s.cursor.EncodeTaskEvents(request, page)
		if err != nil {
			return TaskEventControlResult{}, ErrUnavailable
		}
	}
	return result, nil
}

func readTaskEventControlPage(ctx context.Context, q detailReadSQL, task TaskHeader, request TaskEventPageRequest) (TaskEventControlPage, error) {
	var zero TaskEventControlPage
	page := TaskEventControlPage{task: task, installation: task.InstallationID, cutoff: request.CutoffID, events: []TaskEventControl{}, consistency: "stable_cutoff"}
	if page.cutoff == 0 {
		if err := q.QueryRowContext(ctx, taskEventCutoffSQL, task.InstallationID, string(task.Kind), task.PublicID).Scan(&page.cutoff); err != nil {
			return zero, ErrUnavailable
		}
		if page.cutoff == 0 {
			return page, nil
		}
	}
	args := []any{task.InstallationID, string(task.Kind), task.PublicID, page.cutoff}
	if request.BeforeID != 0 {
		args = append(args, request.BeforeCreatedAt, request.BeforeCreatedAt, request.BeforeID)
	}
	args = append(args, request.Limit+1)
	rows, err := q.QueryContext(ctx, taskEventControlSQL(request.BeforeID != 0), args...)
	if err != nil {
		return zero, ErrUnavailable
	}
	var previous *TaskEventControl
	seen := make(map[uint64]bool)
	for rows.Next() {
		var item TaskEventControl
		var schema string
		if err := rows.Scan(&item.ID, &schema, &item.InstallationID, &item.Kind, &item.PublicID, &item.EventType, &item.Level,
			&item.TaskStatus, &item.DetailsPresent, &item.PreviousStatus, &item.CurrentStatus, &item.Reason, &item.AttemptNumber,
			&item.OperationPublicID, &item.EvidencePublicID, &item.Truncated, &item.OriginalSize, &item.ContentHash, &item.RequestID, &item.CreatedAt); err != nil ||
			schema != "system-backup-event.v1" || seen[item.ID] || !validTaskEventControl(item, task) || item.ID > page.cutoff ||
			request.BeforeID != 0 && !eventPositionBefore(item.CreatedAt, item.ID, request.BeforeCreatedAt, request.BeforeID) ||
			previous != nil && !eventPositionBefore(item.CreatedAt, item.ID, previous.CreatedAt, previous.ID) {
			rows.Close()
			return zero, ErrUnavailable
		}
		seen[item.ID] = true
		if len(page.events) == request.Limit {
			page.hasMore = true
			break
		}
		page.events = append(page.events, item)
		previous = &page.events[len(page.events)-1]
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return zero, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	if page.hasMore {
		last := page.events[len(page.events)-1]
		page.before, page.beforeCreatedAt = last.ID, last.CreatedAt
	}
	return page, nil
}

var taskDiagnosticEvent = regexp.MustCompile(`^diagnostic\.[a-d]\.[a-z0-9_-]{1,64}$`)
var taskEventReason = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

func validTaskEventControl(e TaskEventControl, task TaskHeader) bool {
	table, ok := taskTables[task.Kind]
	if !ok || e.ID == 0 || e.InstallationID != task.InstallationID || e.Kind != task.Kind || e.PublicID != task.PublicID ||
		!validEventCursorTime(e.CreatedAt) || e.CreatedAt.Before(task.CreatedAt) || !statusSet("info", "warning", "error", "critical")[e.Level] ||
		e.TaskStatus.Valid && !table.status[e.TaskStatus.String] || e.RequestID.Valid && (len(e.RequestID.String) == 0 || len(e.RequestID.String) > 128 || !taskToken.MatchString(e.RequestID.String)) {
		return false
	}
	if !statusSet("task_status_changed", "attempt_started", "attempt_finished", "gate_changed", "participant_changed", "artifact_committed", "artifact_health_changed", "external_action_changed", "evidence_changed", "log_persistence_changed", "provider_capability_changed", "dependency_health_changed", "catalog_scan_changed", "catalog_record_changed", "cleanup_changed", "ownership_resolved", "prune_changed", "promotion_changed", "operation_finished")[e.EventType] && !taskDiagnosticEvent.MatchString(e.EventType) {
		return false
	}
	if !e.DetailsPresent {
		return !e.PreviousStatus.Valid && !e.CurrentStatus.Valid && !e.Reason.Valid && !e.AttemptNumber.Valid && !e.OperationPublicID.Valid && !e.EvidencePublicID.Valid && !e.Truncated.Valid && !e.OriginalSize.Valid && !e.ContentHash.Valid
	}
	if e.PreviousStatus.Valid && !taskJobStatusPattern.MatchString(e.PreviousStatus.String) || e.CurrentStatus.Valid && !taskJobStatusPattern.MatchString(e.CurrentStatus.String) ||
		e.Reason.Valid && !taskEventReason.MatchString(e.Reason.String) || e.AttemptNumber.Valid && (e.AttemptNumber.V == 0 || e.AttemptNumber.V > 1<<32-1) ||
		e.OperationPublicID.Valid && !validDetailPublicID(e.OperationPublicID.String, "sop_") || e.EvidencePublicID.Valid && !validDetailPublicID(e.EvidencePublicID.String, "sev_") {
		return false
	}
	if e.Truncated.Valid && e.Truncated.Bool {
		return e.OriginalSize.Valid && e.ContentHash.Valid && taskHash.MatchString(e.ContentHash.String)
	}
	return !e.OriginalSize.Valid && !e.ContentHash.Valid
}

const taskEventCursorTimeFormat = "2006-01-02T15:04:05.000000Z"

func validEventCursorTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1000 && t.Year() <= 9999 && offset == 0 && t.Nanosecond()%1000 == 0
}
func eventPositionBefore(at time.Time, id uint64, before time.Time, beforeID uint64) bool {
	return at.Before(before) || at.Equal(before) && id < beforeID
}
