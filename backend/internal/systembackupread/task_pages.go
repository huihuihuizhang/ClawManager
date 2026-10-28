package systembackupread

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"time"
)

var (
	ErrDenied      = errors.New("system_backup_read_denied")
	ErrInvalid     = errors.New("system_backup_read_invalid")
	ErrNotFound    = errors.New("system_backup_read_not_found")
	ErrUnavailable = errors.New("system_backup_read_unavailable")
)

// ScopeProvider must resolve the current caller's installation and
// system_backup.read permission in the same read transaction, then recheck
// that authority before it commits. Request fields never select an
// installation. There is deliberately no permissive/default provider.
type ScopeProvider interface {
	AuthorizeRead(context.Context, *sql.Tx) (string, error)
	RecheckRead(context.Context, *sql.Tx, string) error
}

type TaskKind string

const (
	BackupTask       TaskKind = "backup"
	DrillTask        TaskKind = "drill"
	PreflightTask    TaskKind = "preflight"
	VerificationTask TaskKind = "artifact_verify"
)

type taskTable struct {
	name   string
	prefix string
	status map[string]bool
}

var taskTables = map[TaskKind]taskTable{
	BackupTask:       {"system_backup_v2_backups", "sbk_", statusSet("pending", "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating", "publishing", "finalization_unknown", "canceling", "succeeded", "failed", "canceled")},
	DrillTask:        {"system_backup_v2_restore_drills", "sdr_", statusSet("pending", "preflighting", "provisioning", "restoring", "normalizing", "verifying", "canceling", "succeeded", "failed", "canceled")},
	PreflightTask:    {"system_backup_v2_preflights", "spf_", statusSet("pending", "running", "canceling", "succeeded", "failed", "canceled")},
	VerificationTask: {"system_backup_v2_artifact_verifications", "sav_", statusSet("pending", "running", "canceling", "succeeded", "failed", "canceled")},
}

func statusSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

var installationID = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var taskUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var taskHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var taskToken = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
var taskReason = regexp.MustCompile(`^[a-z_]+$`)

const taskProjectionColumns = "id,public_id,origin_installation_id,task_type,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,retry_of_public_id,status,pending_reason,attention_reason,can_cancel,config_version,retryable,failure_category,row_version,deadline_at,created_at,updated_at,schema_version"

// PageRequest is the already verified, internal keyset position. HTTP cursors
// must authenticate and bind InstallationID, Kind, Status, Limit, CutoffID and
// BeforeID before constructing it. Zero CutoffID starts a new page sequence.
type PageRequest struct {
	InstallationID string
	Kind           TaskKind
	Status         string
	Limit          int
	CutoffID       uint64
	BeforeID       uint64
}

// TaskHeader carries the common, non-secret Task contract fields. It omits
// config snapshots, failure messages, provider data and owner detail fields.
type TaskHeader struct {
	PublicID        string
	InstallationID  string
	Kind            TaskKind
	ActorType       string
	ActorID         string
	Endpoint        string
	IdempotencyKey  string
	RequestHash     string
	RequestID       string
	RetryOfPublicID sql.NullString
	Status          string
	PendingReason   string
	AttentionReason string
	CanCancel       bool
	ConfigVersion   uint64
	Retryable       bool
	FailureCategory string
	RowVersion      uint64
	DeadlineAt      time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ID              uint64 `json:"-"` // internal keyset position, never serialize directly
}

type TaskPage struct {
	Items          []TaskHeader
	InstallationID string `json:"-"`
	CutoffID       uint64 `json:"-"`
	BeforeID       uint64 `json:"-"`
	HasMore        bool
	Consistency    string
}

// Task headers and internal keyset metadata are never wire DTOs.
func (TaskHeader) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (TaskPage) MarshalJSON() ([]byte, error)   { return nil, ErrInvalid }

type Reader struct {
	db    *sql.DB
	scope ScopeProvider
}

func NewReader(db *sql.DB, scope ScopeProvider) (*Reader, error) {
	if db == nil || nilScope(scope) {
		return nil, ErrDenied
	}
	return &Reader{db: db, scope: scope}, nil
}

func (r *Reader) ListTasks(ctx context.Context, request PageRequest) (TaskPage, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return TaskPage{}, ErrDenied
	}
	table, ok := taskTables[request.Kind]
	if !ok || request.Limit < 1 || request.Limit > 500 ||
		request.Status != "" && !table.status[request.Status] ||
		request.CutoffID == 0 && (request.BeforeID != 0 || request.InstallationID != "") ||
		request.CutoffID != 0 && request.InstallationID == "" ||
		request.CutoffID != 0 && request.BeforeID > request.CutoffID {
		return TaskPage{}, ErrInvalid
	}
	// Read committed lets the final authorization check observe a revocation
	// made after the page query. The trusted provider may hold its authority
	// row lock through Commit to close the final-check race.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return TaskPage{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return TaskPage{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) ||
		request.InstallationID != "" && request.InstallationID != installation {
		return TaskPage{}, ErrDenied
	}
	cutoff := request.CutoffID
	if cutoff == 0 {
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM "+table.name+" WHERE origin_installation_id=?", installation).Scan(&cutoff); err != nil {
			return TaskPage{}, ErrUnavailable
		}
	}
	page := TaskPage{Items: []TaskHeader{}, InstallationID: installation, CutoffID: cutoff, Consistency: "stable_cutoff"}
	if request.Status != "" {
		page.Consistency = "eventual"
	}
	if cutoff == 0 {
		if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
			return TaskPage{}, scopeReadFailure(err)
		}
		if err := tx.Commit(); err != nil || ctx.Err() != nil {
			return TaskPage{}, ErrUnavailable
		}
		return page, nil
	}
	upper := cutoff + 1
	if request.BeforeID != 0 {
		upper = request.BeforeID
	} else if cutoff == ^uint64(0) {
		return TaskPage{}, ErrInvalid
	}
	query := taskPageSQL(table, request.Status != "")
	args := []any{installation, upper}
	if request.Status != "" {
		args = append(args, request.Status)
	}
	args = append(args, request.Limit+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return TaskPage{}, ErrUnavailable
	}
	previousID := upper
	for rows.Next() {
		item, err := scanTask(rows, request.Kind, table, installation)
		if err != nil {
			rows.Close()
			return TaskPage{}, ErrUnavailable
		}
		if item.ID >= previousID || item.ID > cutoff || request.Status != "" && item.Status != request.Status {
			rows.Close()
			return TaskPage{}, ErrUnavailable
		}
		previousID = item.ID
		if len(page.Items) == request.Limit {
			page.HasMore = true
			break
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return TaskPage{}, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return TaskPage{}, ErrUnavailable
	}
	if page.HasMore {
		page.BeforeID = page.Items[len(page.Items)-1].ID
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return TaskPage{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return TaskPage{}, ErrUnavailable
	}
	return page, nil
}

// Keep the trusted scope's cause for HTTP error mapping without exposing it
// in a response. Existing callers can still treat every rejection as denied.
func scopeReadFailure(err error) error {
	if err == nil {
		return ErrDenied
	}
	return errors.Join(ErrDenied, err)
}

type taskScanner interface{ Scan(...any) error }

func scanTask(row taskScanner, kind TaskKind, table taskTable, installation string) (TaskHeader, error) {
	var item TaskHeader
	var taskType string
	var schemaVersion string
	if err := row.Scan(&item.ID, &item.PublicID, &item.InstallationID, &taskType,
		&item.ActorType, &item.ActorID, &item.Endpoint, &item.IdempotencyKey, &item.RequestHash,
		&item.RequestID, &item.RetryOfPublicID, &item.Status, &item.PendingReason,
		&item.AttentionReason, &item.CanCancel, &item.ConfigVersion, &item.Retryable,
		&item.FailureCategory, &item.RowVersion, &item.DeadlineAt, &item.CreatedAt,
		&item.UpdatedAt, &schemaVersion); err != nil {
		return TaskHeader{}, err
	}
	item.Kind = kind
	if item.ID == 0 || item.InstallationID != installation || schemaVersion != "system-backup-task.v1" || taskType != string(kind) ||
		len(item.PublicID) != len(table.prefix)+36 || item.PublicID[:len(table.prefix)] != table.prefix ||
		!taskUUID.MatchString(item.PublicID[len(table.prefix):]) || !table.status[item.Status] ||
		item.ConfigVersion == 0 || item.RowVersion == 0 || item.DeadlineAt.IsZero() ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() || !validTaskProjection(item, table) {
		return TaskHeader{}, ErrUnavailable
	}
	return item, nil
}

func nilScope(scope ScopeProvider) bool {
	if scope == nil {
		return true
	}
	v := reflect.ValueOf(scope)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface:
		return v.IsNil()
	}
	return false
}

func validTaskProjection(item TaskHeader, table taskTable) bool {
	if item.ActorType != "admin" && item.ActorType != "system" {
		return false
	}
	if len(item.ActorID) == 0 || len(item.ActorID) > 128 || len(item.Endpoint) == 0 || len(item.Endpoint) > 128 ||
		len(item.IdempotencyKey) < 16 || len(item.IdempotencyKey) > 128 || !taskToken.MatchString(item.IdempotencyKey) ||
		len(item.RequestID) == 0 || len(item.RequestID) > 128 || !taskToken.MatchString(item.RequestID) ||
		!taskHash.MatchString(item.RequestHash) || !taskReason.MatchString(item.PendingReason) ||
		!taskReason.MatchString(item.AttentionReason) || !taskReason.MatchString(item.FailureCategory) {
		return false
	}
	if item.RetryOfPublicID.Valid {
		id := item.RetryOfPublicID.String
		if len(id) != len(table.prefix)+36 || id[:len(table.prefix)] != table.prefix || !taskUUID.MatchString(id[len(table.prefix):]) {
			return false
		}
	}
	return true
}
