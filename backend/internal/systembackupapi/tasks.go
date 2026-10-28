// Package systembackupapi connects the v12 task transport to an explicitly
// supplied application. It deliberately contains no default task/provider store.
package systembackupapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strconv"

	contract "clawreef/internal/systembackupcontract"
	"clawreef/internal/systembackupread"
)

// TaskApplication is the single deployment composition boundary. Implementations
// must authenticate the request with current session/installation/operate RBAC,
// strictly decode the reviewed owner DTO, apply its defaults/JCS hash, and check
// effective config, capacity and execution readiness BEFORE creating anything.
// CreateAndEnqueue must atomically persist the task, config snapshot and durable
// scheduler selection under the existing installation/actor/endpoint/key scope.
// Same-key retries return the original task, including after an unknown commit;
// they must not enqueue a second job. An in-memory wakeup is not durable enqueue.
// Reads authorize/recheck system_backup.read and build the complete reviewed
// detail in one transaction. A read ScopeProvider never authorizes a mutation.
// The request body stays opaque here until the missing owner requestBody
// contracts are supplied; accepting JSON syntax is not business admission.
type TaskApplication interface {
	CreateAndEnqueue(*http.Request, systembackupread.TaskKind, string, string, json.RawMessage) (systembackupread.TaskHeader, error)
	ReadBackup(*http.Request, string) (contract.BackupDetailResource, error)
	ReadPreflight(*http.Request, string) (contract.PreflightDetailResource, error)
}

// Error contains only a closed business code. Never put driver/provider errors,
// credentials, request bodies or authorization material in the public response.
type Error struct{ Code string }

type ExpiredTaskError struct{ PublicID, TerminalStatus, FailureCategory string }

func (*ExpiredTaskError) Error() string { return "system backup task idempotency expired" }
func (*ExpiredTaskError) Unwrap() error { return &Error{"idempotency_expired"} }

type taskRequestIDKey struct{}

func (e *Error) Error() string { return "system backup task application rejected" }

type Handler struct{ application TaskApplication }

func NewHandler(application TaskApplication) *Handler {
	if nilDependency(application) {
		application = nil
	}
	return &Handler{application: application}
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

var token = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func taskRoute(kind systembackupread.TaskKind) (path, endpoint, prefix string) {
	switch kind {
	case systembackupread.BackupTask:
		return "/api/v1/admin/system-backups", "createSystemBackup", "sbk_"
	case systembackupread.PreflightTask:
		return "/api/v1/admin/system-backup-preflights", "createSystemBackupPreflight", "spf_"
	default:
		return "", "", ""
	}
}

const maxTaskBody = 64 << 10 // transport bound; owner DTO may require a smaller one

func (h *Handler) Create(w http.ResponseWriter, r *http.Request, kind systembackupread.TaskKind, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	path, endpoint, _ := taskRoute(kind)
	if path == "" || h == nil || h.application == nil {
		writeError(w, requestID, nil)
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.URL.RawQuery != "" || len(keys) != 1 || !token.MatchString(keys[0]) || err != nil || contentType != "application/json" {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTaskBody))
	if err != nil {
		var size *http.MaxBytesError
		code := "validation_failed"
		if errors.As(err, &size) {
			code = "payload_too_large"
		}
		writeError(w, requestID, &Error{code})
		return
	}
	if r.Context().Err() != nil {
		writeError(w, requestID, nil)
		return
	}
	if !json.Valid(body) {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), taskRequestIDKey{}, requestID))
	task, err := h.application.CreateAndEnqueue(r, kind, endpoint, keys[0], json.RawMessage(body))
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	dto, err := systembackupread.ProjectTask(task)
	if err != nil || task.Kind != kind || task.Endpoint != endpoint || task.IdempotencyKey != keys[0] || r.Context().Err() != nil {
		// Creation may have committed. Do not retry, compensate or manufacture
		// a different ID here: retain the original body/key for application replay.
		writeError(w, requestID, nil)
		return
	}
	w.Header().Set("Location", path+"/"+dto.PublicID)
	w.Header().Set("Retry-After", "1")
	w.Header().Set("X-System-Backup-Data-Source", "live")
	writeJSON(w, http.StatusAccepted, dto)
}

func (h *Handler) Detail(w http.ResponseWriter, r *http.Request, kind systembackupread.TaskKind, id, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	_, _, prefix := taskRoute(kind)
	if prefix == "" || h == nil || h.application == nil {
		writeError(w, requestID, nil)
		return
	}
	if r.URL.RawQuery != "" || len(id) != len(prefix)+36 || id[:len(prefix)] != prefix || !uuid.MatchString(id[len(prefix):]) {
		writeError(w, requestID, &Error{"validation_failed"})
		return
	}
	var result any
	var task contract.Task
	var err error
	if kind == systembackupread.BackupTask {
		var detail contract.BackupDetailResource
		detail, err = h.application.ReadBackup(r, id)
		result, task = detail, detail.Task
		if err == nil && detail.SchemaVersion != "system-backup-backup-detail.v1" {
			err = &Error{"not_ready"}
		}
	} else {
		var detail contract.PreflightDetailResource
		detail, err = h.application.ReadPreflight(r, id)
		result, task = detail, detail.Task
		if err == nil && detail.SchemaVersion != "system-backup-preflight-detail.v1" {
			err = &Error{"not_ready"}
		}
	}
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	if task.PublicID != id || task.TaskType != string(kind) || task.SchemaVersion != "system-backup-task.v1" || r.Context().Err() != nil {
		writeError(w, requestID, nil)
		return
	}
	w.Header().Set("X-System-Backup-Data-Source", "live")
	w.Header().Set("X-System-Backup-Origin-Installation-ID", task.OriginInstallationID)
	w.Header().Set("X-System-Backup-Task-Row-Version", strconv.FormatInt(task.RowVersion, 10))
	w.Header().Add("Access-Control-Expose-Headers", "X-System-Backup-Data-Source, X-System-Backup-Origin-Installation-ID, X-System-Backup-Task-Row-Version")
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		status, body = http.StatusServiceUnavailable, []byte(`{"code":"not_ready"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, requestID string, err error) {
	status, code := http.StatusServiceUnavailable, "not_ready"
	if err != nil {
		status, code = http.StatusInternalServerError, "internal_error"
	}
	var failure *Error
	if errors.As(err, &failure) && failure != nil {
		if mapped, ok := errorStatuses[failure.Code]; ok {
			status, code = mapped, failure.Code
		}
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, status, map[string]any{"code": code, "message": code, "details": map[string]any{}, "request_id": requestID})
}

// Existing admin-operation-errors task_create codes and common HTTP statuses.
var errorStatuses = map[string]int{
	"validation_failed": 400, "authentication_required": 401, "permission_denied": 403, "not_found": 404,
	"idempotency_conflict": 409, "idempotency_expired": 410, "conflict_active_job": 409,
	"artifact_conflict": 409, "catalog_conflict": 409, "state_conflict": 409,
	"unsupported_runner_p1": 422, "unsupported_profile_p1": 422, "unsupported_datasource_p1": 422,
	"unsupported_schema": 422, "backup_target_risk_rejected": 422, "isolation_invalid": 409,
	"capacity_exceeded": 422, "payload_too_large": 413, "rate_limited": 429,
	"not_ready": 503, "artifact_unavailable": 503, "encryption_key_unavailable": 503,
	"signing_key_unavailable": 503, "catalog_unavailable": 503, "internal_error": 500,
}
