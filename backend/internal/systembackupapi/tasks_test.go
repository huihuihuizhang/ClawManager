package systembackupapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	contract "clawreef/internal/systembackupcontract"
	"clawreef/internal/systembackupread"
)

// Model only: a durable task/queue and worker are simulated here, never linked
// by the server. Production SQL, A authority and B/C execution remain required.
type taskModel struct {
	tasks   map[string]systembackupread.TaskHeader
	queue   []string
	err     error
	corrupt bool
}

func (m *taskModel) CreateAndEnqueue(r *http.Request, kind systembackupread.TaskKind, endpoint, key string, body json.RawMessage) (systembackupread.TaskHeader, error) {
	if m.err != nil {
		return systembackupread.TaskHeader{}, m.err
	}
	if r.Header.Get("Authorization") != "Bearer model-admin" {
		return systembackupread.TaskHeader{}, &Error{"permission_denied"}
	}
	if string(body) != "{}" && string(body) != `{"different":true}` {
		return systembackupread.TaskHeader{}, &Error{"validation_failed"}
	}
	scope := "installation_model/admin/7/" + endpoint + "/" + key
	hash := sha256.Sum256(body)
	digest := hex.EncodeToString(hash[:]) // model only, NOT the owner JCS algorithm
	if old, ok := m.tasks[scope]; ok {
		if old.RequestHash != digest {
			return systembackupread.TaskHeader{}, &Error{"idempotency_conflict"}
		}
		return old, nil
	}
	_, _, prefix := taskRoute(kind)
	now := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	task := systembackupread.TaskHeader{Kind: kind, PublicID: prefix + "11111111-2222-3333-4444-555555555555", InstallationID: "installation_model", ActorType: "admin", ActorID: "7", Endpoint: endpoint, IdempotencyKey: key, RequestID: "model-request", RequestHash: digest, Status: "pending", PendingReason: "none", AttentionReason: "none", FailureCategory: "none", ConfigVersion: 1, RowVersion: 1, CreatedAt: now, UpdatedAt: now, DeadlineAt: now.Add(time.Minute)}
	m.tasks[scope] = task
	m.queue = append(m.queue, scope)
	if m.corrupt {
		task.Kind = systembackupread.DrillTask
	}
	return task, nil
}

func modelTask(task systembackupread.TaskHeader) contract.Task {
	dto, _ := systembackupread.ProjectTask(task)
	raw, _ := json.Marshal(dto)
	var result contract.Task
	_ = json.Unmarshal(raw, &result)
	return result
}
func (m *taskModel) find(r *http.Request, id string) (contract.Task, error) {
	if r.Header.Get("Authorization") != "Bearer model-admin" {
		return contract.Task{}, &Error{"permission_denied"}
	}
	for _, task := range m.tasks {
		if task.PublicID == id {
			return modelTask(task), nil
		}
	}
	return contract.Task{}, &Error{"not_found"}
}
func (m *taskModel) ReadBackup(r *http.Request, id string) (contract.BackupDetailResource, error) {
	task, err := m.find(r, id)
	return contract.BackupDetailResource{SchemaVersion: "system-backup-backup-detail.v1", Task: task}, err
}
func (m *taskModel) ReadPreflight(r *http.Request, id string) (contract.PreflightDetailResource, error) {
	task, err := m.find(r, id)
	return contract.PreflightDetailResource{SchemaVersion: "system-backup-preflight-detail.v1", Task: task}, err
}
func createRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "model-key-123456789")
	r.Header.Set("Authorization", "Bearer model-admin")
	return r
}

func TestTaskHTTPCreateReplayWorkerAndDetailModel(t *testing.T) {
	for _, kind := range []systembackupread.TaskKind{systembackupread.BackupTask, systembackupread.PreflightTask} {
		t.Run(string(kind), func(t *testing.T) {
			m := &taskModel{tasks: map[string]systembackupread.TaskHeader{}}
			h := NewHandler(m)
			first, replay := httptest.NewRecorder(), httptest.NewRecorder()
			h.Create(first, createRequest("{}"), kind, "request-one")
			h.Create(replay, createRequest("{}"), kind, "request-two")
			if first.Code != 202 || replay.Code != 202 || first.Body.String() != replay.Body.String() || len(m.tasks) != 1 || len(m.queue) != 1 {
				t.Fatalf("not one creation/enqueue: %d %d %s", first.Code, replay.Code, first.Body)
			}
			if first.Header().Get("Location") == "" || first.Header().Get("Retry-After") != "1" || first.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing async transport headers")
			}
			conflict := httptest.NewRecorder()
			h.Create(conflict, createRequest(`{"different":true}`), kind, "request-conflict")
			if conflict.Code != 409 || len(m.queue) != 1 {
				t.Fatal("same key conflict enqueued again")
			}
			for _, status := range []string{"running", "succeeded", "failed"} {
				if kind == systembackupread.BackupTask && status == "running" {
					status = "preparing"
				}
				key := m.queue[0]
				task := m.tasks[key]
				task.Status = status
				task.RowVersion++
				if status == "failed" {
					task.FailureCategory = "runner_failed"
				}
				m.tasks[key] = task
				read := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("Authorization", "Bearer model-admin")
				h.Detail(read, r, kind, task.PublicID, "request-detail")
				var detail struct {
					Task contract.Task `json:"task"`
				}
				if json.Unmarshal(read.Body.Bytes(), &detail) != nil || read.Code != 200 || detail.Task.Status != status || detail.Task.FailureCategory != task.FailureCategory {
					t.Fatalf("worker outcome lost: %s", read.Body)
				}
				denied := httptest.NewRecorder()
				h.Detail(denied, httptest.NewRequest("GET", "/", nil), kind, task.PublicID, "denied")
				if denied.Code != 403 || strings.Contains(denied.Body.String(), task.PublicID) {
					t.Fatal("foreign session observed task")
				}
			}
		})
	}
}

func TestTaskHTTPRejectsBeforeDispatchAndNeverLeaksErrors(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "another-key-123456") },
		func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		func(r *http.Request) { r.URL.RawQuery = "installation_id=foreign" },
	} {
		m := &taskModel{tasks: map[string]systembackupread.TaskHeader{}}
		r := createRequest("{}")
		mutate(r)
		w := httptest.NewRecorder()
		NewHandler(m).Create(w, r, systembackupread.BackupTask, "request")
		if w.Code != 400 || len(m.queue) != 0 {
			t.Fatal("invalid transport dispatched")
		}
	}
	for _, body := range []string{"{", "{} {}", strings.Repeat(" ", maxTaskBody) + "{}"} {
		m := &taskModel{tasks: map[string]systembackupread.TaskHeader{}}
		w := httptest.NewRecorder()
		NewHandler(m).Create(w, createRequest(body), systembackupread.BackupTask, "request")
		if w.Code != 400 && w.Code != 413 || len(m.queue) != 0 {
			t.Fatal("malformed/oversize body dispatched")
		}
	}
	for _, application := range []TaskApplication{nil, (*taskModel)(nil)} {
		w := httptest.NewRecorder()
		NewHandler(application).Create(w, createRequest("{}"), systembackupread.BackupTask, "request")
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"not_ready"`) {
			t.Fatal("missing application accepted")
		}
	}
	for _, failure := range []error{errors.New("password=never-print-this"), &Error{"made_up_code"}, &Error{"permission_denied"}, &Error{"not_ready"}} {
		m := &taskModel{err: failure}
		w := httptest.NewRecorder()
		NewHandler(m).Create(w, createRequest("{}"), systembackupread.BackupTask, "request")
		if w.Code < 400 || strings.Contains(w.Body.String(), "never-print") || strings.Contains(w.Body.String(), "made_up") {
			t.Fatal("raw/unknown error exposed")
		}
	}
	m := &taskModel{tasks: map[string]systembackupread.TaskHeader{}, corrupt: true}
	w := httptest.NewRecorder()
	NewHandler(m).Create(w, createRequest("{}"), systembackupread.BackupTask, "request")
	if w.Code != 503 || len(m.queue) != 1 || w.Header().Get("Location") != "" {
		t.Fatal("invalid committed result fabricated success/retried")
	}
}

func TestTaskHTTPMappingsMatchFrozenPolicy(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-operation-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Errors []struct {
			Code   string `json:"code"`
			Status int    `json:"http_status"`
		} `json:"error_status_map"`
	}
	if json.Unmarshal(raw, &policy) != nil {
		t.Fatal("invalid policy")
	}
	if len(policy.Errors) == 0 {
		t.Fatal("missing error registry")
	}
	for code, status := range errorStatuses {
		found := false
		for _, item := range policy.Errors {
			if item.Code == code {
				found = true
				if item.Status != status {
					t.Fatalf("%s: got %d want %d", code, status, item.Status)
				}
			}
		}
		if !found {
			t.Fatal("unregistered code", code)
		}
	}
}
