package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
)

type WorkerGrant struct {
	TaskID          string               `json:"task_id"`
	ProfileRevision string               `json:"profile_revision"`
	SPIFFE          string               `json:"spiffe"`
	JobNamespace    string               `json:"job_namespace"`
	JobName         string               `json:"job_name"`
	JobUID          string               `json:"job_uid"`
	Invocation      worker.Invocation    `json:"invocation"`
	Key             artifact.WrappedKey  `json:"key"`
	CredentialRef   string               `json:"credential_ref,omitempty"`
	Security        *kube.WorkerSecurity `json:"security,omitempty"`
}

func validWorker(g WorkerGrant) bool {
	_, e := g.Invocation.Hash()
	if e != nil || !identifier.MatchString(g.TaskID) || !revision.MatchString(g.ProfileRevision) || g.JobNamespace == "" || g.JobName == "" || g.JobUID == "" || len(g.JobUID) > 256 || len(g.SPIFFE) > 512 {
		return false
	}
	uri, e := url.Parse(g.SPIFFE)
	if e != nil || uri.Scheme != "spiffe" || uri.Host == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" {
		return false
	}
	if len(g.Key.Nonce) != 12 || len(g.Key.Ciphertext) != 48 || !identifier.MatchString(g.Key.Version) {
		return false
	}
	if (g.Invocation.Request.Database != nil) != (g.CredentialRef != "") {
		return false
	}
	return worker.ValidateRecordedInvocation(g.Invocation)
}
func (s SQLStore) RegisterWorker(ctx context.Context, t Task, g WorkerGrant) error {
	if !validWorker(g) || !time.Now().Before(g.Invocation.Request.Deadline) || g.TaskID != t.ID || g.ProfileRevision != t.ProfileRevision {
		return ErrInvalid
	}
	body, _ := json.Marshal(g)
	if len(body) > 1<<20 {
		return ErrInvalid
	}
	hash, _ := g.Invocation.Hash()
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	if e != nil || !current.CanCancel || g.Invocation.Request.Deadline.UnixMilli() > current.Deadline {
		return ErrFence
	}
	if e = jobRegistered(ctx, tx, g); e != nil {
		return e
	}
	var old []byte
	e = tx.QueryRowContext(ctx, "SELECT grant_json FROM system_backup_workers WHERE task_id=? AND invocation_sha256=? FOR UPDATE", t.ID, hash).Scan(&old)
	if e == nil {
		if string(old) != string(body) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrNotReady
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_workers(task_id,invocation_sha256,spiffe_uri,grant_json) VALUES(?,?,?,?)", t.ID, hash, g.SPIFFE, body)
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func jobRegistered(ctx context.Context, tx *sql.Tx, g WorkerGrant) error {
	var uid, lifecycle string
	var dispatched bool
	if tx.QueryRowContext(ctx, "SELECT uid,lifecycle,dispatched FROM system_backup_resources WHERE task_id=? AND kind='Job' AND namespace_name=? AND resource_name=? FOR UPDATE", g.TaskID, g.JobNamespace, g.JobName).Scan(&uid, &lifecycle, &dispatched) != nil || uid != g.JobUID || !dispatched || lifecycle != "created" {
		return ErrFence
	}
	return nil
}

// WorkerAuthorizer joins the task claim, immutable worker/resource journals,
// maintenance barrier and fixed-lifetime grant. ValidateLive MUST verify the
// current Job/pod UID, mounts and runtime stop or target isolation evidence; it
// is required even for Ready. No metadata flag can stand in for that evidence.
type WorkerAuthorizer struct {
	Store        SQLStore
	Keys         artifact.Keys
	Credentials  func(context.Context, WorkerGrant) (*worker.DatabaseCredential, error)
	ValidateLive func(context.Context, WorkerGrant, string) error
	Lifetime     time.Duration
}

func (a WorkerAuthorizer) Authorize(ctx context.Context, spiffe string, r worker.ControlRequest) (response worker.Lease, result error) {
	if a.Store.DB == nil || a.Keys == nil || a.ValidateLive == nil || a.Lifetime < time.Second || a.Lifetime > 5*time.Minute || !worker.ValidateControl(r) {
		return response, worker.ErrNotReady
	}
	var raw []byte
	if a.Store.DB.QueryRowContext(ctx, "SELECT grant_json FROM system_backup_workers WHERE spiffe_uri=? AND invocation_sha256=?", spiffe, r.InvocationSHA256).Scan(&raw) != nil {
		return response, worker.ErrNotReady
	}
	var g WorkerGrant
	if len(raw) > 1<<20 || json.Unmarshal(raw, &g) != nil || !validWorker(g) || g.SPIFFE != spiffe {
		return response, worker.ErrNotReady
	}
	hash, _ := g.Invocation.Hash()
	if hash != r.InvocationSHA256 {
		return response, worker.ErrNotReady
	}
	if a.ValidateLive(ctx, g, r.Action+"/"+r.Point) != nil {
		return response, worker.ErrNotReady
	}
	tx, e := a.Store.begin(ctx)
	if e != nil {
		return response, worker.ErrNotReady
	}
	defer tx.Rollback()
	task, e := load(ctx, tx, g.TaskID)
	if e != nil || task.ProfileRevision != g.ProfileRevision || !task.CanCancel || task.Request.Purpose != "functional_test" {
		return response, worker.ErrNotReady
	}
	if a.Store.Fence(ctx, tx, task) != nil || jobRegistered(ctx, tx, g) != nil {
		return response, worker.ErrNotReady
	}
	var stored, previousResult []byte
	var ready, revoked bool
	var expires int64
	if tx.QueryRowContext(ctx, "SELECT grant_json,ready,revoked,acquired_until_ms,result_json FROM system_backup_workers WHERE task_id=? AND invocation_sha256=? FOR UPDATE", task.ID, hash).Scan(&stored, &ready, &revoked, &expires, &previousResult) != nil || string(stored) != string(raw) || revoked {
		return response, worker.ErrNotReady
	}
	nowMS, e := now(ctx, tx)
	if e != nil || task.Deadline <= nowMS || !workerPhase(task, r.Invocation.Request.Operation, r.Action) {
		return response, worker.ErrNotReady
	}
	deadline := r.Invocation.Request.Deadline.UnixMilli()
	if deadline > task.Deadline {
		deadline = task.Deadline
	}
	capture := r.Invocation.Request.Operation == "capture-database" || r.Invocation.Request.Operation == "capture-workspace"
	if capture && r.Action != "ready" {
		if r.Invocation.Request.Binding.BackupID != task.ID || a.Store.GateDrained(ctx, tx, task, false) != nil {
			return response, worker.ErrNotReady
		}
		var registry []byte
		var acknowledged, pending int
		if tx.QueryRowContext(ctx, "SELECT registry_json FROM system_backup_capture_registry WHERE task_id=? FOR UPDATE", task.ID).Scan(&registry) != nil {
			return response, worker.ErrNotReady
		}
		var inventory struct{ Writers []string }
		if json.Unmarshal(registry, &inventory) != nil || len(inventory.Writers) == 0 {
			return response, worker.ErrNotReady
		}
		if tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(NOT acknowledged OR resumed),0) FROM system_backup_pauses WHERE task_id=?", task.ID).Scan(&acknowledged, &pending) != nil || acknowledged != len(inventory.Writers) || pending != 0 {
			return response, worker.ErrNotReady
		}
		var hold int64
		if tx.QueryRowContext(ctx, "SELECT hold_until_ms FROM system_backup_maintenance WHERE id=1").Scan(&hold) != nil {
			return response, worker.ErrNotReady
		}
		if deadline > hold {
			deadline = hold
		}
	}
	if !capture && r.Invocation.Request.Binding.BackupID != task.Request.Artifact {
		return response, worker.ErrNotReady
	}
	if deadline <= nowMS {
		return response, worker.ErrNotReady
	}
	success := false
	defer func() {
		if !success {
			response.Clear()
			response = worker.Lease{}
		}
	}()
	switch r.Action {
	case "ready":
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_workers SET ready=TRUE WHERE task_id=? AND invocation_sha256=?", task.ID, hash)
		response.ExpiresAt = time.UnixMilli(deadline)
	case "acquire":
		if !ready || len(previousResult) > 0 {
			return response, worker.ErrNotReady
		}
		if expires == 0 {
			expires = nowMS + a.Lifetime.Milliseconds()
			if expires > deadline {
				expires = deadline
			}
			e = changed(tx.ExecContext(ctx, "UPDATE system_backup_workers SET acquired_until_ms=? WHERE task_id=? AND invocation_sha256=? AND acquired_until_ms=0", expires, task.ID, hash))
			if e != nil {
				return response, worker.ErrNotReady
			}
		}
		if expires <= nowMS || expires > deadline {
			return response, worker.ErrNotReady
		}
		response.ExpiresAt = time.UnixMilli(expires)
	case "check", "complete":
		if !ready || expires <= nowMS || expires > deadline {
			return response, worker.ErrNotReady
		}
		response.ExpiresAt = time.UnixMilli(expires)
		if r.Action == "check" && len(previousResult) > 0 {
			return response, worker.ErrNotReady
		}
		if r.Action == "complete" {
			b, _ := json.Marshal(r.Result)
			if len(previousResult) > 0 {
				if string(b) != string(previousResult) {
					return response, worker.ErrExecution
				}
			} else {
				_, e = tx.ExecContext(ctx, "UPDATE system_backup_workers SET result_json=? WHERE task_id=? AND invocation_sha256=? AND result_json IS NULL", b, task.ID, hash)
			}
		}
	default:
		return response, worker.ErrNotReady
	}
	if e != nil || a.Store.Fence(ctx, tx, task) != nil || tx.Commit() != nil {
		return response, worker.ErrNotReady
	}
	response.InvocationSHA256 = hash
	if r.Action == "acquire" {
		// Key/credential providers may read the same task vault. Never call them
		// while holding its row lock: that deadlocks with a nested transaction.
		// The fixed lifetime is already durable; reauthorize after fetching.
		response.DEK, e = a.Keys.Unwrap(ctx, r.Invocation.Request.Binding, g.Key)
		if e != nil || len(response.DEK) != 32 {
			return response, worker.ErrNotReady
		}
		if r.Invocation.Request.Database != nil {
			if a.Credentials == nil {
				return response, worker.ErrNotReady
			}
			response.Database, e = a.Credentials(ctx, g)
			if e != nil || response.Database == nil || response.Database.Username == "" || len(response.Database.Username) > 128 || len(response.Database.Password) == 0 || len(response.Database.Password) > 4096 {
				return response, worker.ErrNotReady
			}
		}
		check := r
		check.Action, check.Point = "check", "prepare"
		confirmation, err := a.Authorize(ctx, spiffe, check)
		if err != nil || !confirmation.ExpiresAt.Equal(response.ExpiresAt) {
			return response, worker.ErrNotReady
		}
	}
	success = true
	return response, nil
}
func workerPhase(t Task, operation, action string) bool {
	switch operation {
	case "capture-workspace", "capture-database":
		if t.Request.Kind != "backup" {
			return false
		}
		if action == "ready" {
			return t.Status == "preparing" || t.Status == "ready_for_capture" || t.Status == "acquiring_gate" || t.Status == "capturing"
		}
		return t.Status == "capturing"
	case "restore-workspace", "restore-database", "restore-assets":
		return t.Request.Kind == "drill" && (t.Status == "restoring" || (action == "ready" && t.Status == "provisioning"))
	case "verify-database", "verify-assets":
		return (t.Request.Kind == "drill" && t.Status == "verifying") || (t.Request.Kind == "preflight" && t.Status == "running")
	}
	return false
}
func (s SQLStore) RevokeWorkers(ctx context.Context, t Task) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_workers SET revoked=TRUE WHERE task_id=?", t.ID)
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
