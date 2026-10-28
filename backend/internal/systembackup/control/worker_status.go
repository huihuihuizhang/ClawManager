package control

import (
	"context"
	"encoding/json"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
)

type WorkerStatus struct {
	Grant   WorkerGrant
	Ready   bool
	Revoked bool
	Result  *worker.Result
}

// WorkerStatus reads only the immutable registered invocation, never pod logs.
// Results remain readable after a grant expires; reading them issues no keys.
func (s SQLStore) WorkerStatus(ctx context.Context, t Task, hash string) (WorkerStatus, error) {
	var out WorkerStatus
	if !revision.MatchString(hash) {
		return out, ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return out, ErrFence
	}
	var raw, result []byte
	e = tx.QueryRowContext(ctx, "SELECT grant_json,ready,revoked,result_json FROM system_backup_workers WHERE task_id=? AND invocation_sha256=? FOR UPDATE", t.ID, hash).Scan(&raw, &out.Ready, &out.Revoked, &result)
	if e != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &out.Grant) != nil {
		return WorkerStatus{}, ErrNotReady
	}
	actual, e := out.Grant.Invocation.Hash()
	if e != nil || actual != hash || out.Grant.TaskID != t.ID || out.Grant.ProfileRevision != t.ProfileRevision {
		return WorkerStatus{}, ErrConflict
	}
	if len(result) > 0 {
		if len(result) > 1<<20 || json.Unmarshal(result, &out.Result) != nil || !worker.ValidateResult(out.Grant.Invocation.Request, out.Result) {
			return WorkerStatus{}, ErrConflict
		}
	}
	if s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return WorkerStatus{}, ErrNotReady
	}
	return out, nil
}

// AwaitWorker joins the authenticated result relay with the matching Job's
// Complete condition. Neither a receipt alone nor a succeeded counter suffices.
// Runner's live fence is rechecked on every poll and after the final SQL read.
func (s SQLStore) AwaitWorker(ctx context.Context, t Task, hash string, runner kube.Runner, record kube.ResourceRecord) (worker.Result, error) {
	if _, ok := ctx.Deadline(); !ok || record.Intent.Kind != "Job" || record.UID == "" {
		return worker.Result{}, ErrInvalid
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, e := s.WorkerStatus(ctx, t, hash)
		if e != nil {
			return worker.Result{}, e
		}
		if state.Revoked || state.Grant.JobUID != record.UID || state.Grant.JobNamespace != record.Intent.Identity.Namespace || state.Grant.JobName != record.Intent.Identity.Name {
			return worker.Result{}, ErrConflict
		}
		done, e := runner.JobComplete(ctx, record)
		if e != nil {
			return worker.Result{}, e
		}
		if done && state.Result != nil {
			return *state.Result, nil
		}
		// Complete without a result can reflect delayed replication/relay reads.
		// Keep waiting boundedly, never reconstruct a receipt from untrusted logs.
		select {
		case <-ctx.Done():
			return worker.Result{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
