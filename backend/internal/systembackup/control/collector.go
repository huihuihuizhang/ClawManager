package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	batchv1 "k8s.io/api/batch/v1"
)

// JobCollector binds real Kubernetes dispatch, authenticated Ready/result relay
// and recovery to flow.Capture. Job and Grant are frozen task-plan values.
// StopProof must use recorded Pod/container identities and node runtime proof;
// it MUST NOT infer process death merely from a missing Job or Pod.
type JobCollector struct {
	Store                 SQLStore
	Task                  Task
	Runner, CleanupRunner kube.Runner
	Job                   *batchv1.Job
	Grant                 WorkerGrant
	PartID                string
	StopProof             func(context.Context, WorkerGrant, kube.ResourceRecord) error
	RevokeCredential      func(context.Context, string) error
}

var _ flow.Collector = (*JobCollector)(nil)

func (c *JobCollector) ID() string { return c.PartID }
func (c *JobCollector) valid() bool {
	return c.Store.DB != nil && c.Job != nil && identifier.MatchString(c.PartID) && c.Task.ID == c.Grant.TaskID && c.Task.ProfileRevision == c.Grant.ProfileRevision && c.Job.Namespace == c.Grant.JobNamespace && c.Job.Name == c.Grant.JobName && c.StopProof != nil && (c.Grant.CredentialRef == "" || c.RevokeCredential != nil)
}
func (c *JobCollector) Prepare(ctx context.Context) error {
	if !c.valid() {
		return ErrInvalid
	}
	record, e := c.Runner.Ensure(ctx, "Job", c.Job)
	if e != nil {
		return e
	}
	if c.Grant.JobUID != "" && c.Grant.JobUID != record.UID {
		return ErrConflict
	}
	c.Grant.JobUID = record.UID
	if e = c.Store.RegisterWorker(ctx, c.Task, c.Grant); e != nil {
		return e
	}
	hash, _ := c.Grant.Invocation.Hash()
	for {
		status, e := c.Store.WorkerStatus(ctx, c.Task, hash)
		if e != nil {
			return e
		}
		if status.Revoked {
			return ErrConflict
		}
		if status.Ready {
			return nil
		}
		if !waitPoll(ctx, 500*time.Millisecond) {
			return ctx.Err()
		}
	}
}
func (c *JobCollector) Capture(ctx context.Context) (flow.Part, error) {
	if !c.valid() {
		return flow.Part{}, ErrInvalid
	}
	record, e := c.Runner.Ensure(ctx, "Job", c.Job)
	if e != nil {
		return flow.Part{}, e
	}
	hash, e := c.Grant.Invocation.Hash()
	if e != nil {
		return flow.Part{}, ErrInvalid
	}
	result, e := c.Store.AwaitWorker(ctx, c.Task, hash, c.Runner, record)
	if e != nil {
		return flow.Part{}, e
	}
	raw, e := json.Marshal(result.Receipt)
	if e != nil {
		return flow.Part{}, ErrInvalid
	}
	return flow.Part{ID: c.PartID, Checkpoint: hash, SealedRef: string(raw)}, nil
}
func (c *JobCollector) Stop(ctx context.Context) error {
	if !c.valid() {
		return ErrInvalid
	}
	hash, e := c.Grant.Invocation.Hash()
	if e != nil {
		return ErrInvalid
	}
	terminated, e := c.Store.revokeWorker(ctx, c.Task, hash)
	if e != nil {
		return e
	}
	if terminated {
		return nil
	} // durable proof survives node-side container GC
	// Revoke at the database/provider as well as at the relay. An already issued
	// SQL password or key is not revoked by a boolean in the control database.
	if c.Grant.CredentialRef != "" && c.RevokeCredential(ctx, c.Grant.CredentialRef) != nil {
		return ErrNotReady
	}
	intent, e := kube.Intent("Job", c.Job)
	if e != nil {
		return e
	}
	if c.CleanupRunner.Journal == nil {
		return ErrNotReady
	}
	record, e := c.CleanupRunner.Journal.Prepare(ctx, intent)
	if e != nil {
		return e
	}
	if c.Grant.JobUID != "" && record.UID != c.Grant.JobUID {
		return ErrConflict
	}
	c.Grant.JobUID = record.UID
	for {
		done, e := c.CleanupRunner.Cleanup(ctx, record)
		if e != nil && !errors.Is(e, kube.ErrPending) {
			return e
		}
		if done {
			break
		}
		if !waitPoll(ctx, 500*time.Millisecond) {
			return ctx.Err()
		}
	}
	record, e = c.CleanupRunner.Journal.Prepare(ctx, intent)
	if e != nil || !record.Deleted || (c.Grant.JobUID != "" && c.Grant.JobUID != record.UID) {
		return ErrNotReady
	}
	c.Grant.JobUID = record.UID
	if c.StopProof(ctx, c.Grant, record) != nil {
		return ErrNotReady
	}
	return c.Store.markWorkerTerminated(ctx, c.Task, hash)
}

func (s SQLStore) revokeWorker(ctx context.Context, t Task, hash string) (bool, error) {
	tx, e := s.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return false, ErrFence
	}
	var terminated bool
	e = tx.QueryRowContext(ctx, "SELECT terminated FROM system_backup_workers WHERE task_id=? AND invocation_sha256=? FOR UPDATE", t.ID, hash).Scan(&terminated)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return false, ErrNotReady
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_workers SET revoked=TRUE WHERE task_id=? AND invocation_sha256=?", t.ID, hash)
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return false, ErrNotReady
	}
	return terminated, nil
}
func (s SQLStore) markWorkerTerminated(ctx context.Context, t Task, hash string) error {
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	// Zero rows is valid only for a Job that never completed grant registration.
	// Such a Job could not acquire data-plane credentials from this relay.
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_workers SET terminated=TRUE WHERE task_id=? AND invocation_sha256=? AND revoked=TRUE", t.ID, hash)
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}

// Contains two task_id placeholders. Reused under the task lock by gate,
// source-recovery and terminal transitions; no timeout silently clears it.
const pendingWorkersSQL = "(SELECT COUNT(*) FROM system_backup_workers WHERE task_id=? AND (revoked=FALSE OR terminated=FALSE))+(SELECT COUNT(*) FROM system_backup_resources WHERE task_id=? AND kind='Job' AND lifecycle<>'deleted')"
