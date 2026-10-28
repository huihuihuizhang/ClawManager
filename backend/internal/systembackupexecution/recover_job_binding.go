package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// recoverJobIdentity can only inspect an already-dispatched original request.
// Revocation is durable before external IO. Ensure cannot create again because
// the original send bit is already set; a missing/unknown object stays blocked.
type recoveryJobFailure struct {
	stage string
	cause error
}

func (e recoveryJobFailure) Error() string { return "original job recovery: " + e.stage }
func (e recoveryJobFailure) Unwrap() error { return e.cause }

func (o *PublicJobOwner) recoverJobIdentity(ctx context.Context, a d.Authority, part b.JobPart) (result d.JobBinding, resultErr error) {
	stage := "original-intent"
	defer func() {
		if resultErr != nil {
			resultErr = recoveryJobFailure{stage, resultErr}
		}
	}()
	var zero d.JobBinding
	var original batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &original) != nil {
		return zero, c.ErrExecutionRecord
	}
	wanted, e := kube.Intent("Job", &original)
	if e != nil {
		return zero, e
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback()
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return zero, e
	}
	rows, e := o.rows(a.TaskPublicID)
	if e != nil {
		return zero, e
	}
	record, e := rows.Load(ctx, tx, wanted)
	if e != nil || !record.CreateDispatched || record.Intent.RequestSHA256 != wanted.RequestSHA256 {
		return zero, c.ErrExecutionRecoveryRequired
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND request_sha256=?", a.TaskPublicID, part.Intent.Namespace, part.Intent.Name, wanted.RequestSHA256); e != nil {
		return zero, e
	}
	if e = tx.Commit(); e != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	stage = "lookup-original"
	runner, e := o.runner(a, true)
	if e != nil {
		return zero, e
	}
	record, e = runner.Ensure(ctx, "Job", &original)
	if e != nil {
		return zero, e
	}
	stage = "bind-original"
	binding, e := o.bindOriginal(ctx, a, part.Intent, record, true)
	if e != nil {
		return zero, e
	}
	// An expired certificate is valid historical identity, never a new grant.
	// The exact actual Pod/containers are needed even if no acquire reached us.
	stage = "original-mounts"
	security, e := o.workerSecurity(ctx, a, part)
	if e != nil {
		return zero, e
	}
	stage = "observe-original-process"
	var process kube.WorkerProcess
	for {
		process, e = (kube.WorkerObserver{Client: o.Client}).ObserveForRecovery(ctx, record, security)
		if e == nil {
			break
		}
		if !errors.Is(e, kube.ErrPending) {
			return zero, e
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	stage = "record-original-process"
	raw, _ := json.Marshal(process)
	tx, e = o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback()
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return zero, e
	}
	var old []byte
	if e = tx.QueryRowContext(ctx, "SELECT process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND revoked=TRUE FOR UPDATE", a.TaskPublicID, binding.UID).Scan(&old); e != nil {
		return zero, e
	}
	if len(old) > 0 {
		var saved kube.WorkerProcess
		if json.Unmarshal(old, &saved) != nil || !kube.SameWorkerProcess(saved, process) {
			return zero, c.ErrExecutionRecord
		}
	} else if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET process_json=? WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND process_json IS NULL AND revoked=TRUE", raw, a.TaskPublicID, binding.UID); e != nil {
		return zero, e
	}
	if e = tx.Commit(); e != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	return binding, nil
}
