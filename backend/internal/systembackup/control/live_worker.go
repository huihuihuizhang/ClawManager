package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
)

// LiveWorkers supplies WorkerAuthorizer.ValidateLive and JobCollector.StopProof.
// CheckEvidence must additionally prove the profile-specific source pause or
// target quarantine; checking a Pod alone cannot establish either property.
type LiveWorkers struct {
	Store         SQLStore
	Observer      kube.WorkerObserver
	Proof         *quiesce.ProofClient
	CheckEvidence func(context.Context, WorkerGrant, string) error
}

func (l LiveWorkers) resource(ctx context.Context, g WorkerGrant) (kube.ResourceRecord, error) {
	r := kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: g.JobNamespace, Name: g.JobName}}}
	var lifecycle string
	e := l.Store.DB.QueryRowContext(ctx, "SELECT owner_marker,request_sha256,request_json,uid,resource_version,row_version,dispatched,lifecycle FROM system_backup_resources WHERE task_id=? AND kind='Job' AND namespace_name=? AND resource_name=?", g.TaskID, g.JobNamespace, g.JobName).Scan(&r.Intent.Identity.Owner, &r.Intent.RequestSHA256, &r.Intent.RequestJSON, &r.UID, &r.ResourceVersion, &r.Revision, &r.CreateDispatched, &lifecycle)
	if e != nil || r.UID != g.JobUID || !r.CreateDispatched || lifecycle != "created" || len(r.Intent.RequestJSON) > 1<<20 {
		return r, ErrFence
	}
	return r, nil
}
func (l LiveWorkers) Validate(ctx context.Context, g WorkerGrant, point string) error {
	if l.Store.DB == nil || g.Security == nil || l.CheckEvidence == nil || !validWorker(g) {
		return ErrNotReady
	}
	r, e := l.resource(ctx, g)
	if e != nil {
		return e
	}
	process, e := l.Observer.Observe(ctx, r, *g.Security)
	if e != nil {
		return ErrNotReady
	}
	if e = l.CheckEvidence(ctx, g, point); e != nil {
		return ErrNotReady
	}
	task, e := l.Store.Get(ctx, g.TaskID)
	if e != nil || task.ProfileRevision != g.ProfileRevision || !task.CanCancel {
		return ErrFence
	}
	return l.pin(ctx, task, g, process)
}

// Pin before the first Ready/acquire acknowledgement; a replacement Pod or
// restarted container can never inherit the first process's grant. There is no
// dependence on Pod logs, or on the Pod remaining in the API during recovery.
func (l LiveWorkers) pin(ctx context.Context, t Task, g WorkerGrant, p kube.WorkerProcess) error {
	if p.UID == "" || p.Node == "" || p.Name == "" || len(p.Containers) != 1 || p.Containers[0] == "" {
		return ErrInvalid
	}
	hash, e := g.Invocation.Hash()
	if e != nil {
		return ErrInvalid
	}
	tx, e := l.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if l.Store.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	current, e := load(ctx, tx, t.ID)
	timestamp, te := now(ctx, tx)
	if e != nil || te != nil || !current.CanCancel || current.Deadline <= timestamp {
		return ErrFence
	}
	if e = jobRegistered(ctx, tx, g); e != nil {
		return e
	}
	var revoked bool
	if tx.QueryRowContext(ctx, "SELECT revoked FROM system_backup_workers WHERE task_id=? AND invocation_sha256=? FOR UPDATE", t.ID, hash).Scan(&revoked) != nil || revoked {
		return ErrFence
	}
	var raw []byte
	e = tx.QueryRowContext(ctx, "SELECT process_json FROM system_backup_worker_processes WHERE task_id=? AND invocation_sha256=? FOR UPDATE", t.ID, hash).Scan(&raw)
	if e == nil {
		var previous kube.WorkerProcess
		if json.Unmarshal(raw, &previous) != nil || !kube.SameWorkerProcess(previous, p) {
			return ErrConflict
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		raw, _ = json.Marshal(p)
		if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_worker_processes(task_id,invocation_sha256,process_json) VALUES(?,?,?)", t.ID, hash, raw); e != nil {
			return ErrNotReady
		}
	} else {
		return ErrNotReady
	}
	if l.Store.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrFence
	}
	return nil
}
func (l LiveWorkers) Stopped(ctx context.Context, g WorkerGrant, r kube.ResourceRecord) error {
	if l.Store.DB == nil || l.Proof == nil || r.UID != g.JobUID || r.Intent.Kind != "Job" || r.Intent.Identity.Name != g.JobName || r.Intent.Identity.Namespace != g.JobNamespace || !validWorker(g) {
		return ErrNotReady
	}
	hash, _ := g.Invocation.Hash()
	var raw []byte
	if l.Store.DB.QueryRowContext(ctx, "SELECT process_json FROM system_backup_worker_processes WHERE task_id=? AND invocation_sha256=?", g.TaskID, hash).Scan(&raw) != nil || len(raw) > 16<<10 {
		return ErrNotReady
	}
	var p kube.WorkerProcess
	if json.Unmarshal(raw, &p) != nil || p.UID == "" || p.Node == "" || len(p.Containers) != 1 {
		return ErrConflict
	}
	return l.Proof.Confirm(ctx, []quiesce.PodIdentity{{Name: p.Name, UID: p.UID, Node: p.Node, Containers: p.Containers}})
}
