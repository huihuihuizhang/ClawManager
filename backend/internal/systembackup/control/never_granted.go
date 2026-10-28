package control

import (
	"context"
	"database/sql"
	"errors"

	"clawreef/internal/systembackup/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StoppedOrNeverGranted reconciles a fixed worker that failed before Ready.
// The absence of a Pod is sufficient ONLY if no process/key grant was ever
// recorded, credentials were revoked by the caller and the Job is durably gone.
// Any observed process still requires the original node's CRI stop proof.
func (l LiveWorkers) StoppedOrNeverGranted(ctx context.Context, t Task, g WorkerGrant, r kube.ResourceRecord) error {
	if l.Store.DB == nil || l.Observer.Client == nil || g.TaskID != t.ID || !r.Deleted || r.Intent.Kind != "Job" || r.Intent.Identity.Owner != t.ID || r.Intent.Identity.Name != g.JobName || r.Intent.Identity.Namespace != g.JobNamespace || r.UID != g.JobUID {
		return ErrNotReady
	}
	hash, e := g.Invocation.Hash()
	if e != nil {
		return ErrInvalid
	}
	var count int
	if l.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_worker_processes WHERE task_id=? AND invocation_sha256=?", t.ID, hash).Scan(&count) != nil {
		return ErrNotReady
	}
	if count > 0 {
		return l.Stopped(ctx, g, r)
	}
	var until int64
	var revoked bool
	e = l.Store.DB.QueryRowContext(ctx, "SELECT acquired_until_ms,revoked FROM system_backup_workers WHERE task_id=? AND invocation_sha256=?", t.ID, hash).Scan(&until, &revoked)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return ErrNotReady
	}
	if e == nil && (!revoked || until != 0) {
		return ErrNotReady
	}
	if g.JobUID != "" {
		pods, e := l.Observer.Client.CoreV1().Pods(g.JobNamespace).List(ctx, metav1.ListOptions{LabelSelector: "batch.kubernetes.io/controller-uid=" + g.JobUID})
		if e != nil || len(pods.Items) != 0 {
			return ErrNotReady
		}
	} else if r.CreateDispatched {
		return ErrNotReady
	}
	tx, e := l.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return l.Store.Fence(ctx, tx, t)
}
