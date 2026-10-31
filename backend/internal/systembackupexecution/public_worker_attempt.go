package systembackupexecution

import (
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	"context"
	"database/sql"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Locate an existing attempt through the API-authenticated current Pod's
// original Job UID, never through a worker-supplied attempt or MAX(). This is
// only a locator: input/plan and the original transaction guard authenticate
// that exact attempt as current before granting any use.
func (o *PublicJobOwner) originalWorkerAttempt(ctx context.Context, task string, pod BoundPod) (uint64, error) {
	actual, err := o.Client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || string(actual.UID) != pod.UID || actual.DeletionTimestamp != nil || actual.Spec.ServiceAccountName != o.Security.ServiceAccountName || len(actual.OwnerReferences) != 1 {
		return 0, c.ErrExecutionAuthority
	}
	owner := metav1.GetControllerOf(actual)
	if owner == nil || owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name == "" || owner.UID == "" {
		return 0, c.ErrExecutionAuthority
	}
	var attempt uint64
	var uid, lifecycle string
	var dispatched, revoked bool
	var stopped sql.NullTime
	err = o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT attempt_no,observed_uid,lifecycle,create_dispatched,revoked,stopped_at FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND resource_owner=? AND namespace_name=? AND resource_name=? AND phase='capture'`, task, task, pod.Namespace, owner.Name).Scan(&attempt, &uid, &lifecycle, &dispatched, &revoked, &stopped)
	if err != nil || attempt == 0 || !dispatched || revoked || stopped.Valid {
		return 0, c.ErrExecutionAuthority
	}
	if uid == "" && lifecycle == "creating" {
		// This is only a retryable observation gap, never an admitted use. The
		// caller must still authenticate this original attempt/plan/Invocation.
		return attempt, worker.PendingControl("job_observation_pending")
	}
	if uid != string(owner.UID) || lifecycle != "ready" {
		return 0, c.ErrExecutionAuthority
	}
	return attempt, nil
}
