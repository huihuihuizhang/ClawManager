package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// This is a separate negative task/run. It never converts the positive test's
// failure into success, resets an epoch/gate, or retries a consumed envelope.
func (f *dOriginalSixPartTask) checkOriginalProviderDeniedOutcome(ctx context.Context, t *testing.T, capture c.ExecutionWork, discovery b.Discovery, results []d.ModuleResult, captureErr error) {
	t.Helper()
	if captureErr == nil || len(results) != 0 {
		t.Fatal("explicit original Generate denial was accepted")
	}
	f.workers.active.Wait()
	f.provider.mu.Lock()
	denied, generated, unwrapped := f.provider.deniedGenerate, f.provider.generateCalls, f.provider.unwrapCalls
	f.provider.mu.Unlock()
	if denied != 1 || generated != 0 || unwrapped != 0 {
		t.Fatal("actual provider denial boundary not exercised", denied, generated, unwrapped)
	}
	f.workers.mu.Lock()
	active, dispatches, checks, projections := f.workers.running, f.workers.heldDispatches, f.workers.resumeChecks, len(f.workers.projections)
	f.workers.mu.Unlock()
	if active != 0 || dispatches != 1 || checks != 2 || projections != 1 {
		t.Fatal("original admitted Job/Pod/held/stop-before-resume checks", active, dispatches, checks, projections)
	}
	f.checkOriginalPhysicalRecovery(ctx, t, 1)
	var accepted int
	if err := f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND (result_sha256 IS NOT NULL OR candidate_sha256 IS NOT NULL)", f.publicID).Scan(&accepted); err != nil || accepted != 0 {
		t.Fatal("denied provider produced accepted candidate/result", err)
	}
	stage, err := f.owner.Staging.OpenRoot(f.publicID)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	for _, part := range discovery.Parts {
		var inv worker.Invocation
		if err := json.Unmarshal(part.InvocationJSON, &inv); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{inv.Request.ArtifactName, inv.FormalCapture.EnvelopeName} {
			if _, err := stage.Lstat(name); !os.IsNotExist(err) {
				t.Fatal("denied provider created a success artifact", name, err)
			}
		}
	}
	if err = f.service.Runtime.Loop.Store.Record(ctx, capture, c.ExecutionOutcome{Err: captureErr}); err != nil {
		t.Fatal("original failed capture Record/claim convergence", err)
	}
	var status string
	var claim sql.NullString
	var lease sql.NullTime
	if err = f.control.QueryRowContext(ctx, "SELECT status,controller_owner,controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=?", f.publicID).Scan(&status, &claim, &lease); err != nil || status != "failed" || claim.Valid || lease.Valid {
		t.Fatal("original negative task did not converge to failed/released", status, err)
	}
}

func (f *dOriginalSixPartTask) checkOriginalPhysicalRecovery(ctx context.Context, t *testing.T, wantJobs int) {
	t.Helper()
	var writers, jobs, proofs int
	if err := f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND paused=TRUE AND resumed=TRUE", f.publicID).Scan(&writers); err != nil || writers != 4 {
		t.Fatal("original four writers not paused/resumed", writers, err)
	}
	if err := f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND revoked=TRUE AND stopped_at IS NOT NULL AND lifecycle='deleted'", f.publicID).Scan(&jobs); err != nil || jobs != wantJobs {
		t.Fatal("original collector stop journal", jobs, err)
	}
	if err := f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=?", f.publicID).Scan(&proofs); err != nil || proofs != wantJobs+2 {
		t.Fatal("original source/collector termination witnesses", proofs, err)
	}
	var ordered bool
	if err := f.control.QueryRowContext(ctx, "SELECT collectors_stopped_at IS NOT NULL AND source_resumed_at IS NOT NULL AND collectors_stopped_at<=source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", f.publicID).Scan(&ordered); err != nil || !ordered {
		t.Fatal("original stop/resume barrier order", err)
	}
	var phase string
	if err := f.control.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=?", f.service.Config.ApplicationScope).Scan(&phase); err != nil || phase != "idle" {
		t.Fatal("original application gate not released", phase, err)
	}
	for _, id := range []int{7, 9} {
		var status string
		var generation uint64
		var podName sql.NullString
		if err := f.control.QueryRowContext(ctx, "SELECT status,runtime_generation,pod_name FROM instances WHERE id=?", id).Scan(&status, &generation, &podName); err != nil {
			t.Fatal(err)
		}
		wantGeneration := uint64(3)
		if id == 9 {
			wantGeneration = 4
		}
		if generation != wantGeneration || id == 7 && (status != "running" || !podName.Valid || podName.String != "d-original-7") || id == 9 && (status != "stopped" || podName.Valid) {
			t.Fatal("original SQL runtime state not restored", id, status, generation)
		}
	}
	client := f.owner.Client.(*kubefake.Clientset)
	pod, err := client.CoreV1().Pods(f.owner.Namespace).Get(ctx, "d-original-7", metav1.GetOptions{})
	if err != nil || pod.UID == "d-original-7-uid" || pod.Status.Phase != corev1.PodRunning || pod.Annotations["backup.clawmanager.io/source-resume-fence"] == "" {
		t.Fatal("original Pro process not restarted under original fence", err)
	}
	deployment, err := client.AppsV1().Deployments(f.owner.Namespace).Get(ctx, "source", metav1.GetOptions{})
	if err != nil || deployment.UID != "dep-uid" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.ReadyReplicas != 1 || deployment.Status.ObservedGeneration != deployment.Generation {
		t.Fatal("original platform replicas/health not restored", err)
	}
	creates := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "pods" {
			creates++
			if action.(ktest.CreateAction).GetObject().(*corev1.Pod).Name != "d-original-7" {
				t.Fatal("previously stopped source was started")
			}
		}
	}
	if creates != 1 {
		t.Fatal("original source restart count", creates)
	}
}
