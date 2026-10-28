package control

import (
	"context"
	"database/sql/driver"
	"testing"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNeverReadyWorkerNeedsNoIssuedKeyAndDeletedJob(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		until                 int64
		revoked, pod, success bool
	}{{"never granted", 0, true, false, true}, {"key already issued", 1, true, false, false}, {"grant not revoked", 0, false, false, false}, {"pod survives", 0, true, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			task, g, _ := grantFixture()
			steps := []sqlStep{{contains: "SELECT COUNT(*) FROM system_backup_worker_processes", rows: [][]driver.Value{{int64(0)}}}, {contains: "SELECT acquired_until_ms,revoked", rows: [][]driver.Value{{tc.until, tc.revoked}}}}
			if tc.success {
				steps = append(steps, workerCommit(task)...)
			}
			store, script := scriptStore(t, steps...)
			client := fake.NewSimpleClientset()
			if tc.pod {
				client.CoreV1().Pods(g.JobNamespace).Create(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "remaining", Namespace: g.JobNamespace, Labels: map[string]string{"batch.kubernetes.io/controller-uid": g.JobUID}}}, metav1.CreateOptions{})
			}
			live := LiveWorkers{Store: store, Observer: kube.WorkerObserver{Client: client}}
			r := kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: g.JobNamespace, Name: g.JobName, Owner: task.ID}}, UID: g.JobUID, Deleted: true, CreateDispatched: true}
			e := live.StoppedOrNeverGranted(context.Background(), task, g, r)
			if (e == nil) != tc.success || script.writes != 0 {
				t.Fatal("unexpected cleanup proof", e)
			}
		})
	}
}
