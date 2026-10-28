package control

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

type deletedJobJournal struct{ record kube.ResourceRecord }

func (j deletedJobJournal) Prepare(context.Context, kube.ResourceIntent) (kube.ResourceRecord, error) {
	return j.record, nil
}
func (j deletedJobJournal) RecordCreate(context.Context, kube.ResourceRecord) (kube.ResourceRecord, error) {
	panic("unexpected CREATE during recovery")
}
func (j deletedJobJournal) Observe(context.Context, kube.ResourceRecord, string, string) (kube.ResourceRecord, error) {
	panic("unexpected observe")
}
func (j deletedJobJournal) RecordDelete(context.Context, kube.ResourceRecord) (kube.ResourceRecord, error) {
	panic("already deleted")
}
func (j deletedJobJournal) RecordAbsent(context.Context, kube.ResourceRecord) error {
	panic("already deleted")
}

func TestCollectorMissingJobIsNotProcessTerminationProof(t *testing.T) {
	for _, proof := range []bool{false, true} {
		t.Run(map[bool]string{false: "partitioned-node", true: "runtime-confirmed"}[proof], func(t *testing.T) {
			task, grant, _ := grantFixture()
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: grant.JobName, Namespace: grant.JobNamespace, Labels: map[string]string{kube.OwnerLabel: "owner-one"}}}
			intent, e := kube.Intent("Job", job)
			if e != nil {
				t.Fatal(e)
			}
			record := kube.ResourceRecord{Intent: intent, UID: grant.JobUID, Revision: 3, ResourceVersion: "three", CreateDispatched: true, Deleted: true}
			steps := workerCommit(task)
			steps = append(steps, sqlStep{contains: "SELECT terminated", rows: [][]driver.Value{{false}}}, sqlStep{contains: "SET revoked=TRUE", affected: 1})
			steps = append(steps, workerCommit(task)...)
			if proof {
				steps = append(steps, workerCommit(task)...)
				steps = append(steps, sqlStep{contains: "SET terminated=TRUE", affected: 1})
				steps = append(steps, workerCommit(task)...)
			}
			store, script := scriptStore(t, steps...)
			collector := JobCollector{Store: store, Task: task, Job: job, Grant: grant, PartID: "instance-1", CleanupRunner: kube.Runner{Client: fake.NewSimpleDynamicClient(runtime.NewScheme()), Journal: deletedJobJournal{record}, CheckFence: func(context.Context) error { return nil }}, StopProof: func(_ context.Context, g WorkerGrant, r kube.ResourceRecord) error {
				if g.JobUID != grant.JobUID || r.UID != grant.JobUID {
					t.Fatal("wrong worker proof")
				}
				if !proof {
					return ErrNotReady
				}
				return nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e = collector.Stop(ctx)
			if proof {
				if e != nil || script.writes != 2 {
					t.Fatal("confirmed termination not persisted", e)
				}
			} else if e == nil || script.writes != 1 {
				t.Fatal("Job disappearance accepted as process death")
			}
		})
	}
}
