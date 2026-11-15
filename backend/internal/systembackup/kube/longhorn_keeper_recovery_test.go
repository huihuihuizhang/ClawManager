package kube

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

type keeperLostObserveJournal struct {
	*testJournal
	lose bool
}

func (j *keeperLostObserveJournal) Observe(ctx context.Context, r ResourceRecord, uid, rv string) (ResourceRecord, error) {
	if j.lose {
		return ResourceRecord{}, ErrJournal
	}
	return j.testJournal.Observe(ctx, r, uid, rv)
}

// The real resource Runner is exercised against a Kubernetes protocol model.
// Neither successful cleanup nor this test is a physical volume release proof.
func TestLonghornKeeperRecoveryRetainsIntentAfterCreateObservationLoss(t *testing.T) {
	for _, outcome := range []string{"created-observe-lost", "create-unknown-absent"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := context.Background()
			client := fake.NewSimpleDynamicClient(runtime.NewScheme())
			journal := &keeperLostObserveJournal{testJournal: &testJournal{}, lose: true}
			runner := Runner{Client: client, Journal: journal, CheckFence: func(context.Context) error { return nil }}
			job, err := LonghornAttachmentKeeperJob(LonghornAttachmentKeeper{Identity: Identity{Namespace: "tenant", Name: "keeper", Owner: "adoption-original"}, NamespaceUID: "namespace", Node: "node", NodeUID: "node-uid", ServiceAccount: "default", Image: "owner@sha256:" + strings.Repeat("a", 64), Executable: "/backup-shared-runtime-node-owner", Source: MountIdentity{Kind: "PersistentVolumeClaim", Name: "pro", UID: "pvc-uid"}})
			if err != nil {
				t.Fatal(err)
			}
			intent, err := Intent(LonghornKeeperResource, job)
			if err != nil {
				t.Fatal(err)
			}
			creates := 0
			client.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
				creates++
				if !journal.records[intentKey(intent)].CreateDispatched {
					t.Fatal("create before durable intent")
				}
				if outcome == "create-unknown-absent" {
					return true, nil, errors.New("lost create reply")
				}
				o := a.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
				o.SetUID("actual-keeper-job")
				o.SetResourceVersion("1")
				if err := client.Tracker().Create(a.GetResource(), o, a.GetNamespace()); err != nil {
					t.Fatal(err)
				}
				return true, o, nil
			})
			retained := ResourceRecord{Intent: intent}
			record, err := runner.Ensure(ctx, LonghornKeeperResource, job)
			if err == nil || creates != 1 {
				t.Fatal("missing injected failure or repeated create", err)
			}
			if record.Intent.Kind != "" {
				retained = record
			}
			journal.lose = false
			deletes := 0
			runner.Client = deleteCheckingClient{Interface: client, check: func(o metav1.DeleteOptions) {
				deletes++
				if o.Preconditions == nil || o.Preconditions.UID == nil || string(*o.Preconditions.UID) != "actual-keeper-job" || o.Preconditions.ResourceVersion == nil || *o.Preconditions.ResourceVersion != "1" {
					t.Fatal("cleanup did not bind actual UID and RV")
				}
			}}
			done, err := runner.Cleanup(ctx, retained)
			if outcome == "create-unknown-absent" {
				if done || !errors.Is(err, ErrPending) || deletes != 0 || journal.records[intentKey(intent)].Deleted {
					t.Fatal("unknown create converted to absence", err)
				}
			} else if err != nil || !done || deletes != 1 || !journal.records[intentKey(intent)].Deleted {
				t.Fatal("original intent could not reconcile actual keeper", err)
			}
			if creates != 1 {
				t.Fatal("recovery recreated keeper")
			}
		})
	}
}
