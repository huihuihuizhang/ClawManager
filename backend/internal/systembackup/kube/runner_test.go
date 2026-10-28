package kube

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

type testJournal struct {
	records                              map[string]ResourceRecord
	events                               []string
	failPrepare, failObserve, failDelete bool
}

func intentKey(i ResourceIntent) string {
	return i.Kind + "/" + i.Identity.Namespace + "/" + i.Identity.Name
}
func (j *testJournal) Prepare(_ context.Context, i ResourceIntent) (ResourceRecord, error) {
	j.events = append(j.events, "intent")
	if j.failPrepare {
		return ResourceRecord{}, errors.New("journal")
	}
	if j.records == nil {
		j.records = map[string]ResourceRecord{}
	}
	key := intentKey(i)
	if r, ok := j.records[key]; ok {
		if !sameIntent(r.Intent, i) {
			return r, errors.New("conflict")
		}
		return r, nil
	}
	r := ResourceRecord{Intent: i, Revision: 1}
	j.records[key] = r
	return r, nil
}
func (j *testJournal) RecordCreate(_ context.Context, r ResourceRecord) (ResourceRecord, error) {
	j.events = append(j.events, "create-intent")
	if j.records[intentKey(r.Intent)].Revision != r.Revision || r.CreateDispatched || r.Deleting || r.Deleted {
		return r, ErrJournal
	}
	r.CreateDispatched = true
	r.Revision++
	j.records[intentKey(r.Intent)] = r
	return r, nil
}
func (j *testJournal) Observe(_ context.Context, r ResourceRecord, uid, rv string) (ResourceRecord, error) {
	j.events = append(j.events, "observe")
	if j.failObserve {
		return r, errors.New("journal")
	}
	current := j.records[intentKey(r.Intent)]
	if current.Revision != r.Revision {
		return r, ErrJournal
	}
	if current.UID != "" && current.UID != uid {
		return r, ErrOwnership
	}
	current.UID = uid
	current.ResourceVersion = rv
	current.Revision++
	j.records[intentKey(r.Intent)] = current
	return current, nil
}
func (j *testJournal) RecordDelete(_ context.Context, r ResourceRecord) (ResourceRecord, error) {
	j.events = append(j.events, "delete-intent")
	if j.failDelete {
		return r, errors.New("journal")
	}
	if j.records[intentKey(r.Intent)].Revision != r.Revision {
		return r, ErrJournal
	}
	r.Deleting = true
	r.Revision++
	j.records[intentKey(r.Intent)] = r
	return r, nil
}
func (j *testJournal) RecordAbsent(_ context.Context, r ResourceRecord) error {
	j.events = append(j.events, "absent")
	if j.records[intentKey(r.Intent)].Revision != r.Revision {
		return ErrJournal
	}
	r.Deleted = true
	r.Revision++
	j.records[intentKey(r.Intent)] = r
	return nil
}
func runnerFixture(t *testing.T) (Runner, *fake.FakeDynamicClient, *testJournal, any) {
	t.Helper()
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	journal := &testJournal{}
	runner := Runner{Client: client, Journal: journal, CheckFence: func(context.Context) error { return nil }}
	job, e := Job(JobRequest{Identity: Identity{"cm-drill-fixture", "capture", "owner-123"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "capture", Command: []string{"/worker"}, Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}, StagingClaim: "staging", DeadlineSeconds: 120})
	if e != nil {
		t.Fatal(e)
	}
	client.PrependReactor("create", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
		journal.events = append(journal.events, "api-create")
		if len(journal.records) == 0 {
			t.Fatal("create without intent")
		}
		o := a.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		if !journal.records[o.GetKind()+"/"+o.GetNamespace()+"/"+o.GetName()].CreateDispatched {
			t.Fatal("create before dispatch intent")
		}
		o.SetUID("created-uid")
		o.SetResourceVersion("1")
		if e := client.Tracker().Create(a.GetResource(), o, a.GetNamespace()); e != nil {
			return true, nil, e
		}
		return true, o, nil
	})
	return runner, client, journal, job
}
func TestRunnerDurableIntentIdempotencyObserveAndUIDCleanup(t *testing.T) {
	r, client, journal, job := runnerFixture(t)
	ctx := context.Background()
	record, e := r.Ensure(ctx, "Job", job)
	if e != nil {
		t.Fatal(e)
	}
	if record.UID != "created-uid" {
		t.Fatal("UID not recorded")
	}
	if _, e = r.Ensure(ctx, "Job", job); e != nil {
		t.Fatal(e)
	}
	creates := 0
	for _, a := range client.Actions() {
		if a.GetVerb() == "create" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatal("duplicate create")
	}
	if ok, e := r.JobComplete(ctx, record); e != nil || ok {
		t.Fatal("empty status completed")
	}
	gvr, _, _ := resourceType("Job")
	o, e := client.Resource(gvr).Namespace(record.Intent.Identity.Namespace).Get(ctx, record.Intent.Identity.Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	unstructured.SetNestedSlice(o.Object, []any{map[string]any{"type": "Complete", "status": "True"}}, "status", "conditions")
	client.Tracker().Update(gvr, o, o.GetNamespace())
	if ok, e := r.JobComplete(ctx, record); e != nil || !ok {
		t.Fatal("valid completion not observed")
	}
	client.PrependReactor("delete", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		if journal.events[len(journal.events)-1] != "delete-intent" {
			t.Fatal("delete before journal")
		}
		return false, nil, nil
	})
	// client-go v0.32 dynamic/fake discards DeleteOptions. Intercept the actual
	// ResourceInterface call so preconditions are tested rather than assumed.
	r.Client = deleteCheckingClient{Interface: client, check: func(options metav1.DeleteOptions) {
		if options.Preconditions == nil || *options.Preconditions.UID != types.UID(record.UID) || *options.Preconditions.ResourceVersion != "1" {
			t.Fatal("delete missing identity preconditions")
		}
	}}
	if done, e := r.Cleanup(ctx, record); e != nil || !done {
		t.Fatal(e)
	}
	if !journal.records[intentKey(record.Intent)].Deleted {
		t.Fatal("absence not recorded")
	}
}

type deleteCheckingClient struct {
	dynamic.Interface
	check func(metav1.DeleteOptions)
}

func (c deleteCheckingClient) Resource(g schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return deleteCheckingNamespace{NamespaceableResourceInterface: c.Interface.Resource(g), check: c.check}
}

type deleteCheckingNamespace struct {
	dynamic.NamespaceableResourceInterface
	check func(metav1.DeleteOptions)
}

func (n deleteCheckingNamespace) Namespace(s string) dynamic.ResourceInterface {
	return deleteCheckingResource{ResourceInterface: n.NamespaceableResourceInterface.Namespace(s), check: n.check}
}

type deleteCheckingResource struct {
	dynamic.ResourceInterface
	check func(metav1.DeleteOptions)
}

func (r deleteCheckingResource) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	r.check(options)
	return r.ResourceInterface.Delete(ctx, name, options, subresources...)
}
func TestRunnerRecoversLostCreateReplyAndJournalWrite(t *testing.T) {
	for _, mode := range []string{"reply-lost", "observe-failed"} {
		t.Run(mode, func(t *testing.T) {
			r, client, journal, job := runnerFixture(t)
			if mode == "reply-lost" {
				client.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
					o := a.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
					o.SetUID("uncertain-uid")
					o.SetResourceVersion("1")
					client.Tracker().Create(a.GetResource(), o, a.GetNamespace())
					return true, nil, apierrors.NewTimeoutError("reply lost", 1)
				})
			} else {
				journal.failObserve = true
			}
			_, e := r.Ensure(context.Background(), "Job", job)
			if mode == "observe-failed" && e == nil {
				t.Fatal("journal failure ignored")
			}
			journal.failObserve = false
			record, e := r.Ensure(context.Background(), "Job", job)
			if e != nil || record.UID == "" {
				t.Fatal("cannot reconcile", e)
			}
			creates := 0
			for _, a := range client.Actions() {
				if a.GetVerb() == "create" {
					creates++
				}
			}
			if creates != 1 {
				t.Fatal("replayed create instead of reconciling")
			}
		})
	}
}
func TestRunnerRefusesResourceReplacementAndSpecDrift(t *testing.T) {
	for _, mode := range []string{"uid", "image", "injected-env", "owner", "delete-journal", "fence"} {
		t.Run(mode, func(t *testing.T) {
			r, client, journal, job := runnerFixture(t)
			record, e := r.Ensure(context.Background(), "Job", job)
			if e != nil {
				t.Fatal(e)
			}
			gvr, _, _ := resourceType("Job")
			o, _ := client.Resource(gvr).Namespace(record.Intent.Identity.Namespace).Get(context.Background(), record.Intent.Identity.Name, metav1.GetOptions{})
			switch mode {
			case "uid":
				o.SetUID("replacement")
			case "owner":
				o.SetLabels(map[string]string{OwnerLabel: "foreign"})
			case "image", "injected-env":
				containers, _, _ := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "containers")
				c := containers[0].(map[string]any)
				if mode == "image" {
					c["image"] = "malicious:latest"
				} else {
					c["env"] = []any{map[string]any{"name": "EXTRA", "value": "not-requested"}}
				}
				unstructured.SetNestedSlice(o.Object, containers, "spec", "template", "spec", "containers")
			case "delete-journal":
				journal.failDelete = true
			case "fence":
				r.CheckFence = func(context.Context) error { return errors.New("lost") }
			}
			client.Tracker().Update(gvr, o, o.GetNamespace())
			if _, e = r.Cleanup(context.Background(), record); e == nil {
				t.Fatal("unsafe cleanup succeeded")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() == "delete" {
					t.Fatal("deleted without ownership/fence/journal")
				}
			}
		})
	}
}
func TestRunnerDoesNotCreateWhenIntentFails(t *testing.T) {
	r, client, journal, job := runnerFixture(t)
	journal.failPrepare = true
	if _, e := r.Ensure(context.Background(), "Job", job); e == nil {
		t.Fatal("missing intent")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("API called before intent persisted")
	}
}

func TestUncertainCreateNotFoundIsNeitherRetriedNorCleaned(t *testing.T) {
	r, client, journal, job := runnerFixture(t)
	client.PrependReactor("create", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewTimeoutError("still in flight", 1)
	})
	record, e := r.Ensure(context.Background(), "Job", job)
	if !errors.Is(e, ErrPending) || !record.CreateDispatched {
		t.Fatal("missing uncertain dispatch record", e)
	}
	if _, e = r.Ensure(context.Background(), "Job", job); !errors.Is(e, ErrPending) {
		t.Fatal("reissued uncertain create")
	}
	if done, e := r.Cleanup(context.Background(), record); done || !errors.Is(e, ErrPending) {
		t.Fatal("404 treated as final absence")
	}
	creates := 0
	for _, a := range client.Actions() {
		if a.GetVerb() == "create" {
			creates++
		}
	}
	if creates != 1 || journal.records[intentKey(record.Intent)].Deleted {
		t.Fatal("lost uncertain resource")
	}
}

func TestRunnerRefusesMatchingResourceWithoutCreateProvenance(t *testing.T) {
	r, client, journal, job := runnerFixture(t)
	intent, object, err := freeze("Job", job)
	if err != nil {
		t.Fatal(err)
	}
	object.SetUID("preexisting-uid")
	object.SetResourceVersion("1")
	gvr, _, _ := resourceType("Job")
	if err = client.Tracker().Create(gvr, object, object.GetNamespace()); err != nil {
		t.Fatal(err)
	}
	record, err := r.Ensure(context.Background(), "Job", job)
	if !errors.Is(err, ErrOwnership) {
		t.Fatal("adopted unproven resource", err)
	}
	if done, err := r.Cleanup(context.Background(), record); done || !errors.Is(err, ErrOwnership) {
		t.Fatal("cleaned unproven resource", err)
	}
	if journal.records[intentKey(intent)].CreateDispatched {
		t.Fatal("invented create provenance")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("mutated preexisting resource")
		}
	}
}
