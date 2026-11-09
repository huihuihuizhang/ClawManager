package kube

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestLonghornSnapshotAliasBindsExactRetainedContent(t *testing.T) {
	ctx := context.Background()
	id := Identity{Namespace: "system", Name: "source-ref", Owner: "backup-1"}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: id.Namespace, UID: "system-uid"}})
	pin := LonghornSnapshotPin{NamespaceUID: "tenant-uid", AccessMode: corev1.ReadWriteOnce,
		BackendSnapshotHandle: "snap://source-pvc/snapshot-at-cut",
		Snapshot:              ResourceRecord{UID: "original-snapshot-uid", Intent: ResourceIntent{Identity: Identity{Namespace: "tenant", Name: "original", Owner: id.Owner}}}}
	request, err := longhornAliasRequest(ctx, client, pin, id, "system-uid")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := Intent("VolumeSnapshot", request)
	if err != nil {
		t.Fatal(err)
	}
	pin.Alias = &LonghornSnapshotAliasPin{NamespaceUID: "system-uid",
		Snapshot: ResourceRecord{Intent: intent, CreateDispatched: true, UID: "alias-snapshot-uid"}}
	snapshot := &unstructured.Unstructured{}
	if err := json.Unmarshal(intent.RequestJSON, &snapshot.Object); err != nil {
		t.Fatal(err)
	}
	snapshot.SetUID("alias-snapshot-uid")
	snapshot.SetResourceVersion("1")
	cut := longhornSourceCut{contentUID: "original-content-uid", contentSHA256: "original-content-digest"}
	api := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), snapshot)
	_, content, err := longhornAliasObjects(ctx, client, api, pin, cut)
	if err != nil {
		t.Fatal(err)
	}
	if got := longhornSnapshotString(content, "spec", "deletionPolicy"); got != "Retain" {
		t.Fatalf("content deletion policy = %q", got)
	}
	runner := Runner{Client: api, Journal: &testJournal{}, CheckFence: func(context.Context) error { return nil }}
	if _, err := runner.Ensure(ctx, "VolumeSnapshotContent", content); err != ErrOwnership || len(api.Actions()) != 1 {
		t.Fatalf("unauthorized content request = %v, actions = %v", err, api.Actions())
	}
	expected, err := Intent("VolumeSnapshotContent", content)
	if err != nil || !validateIntent(expected) || expected.Identity.Namespace != id.Namespace {
		t.Fatalf("content intent is not valid and scoped: %v", err)
	}
	runner.AuthorizeRetainedContent = func(_ context.Context, got ResourceIntent) error {
		if !sameIntent(got, expected) {
			return ErrOwnership
		}
		return nil
	}
	api.PrependReactor("create", "volumesnapshotcontents", func(a ktesting.Action) (bool, runtime.Object, error) {
		obj := a.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		if a.GetNamespace() != "" || obj.GetNamespace() != "" || !runner.Journal.(*testJournal).records[intentKey(expected)].CreateDispatched {
			t.Fatal("content dispatch must be journaled and cluster scoped")
		}
		obj.SetUID("alias-content-uid")
		obj.SetResourceVersion("2")
		if err := api.Tracker().Create(a.GetResource(), obj, ""); err != nil {
			return true, nil, err
		}
		return true, obj, nil
	})
	if pin.Alias.Content, err = runner.Ensure(ctx, "VolumeSnapshotContent", content); err != nil {
		t.Fatal(err)
	}
	content, err = api.Resource(longhornSnapshotResource("volumesnapshotcontents")).Get(ctx, content.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Object["status"] = map[string]any{"readyToUse": true, "boundVolumeSnapshotContentName": content.GetName()}
	content.Object["status"] = map[string]any{"readyToUse": true, "snapshotHandle": pin.BackendSnapshotHandle}
	for _, tc := range []struct {
		name   string
		change func(*unstructured.Unstructured, *unstructured.Unstructured)
		want   error
	}{
		{"exact", func(_, _ *unstructured.Unstructured) {}, nil},
		{"delete policy", func(_, c *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(c.Object, "Delete", "spec", "deletionPolicy")
		}, ErrOwnership},
		{"wrong source", func(_, c *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(c.Object, "snap://source-pvc/older", "status", "snapshotHandle")
		}, ErrOwnership},
		{"wrong snapshot UID", func(_, c *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(c.Object, "another", "spec", "volumeSnapshotRef", "uid")
		}, ErrOwnership},
		{"replaced content", func(_, c *unstructured.Unstructured) { c.SetUID("replacement") }, ErrOwnership},
		{"not ready", func(s, _ *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(s.Object, false, "status", "readyToUse")
		}, ErrPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c := snapshot.DeepCopy(), content.DeepCopy()
			tc.change(s, c)
			api := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), s, c)
			if err := verifyLonghornSnapshotAlias(ctx, client, api, pin, cut); err != tc.want {
				t.Fatalf("alias readback = %v, want %v", err, tc.want)
			}
		})
	}
	if deleted, err := runner.Cleanup(ctx, pin.Alias.Content); err != ErrPending || deleted {
		t.Fatalf("content cleanup while the reference exists = %t, %v", deleted, err)
	}
	if err := api.Resource(longhornSnapshotResource("volumesnapshots")).Namespace(id.Namespace).Delete(ctx, id.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if deleted, err := runner.Cleanup(ctx, pin.Alias.Content); err != nil || !deleted {
		t.Fatalf("content cleanup = %t, %v", deleted, err)
	}
}
