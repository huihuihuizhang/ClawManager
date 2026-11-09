package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestLonghornExecutionRejectsChangedFrozenRequest(t *testing.T) {
	request, err := kube.Snapshot(kube.Identity{Namespace: "tenant-user-1", Name: "sbk-cut-one", Owner: "backup-one"},
		"workspace", "local-cut", true)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := kube.Intent("VolumeSnapshot", request)
	if err != nil {
		t.Fatal(err)
	}
	var object unstructured.Unstructured
	if err := json.Unmarshal(expected.RequestJSON, &object); err != nil {
		t.Fatal(err)
	}
	actual, err := longhornExecutionIntent("VolumeSnapshot", &object)
	if err != nil || !sameLonghornExecutionIntent(actual, expected) {
		t.Fatal("original frozen request rejected", err)
	}
	if err := unstructured.SetNestedField(object.Object, "other-workspace", "spec", "source", "persistentVolumeClaimName"); err != nil {
		t.Fatal(err)
	}
	if _, err := longhornExecutionIntent("VolumeSnapshot", &object); err == nil {
		t.Fatal("changed source retained the original request authority")
	}
}

func TestLonghornExecutionDoesNotForwardOtherMutations(t *testing.T) {
	api := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	gvr := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotcontents"}
	wrapped := longhornExecutionDynamic{Interface: api, content: true}
	resource := wrapped.Resource(gvr)
	ctx := context.Background()
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind": "VolumeSnapshotContent", "metadata": map[string]any{"name": "foreign-content"}}}
	if _, err := resource.Update(ctx, object, metav1.UpdateOptions{}); err == nil {
		t.Fatal("update escaped the executor")
	}
	if _, err := resource.UpdateStatus(ctx, object, metav1.UpdateOptions{}); err == nil {
		t.Fatal("status update escaped the executor")
	}
	if _, err := resource.Patch(ctx, "foreign-content", types.MergePatchType, []byte("{}"), metav1.PatchOptions{}); err == nil {
		t.Fatal("patch escaped the executor")
	}
	if _, err := resource.Apply(ctx, "foreign-content", object, metav1.ApplyOptions{}); err == nil {
		t.Fatal("apply escaped the executor")
	}
	if _, err := resource.ApplyStatus(ctx, "foreign-content", object, metav1.ApplyOptions{}); err == nil {
		t.Fatal("status apply escaped the executor")
	}
	if err := resource.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{}); err == nil {
		t.Fatal("collection delete escaped the executor")
	}
	tenant := wrapped.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace("tenant-user-1")
	if _, err := tenant.Create(ctx, object, metav1.CreateOptions{}); err == nil {
		t.Fatal("unrelated resource escaped the executor")
	}
	if err := tenant.Delete(ctx, "foreign", metav1.DeleteOptions{}); err == nil {
		t.Fatal("unrelated delete escaped the executor")
	}
	if len(api.Actions()) != 0 {
		t.Fatal("a denied mutation reached the ordinary API client")
	}
}
