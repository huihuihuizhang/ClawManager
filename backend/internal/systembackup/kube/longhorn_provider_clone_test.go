package kube

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLonghornProviderCloneReadback(t *testing.T) {
	const (
		providerNamespace = "longhorn-system"
		providerUID       = "provider-uid"
		source            = "original-pvc"
		snapshot          = "snapshot-at-cut"
		clone             = "clone-pvc"
	)
	pin := LonghornSnapshotPin{ProviderNamespace: providerNamespace, ProviderNamespaceUID: providerUID, SourceHandle: source, BackendSnapshotHandle: "snap://" + source + "/" + snapshot}
	for _, test := range []struct {
		name, namespaceUID, source, snapshot, state string
		want                                        error
	}{
		{"completed", providerUID, source, snapshot, "completed", nil},
		{"not initiated", providerUID, "", "", "", ErrPending},
		{"copying", providerUID, source, snapshot, "initiated", ErrPending},
		{"awaiting healthy", providerUID, source, snapshot, "copy-completed-awaiting-healthy", ErrPending},
		{"failed", providerUID, source, snapshot, "failed", ErrOwnership},
		{"different original volume", providerUID, "other-pvc", snapshot, "completed", ErrOwnership},
		{"different snapshot", providerUID, source, "older-snapshot", "completed", ErrOwnership},
		{"replaced namespace", "replacement", source, snapshot, "completed", ErrOwnership},
	} {
		t.Run(test.name, func(t *testing.T) {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: providerNamespace, UID: types.UID(test.namespaceUID)}}
			client := fake.NewSimpleClientset(ns)
			volume := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "longhorn.io/v1beta2", "kind": "Volume",
				"metadata": map[string]any{"name": clone, "namespace": providerNamespace, "uid": "clone-uid"},
				"status":   map[string]any{"cloneStatus": map[string]any{"sourceVolume": test.source, "snapshot": test.snapshot, "state": test.state}},
			}}
			api := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), volume)
			uid, err := verifyLonghornProviderClone(context.Background(), client, api, pin, clone)
			if err != test.want || (err == nil && uid != "clone-uid") || (err != nil && uid != "") {
				t.Fatalf("clone readback = %q, %v, want error %v", uid, err, test.want)
			}
		})
	}
}
