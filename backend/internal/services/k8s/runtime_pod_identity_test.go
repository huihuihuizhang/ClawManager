package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestRuntimePodIdentityReadsTerminatingAndTerminalPods(t *testing.T) {
	for _, tc := range []struct {
		name, uid                         string
		deleted, terminal, absent, denied bool
		present                           bool
	}{
		{name: "live", uid: "old", present: true},
		{name: "terminating", uid: "old", deleted: true, present: true},
		{name: "terminal", uid: "old", terminal: true, present: true},
		{name: "name reused", uid: "replacement"},
		{name: "absent", absent: true},
		{name: "forbidden", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			if !tc.absent {
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "hermes-old", Namespace: "system", UID: types.UID(tc.uid)}}
				if tc.deleted {
					now := metav1.Now()
					pod.DeletionTimestamp = &now
				}
				if tc.terminal {
					pod.Status.Phase = corev1.PodSucceeded
				}
				if _, err := client.CoreV1().Pods("system").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.denied {
				client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "hermes-old", nil)
				})
			}
			reader := NewRuntimeDeploymentService(client).(RuntimePodIdentityReader)
			present, err := reader.RuntimePodUIDPresent(context.Background(), "system", "hermes-old", "old")
			if tc.denied {
				if !apierrors.IsForbidden(err) {
					t.Fatalf("permission failure became absence: %v", err)
				}
				return
			}
			if err != nil || present != tc.present {
				t.Fatalf("present=%v err=%v", present, err)
			}
		})
	}
}
