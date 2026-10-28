package quiesce

import (
	"context"
	"errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type retryWitnessStore struct {
	mu    sync.Mutex
	calls int
	proof ExitWitness
}

func (s *retryWitnessStore) Save(_ context.Context, p ExitWitness) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		return errors.New("transient write failure")
	}
	s.proof = p
	return nil
}
func (s *retryWitnessStore) Load(context.Context, string) (ExitWitness, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proof.PodUID == "" {
		return ExitWitness{}, errors.New("pending")
	}
	return s.proof, nil
}
func TestWitnessRetainsExplicitAckAcrossStoreFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id := PodIdentity{Name: "source", UID: "pod-uid", Node: "node", Containers: []string{"containerd://old"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: id.Name, Namespace: "backup", UID: "pod-uid", ResourceVersion: "1"}, Spec: corev1.PodSpec{NodeName: "node"}}
	client := fake.NewSimpleClientset(pod, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid"}})
	watchClient := fake.NewSimpleClientset()
	stream := watch.NewRaceFreeFake()
	var armed atomic.Bool
	client.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		t.Error("ordinary timeout client used for witness stream")
		return true, nil, errors.New("wrong client")
	})
	watchClient.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) { armed.Store(true); return true, stream, nil })
	store := &retryWitnessStore{}
	w := KubeletStopWitness{Client: client, Watches: watchClient, Namespace: "backup", NodeUIDs: map[string]string{"node": "node-uid"}, Store: store, Timeout: time.Second}
	if e := w.Arm(ctx, []PodIdentity{id}); e != nil || !armed.Load() {
		t.Fatal("watch was not armed", e)
	}
	terminated := pod.DeepCopy()
	terminated.ResourceVersion = "2"
	terminated.Status.ContainerStatuses = []corev1.ContainerStatus{{ContainerID: id.Containers[0], State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: id.Containers[0], FinishedAt: metav1.Now()}}}}
	stream.Modify(terminated)
	for {
		if w.Confirm(ctx, []PodIdentity{id}) == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("termination acknowledgement lost after SQL failure")
		case <-time.After(10 * time.Millisecond):
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.calls != 2 || store.proof.ResourceVersion != "2" {
		t.Fatal("did not retry original acknowledgement")
	}
}

func TestKubeletWitnessRequiresExplicitOriginalContainerTermination(t *testing.T) {
	for _, scenario := range []string{"valid", "deleted-without-ack", "running", "wrong-pod", "wrong-node", "wrong-container", "zero-finished", "restarted", "extra-running"} {
		t.Run(scenario, func(t *testing.T) {
			finished := metav1.NewTime(time.Now().UTC())
			id := "containerd://original"
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "backup", UID: "original-pod", ResourceVersion: "20"}, Spec: corev1.PodSpec{NodeName: "original-node"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{ContainerID: id, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: id, FinishedAt: finished}}}}}}
			switch scenario {
			case "deleted-without-ack":
				pod.DeletionTimestamp = &finished
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{}
			case "running":
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
			case "wrong-pod":
				pod.UID = "new-pod"
			case "wrong-node":
				pod.Spec.NodeName = "new-node"
			case "wrong-container":
				pod.Status.ContainerStatuses[0].ContainerID = "foreign"
			case "zero-finished":
				pod.Status.ContainerStatuses[0].State.Terminated.FinishedAt = metav1.Time{}
			case "restarted":
				pod.Status.ContainerStatuses[0].ContainerID = "containerd://new"
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
			case "extra-running":
				pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{ContainerID: "injected", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
			}
			proof, ok := witnessFor(pod, PodIdentity{Name: "source", UID: "original-pod", Node: "original-node", Containers: []string{id}}, "original-node-uid")
			if (scenario == "valid") != ok {
				t.Fatal("unexpected termination decision", ok)
			}
			if ok && (proof.PodUID != "original-pod" || proof.Containers[id].IsZero()) {
				t.Fatal("unbound witness")
			}
		})
	}
}
