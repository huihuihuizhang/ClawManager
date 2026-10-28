package quiesce

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

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
