package install

import (
	"context"
	"reflect"
	"sort"

	q "clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalRecoveryPeerPin struct {
	Writer, Namespace, Name, UID, ResourceVersion, ControllerUID, ControllerVersion, SpecSHA256 string
	Process                                                                                     q.PodIdentity
}

type originalRecoveryPeerSnapshot struct {
	Pods []q.PodIdentity
	Pins []originalRecoveryPeerPin
}

// Actual peers are derived ONLY through original private writer objects and
// real API owner graphs. A namespace-wide list cannot assign a foreign Pod to
// an original writer. The snapshot is re-read after native I/O, outside SQL.
func (s *PreparedOriginalWriterSet) readOriginalRecoveryPeers(ctx context.Context, fence *originalWriterRecoveryFence, node *originalWholeNodeScope, affected []q.PodIdentity) (originalRecoveryPeerSnapshot, error) {
	result := originalRecoveryPeerSnapshot{Pods: []q.PodIdentity{}, Pins: []originalRecoveryPeerPin{}}
	if fence.checkReleasing(ctx) != nil || node == nil || node.set != s || node.prepare == nil {
		return result, ErrInstall
	}
	targets := map[string]bool{}
	original := map[string]bool{}
	for _, pod := range node.request.Pods {
		original[pod.UID] = true
	}
	for _, pod := range affected {
		if !original[pod.UID] || targets[pod.UID] {
			return result, ErrInstall
		}
		targets[pod.UID] = true
	}
	k := fence.operator.installer.kube
	covered := map[string]bool{}
	seen := map[string]bool{}
	add := func(writer, controllerUID, controllerRV, spec string, pod *corev1.Pod) error {
		process, running, err := originalRecoveryPeerProcess(pod)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		if process.Node != node.request.Binding.Node || seen[process.UID] {
			return ErrInstall
		}
		seen[process.UID] = true
		result.Pods = append(result.Pods, process)
		result.Pins = append(result.Pins, originalRecoveryPeerPin{writer, pod.Namespace, pod.Name, string(pod.UID), pod.ResourceVersion, controllerUID, controllerRV, spec, process})
		return nil
	}
	for _, writer := range s.deployments {
		member, target := false, false
		for _, old := range writer.pods {
			if original[old.UID] {
				covered[old.UID] = true
				member = true
			}
			target = target || targets[old.UID]
		}
		if !member || target {
			continue
		}
		deployment, err := k.AppsV1().Deployments(writer.namespace).Get(ctx, writer.selection.Name, metav1.GetOptions{})
		if err != nil || string(deployment.UID) != writer.selection.UID || deployment.ResourceVersion == "" || deployment.DeletionTimestamp != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 && *deployment.Spec.Replicas != writer.replicas || originalDeploymentSpecSHA(deployment) != writer.specSHA {
			return result, ErrInstall
		}
		// currentPods verifies selector -> sole controlling ReplicaSet -> the exact
		// original Deployment UID. It never adopts an arbitrary matching label.
		if len(affected) == 0 && writer.stopDispatched && deployment.Annotations[originalDeploymentRecoveryAnnotation] != s.owner.operation {
			return result, ErrInstall
		}
		pods, err := writer.currentPods(ctx, deployment, false)
		if err != nil {
			return result, err
		}
		for _, identity := range pods {
			pod, err := k.CoreV1().Pods(writer.namespace).Get(ctx, identity.Name, metav1.GetOptions{})
			if err != nil || string(pod.UID) != identity.UID {
				return result, ErrInstall
			}
			process, running, e := originalRecoveryPeerProcess(pod)
			found := false
			for _, old := range writer.pods {
				found = found || reflect.DeepEqual(process, old)
			}
			if e != nil || running && !found && (!writer.stopDispatched || deployment.Annotations[originalDeploymentRecoveryAnnotation] != s.owner.operation) {
				return result, ErrInstall
			}
			if err := add(writer.ID(), string(deployment.UID), deployment.ResourceVersion, writer.specSHA, pod); err != nil {
				return result, err
			}
		}
	}
	for _, writer := range s.proPods {
		if !original[writer.original.UID] {
			continue
		}
		covered[writer.original.UID] = true
		if targets[writer.original.UID] {
			continue
		}
		pod, err := k.CoreV1().Pods(writer.source.Namespace).Get(ctx, writer.source.Pod, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil || pod.ResourceVersion == "" || len(pod.OwnerReferences) != 0 || originalObjectSHA(pod.Spec) != writer.specSHA {
			return result, ErrInstall
		}
		if string(pod.UID) != writer.original.UID && (!writer.createDispatched || pod.Annotations[originalDeploymentRecoveryAnnotation] != s.owner.operation) {
			return result, ErrInstall
		}
		if len(affected) == 0 && writer.stopDispatched && pod.Annotations[originalDeploymentRecoveryAnnotation] != s.owner.operation {
			return result, ErrInstall
		}
		if !writer.stopDispatched {
			process, running, e := originalRecoveryPeerProcess(pod)
			if e != nil || !running || !reflect.DeepEqual(process, writer.process) {
				return result, ErrInstall
			}
		}
		if err := add(writer.ID(), "", "", writer.specSHA, pod); err != nil {
			return result, err
		}
	}
	for uid := range original {
		if !covered[uid] {
			return result, ErrInstall
		}
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].UID < result.Pods[j].UID })
	sort.Slice(result.Pins, func(i, j int) bool { return result.Pins[i].UID < result.Pins[j].UID })
	if fence.checkReleasing(ctx) != nil {
		return result, ErrInstall
	}
	return result, nil
}

// A peer observation is current process DATA, not a readiness or recovered ACK.
// Terminating/temporarily unready ORIGINAL peers may still be running while a
// different affected source is recovered. Native B independently checks their
// exact CRI/PID/start/ns/cgroup. Final release still requires original readiness.
func originalRecoveryPeerProcess(pod *corev1.Pod) (q.PodIdentity, bool, error) {
	var zero q.PodIdentity
	if pod == nil || pod.UID == "" || pod.ResourceVersion == "" || len(pod.Spec.EphemeralContainers) != 0 {
		return zero, false, ErrInstall
	}
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return zero, false, nil
	}
	if pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || len(pod.Status.ContainerStatuses) != len(pod.Spec.Containers) {
		return zero, false, ErrInstall
	}
	process := q.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName}
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...)
	for _, status := range pod.Status.InitContainerStatuses {
		if status.State.Running != nil {
			statuses = append(statuses, status)
		} else if status.State.Terminated == nil {
			return zero, false, ErrInstall
		}
	}
	for _, status := range statuses {
		if status.ContainerID == "" || status.State.Running == nil {
			return zero, false, ErrInstall
		}
		process.Containers = append(process.Containers, status.ContainerID)
	}
	sort.Strings(process.Containers)
	if len(process.Containers) == 0 {
		return zero, false, ErrInstall
	}
	return process, true, nil
}

func sameOriginalRecoveryPeers(a, b originalRecoveryPeerSnapshot) bool {
	return reflect.DeepEqual(a, b)
}
