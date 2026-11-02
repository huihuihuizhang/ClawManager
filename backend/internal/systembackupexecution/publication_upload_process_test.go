package systembackupexecution

import (
	"clawreef/internal/systembackup/quiesce"
	"context"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Explicit fake-API process data for the real local upload/result invocation.
// This does not insert a process identity, stop proof, C receipt or authority.
func aOriginalPublicationRunningPod(t *testing.T, client *kubefake.Clientset, cfg DeploymentConfig, pod *corev1.Pod) {
	t.Helper()
	nodes := []string{}
	for name := range cfg.Security.NodeUIDs {
		nodes = append(nodes, name)
	}
	sort.Strings(nodes)
	if len(nodes) == 0 {
		t.Fatal("original admitted node pins required")
	}
	pod.Spec.NodeName = nodes[0]
	pod.ResourceVersion = "original-upload-running"
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, ContainerID: "containerd://" + string(pod.UID), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}}
	if _, err := client.CoreV1().Nodes().Get(context.Background(), nodes[0], metav1.GetOptions{}); apierrors.IsNotFound(err) {
		if err = client.Tracker().Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodes[0], UID: types.UID(cfg.Security.NodeUIDs[nodes[0]])}}); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestPublicationOriginalUploadIdentitySurvivesCurrentDiscoveryChanges(t *testing.T) {
	for _, mode := range []string{"exact", "orphan-running-original-with-replacement", "missing-original", "changed-owner", "changed-label", "replacement-only", "changed-container", "changed-node", "restarted", "duplicate-status"} {
		t.Run(mode, func(t *testing.T) {
			job, original, m, a := publicationUploadExitData(t)
			m.Installation = "installation_process_DATA"
			m.Attempt = 1
			original.Status.Phase = corev1.PodRunning
			original.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Minute))}}
			process, err := publicationUploadProcessData(job, &original, m, "publisher-sa-uid", "original-node-uid")
			if err != nil {
				t.Fatal("live native process DATA", err)
			}
			process.ObservedAt = a.BoundAt.Add(time.Second)
			a.ExpiresAt = process.ObservedAt.Add(time.Minute)
			if !process.valid(m, a) {
				t.Fatal("original authenticated process DATA rejected")
			}
			original.Status.Phase = corev1.PodSucceeded
			original.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: original.Status.ContainerStatuses[0].ContainerID, FinishedAt: metav1.NewTime(time.Now().Add(-time.Second)), ExitCode: 0}}
			pods := []corev1.Pod{original}
			switch mode {
			case "orphan-running-original-with-replacement":
				replacement := original.DeepCopy()
				replacement.UID = "replacement"
				replacement.Name += "-replacement"
				replacement.Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
				replacement.Status.ContainerStatuses[0].State.Terminated.ContainerID = "containerd://replacement"
				pods[0].OwnerReferences = nil
				pods[0].Labels = nil
				pods[0].Status.Phase = corev1.PodRunning
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
				pods = append(pods, *replacement)
			case "missing-original":
				pods = nil
			case "changed-owner":
				pods[0].OwnerReferences = nil
			case "changed-label":
				pods[0].Labels = nil
			case "replacement-only":
				pods[0].UID = "replacement"
				pods[0].Name += "-replacement"
			case "changed-container":
				pods[0].Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
				pods[0].Status.ContainerStatuses[0].State.Terminated.ContainerID = "containerd://replacement"
			case "changed-node":
				pods[0].Spec.NodeName = "replacement-node"
			case "restarted":
				pods[0].Status.ContainerStatuses[0].RestartCount = 1
			case "duplicate-status":
				pods[0].Status.ContainerStatuses = append(pods[0].Status.ContainerStatuses, pods[0].Status.ContainerStatuses[0])
			}
			actual, err := publicationOriginalUploadExitPods(job, pods, process)
			if mode == "exact" {
				if err != nil || len(actual) != 1 || actual[0].UID != process.Pod.UID {
					t.Fatal("same original stopped process rejected", err)
				}
				return
			}
			if err == nil || actual != nil {
				t.Fatal("replaced/orphaned original process accepted", mode)
			}
		})
	}
}

func TestPublicationOriginalUploadMessagesCannotReplaceFirstIdentity(t *testing.T) {
	job, pod, m, _ := publicationUploadExitData(t)
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}
	original, err := publicationUploadProcessData(job, &pod, m, "sa-original", "node-original")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"same", "new-api-version", "pod-uid", "pod-name", "container-id", "node-uid", "node-name", "job-uid", "generation", "service-account"} {
		t.Run(mode, func(t *testing.T) {
			changed := original
			changed.Pod.Containers = append([]string(nil), original.Pod.Containers...)
			switch mode {
			case "new-api-version":
				changed.FirstResourceVersion = "later-rv"
				changed.ObservedAt = time.Now()
			case "pod-uid":
				changed.Pod.UID = "foreign"
			case "pod-name":
				changed.Pod.Name = "foreign"
			case "container-id":
				changed.Pod.Containers[0] = "foreign"
			case "node-uid":
				changed.NodeUID = "foreign"
			case "node-name":
				changed.Pod.Node = "foreign"
			case "job-uid":
				changed.JobUID = "foreign"
			case "generation":
				changed.Generation++
			case "service-account":
				changed.ServiceAccountUID = "foreign"
			}
			if samePublicationUploadProcess(original, changed) != (mode == "same" || mode == "new-api-version") {
				t.Fatal("later result replaced original identity", mode)
			}
		})
	}
}

func TestPublicationFirstProcessCannotIgnoreAnotherPrivateGrantHolder(t *testing.T) {
	job, pod, _, _ := publicationUploadExitData(t)
	process := publicationUploadProcess{Pod: quiesce.PodIdentity{UID: string(pod.UID), Name: pod.Name}}
	if !publicationOnlyOriginalUploader(job, []corev1.Pod{pod}, process) {
		t.Fatal("sole original API Pod rejected")
	}
	orphan := pod.DeepCopy()
	orphan.UID = "other-original-grant-holder"
	orphan.Name = "unrelated-name"
	orphan.OwnerReferences = nil
	orphan.Labels = nil
	orphan.Spec.ServiceAccountName = "unrelated-service-account"
	if publicationOnlyOriginalUploader(job, []corev1.Pod{pod, *orphan}, process) {
		t.Fatal("another holder of original private upload Secret was ignored")
	}
	if _, err := publicationUploadPodIdentities(job, []corev1.Pod{pod, *orphan}); err == nil {
		t.Fatal("orphaned original grant holder omitted at exit")
	}
	if publicationOnlyOriginalUploader(job, []corev1.Pod{*orphan}, process) {
		t.Fatal("replacement admitted before first process was registered")
	}
}

func TestPublicationOriginalProcessReadsActualPinnedNodeAPI(t *testing.T) {
	for _, fault := range []string{"current", "other-known-node", "node-replaced", "claim-replaced", "controller-exited", "binding-deleted", "expired-context", "missing-binding"} {
		t.Run(fault, func(t *testing.T) {
			service, client, controller, node, claim, pv := stagingLocationFixture()
			job, pod, m, _ := publicationUploadExitData(t)
			job.Namespace, pod.Namespace, m.Namespace = service.Config.Namespace, service.Config.Namespace, service.Config.Namespace
			pod.Spec.NodeName = node.Name
			pod.Status.Phase = corev1.PodRunning
			pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}
			service.Config.PublicationWorker = &PublicationWorkerReference{ServiceAccountUID: "publisher-sa"}
			ctx := context.Background()
			switch fault {
			case "other-known-node":
				other := node.DeepCopy()
				other.Name, other.UID = "other-known-node", "other-known-uid"
				service.Config.Security.NodeUIDs[other.Name] = string(other.UID)
				if err := client.Tracker().Add(other); err != nil {
					t.Fatal(err)
				}
				pod.Spec.NodeName = other.Name
			case "node-replaced":
				node.UID = "replacement-node"
				if _, err := client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "claim-replaced":
				claim.UID = "replacement-claim"
				if _, err := client.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "controller-exited":
				controller.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
				if _, err := client.CoreV1().Pods(controller.Namespace).Update(ctx, controller, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "binding-deleted":
				if err := client.CoreV1().PersistentVolumes().Delete(ctx, pv.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			case "expired-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "missing-binding":
				service.Config.StagingLocation = nil
			}
			if err := client.Tracker().Add(&pod); err != nil {
				t.Fatal(err)
			}
			for _, sequence := range []uint64{1, 2} {
				process, err := service.originalPublicationProcessFromPod(ctx, job, &pod, m, sequence)
				if fault == "current" {
					if err != nil || process.Pod.UID != string(pod.UID) || process.NodeUID != "original-node-uid" {
						t.Fatal("actual original staging/process observation", err)
					}
				} else if err == nil || process.Pod.UID != "" {
					t.Fatal("invalid current staging accepted", fault, sequence)
				}
			}
		})
	}
}
