package systembackupexecution

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// API-shaped DATA; deliberately cannot construct a current SQL publication
// authority or the private C/manifest/marker predecessors.
func publicationUploadExitData(t *testing.T) (*batchv1.Job, corev1.Pod, publicationMaterialIntent, publicationActivation) {
	t.Helper()
	requestSHA := hash([]byte("upload exit request DATA"))
	backup := "sbk_11111111-1111-4111-8111-111111111111"
	job, err := kube.PublishJob(kube.PublishJobRequest{Identity: kube.Identity{Namespace: "backup", Name: "sbp-" + requestSHA[:32], Owner: backup}, Image: "registry.invalid/worker@sha256:" + hash([]byte("image")), ServiceAccount: "publisher", StagingClaim: "staging", StagingSubPath: "publication/" + backup + "/1", InvocationConfigMap: "request", UploadCredentialSecret: "credential", RequestSHA256: requestSHA, DeadlineSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	no, yes := false, true
	job.Spec.Suspend = &no
	job.UID = "job-original"
	job.Generation = 2
	job.ResourceVersion = "10"
	job.Labels["backup.clawmanager.io/v2-task"] = backup
	job.Annotations = map[string]string{"backup.clawmanager.io/v2-spec-sha256": hash([]byte("spec DATA"))}
	at := metav1.NewTime(time.Now().Add(-time.Second))
	job.Status = batchv1.JobStatus{Succeeded: 1, CompletionTime: &at, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: job.Namespace, Name: job.Name + "-pod", UID: "pod-original", ResourceVersion: "11", Labels: map[string]string{"backup.clawmanager.io/v2-task": backup}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
	pod.Spec.NodeName = "node-original"
	pod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, ContainerID: "containerd://original", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: "containerd://original", FinishedAt: at, ExitCode: 0}}}}}
	material := publicationMaterialIntent{Namespace: job.Namespace, Backup: backup, RequestSHA256: requestSHA}
	a := publicationActivation{JobUID: string(job.UID), JobSpecSHA256: job.Annotations["backup.clawmanager.io/v2-spec-sha256"], AfterGeneration: job.Generation, BoundAt: at.Add(-time.Minute)}
	return job, pod, material, a
}

func TestPublicationUploadExitRejectsCompleteWithoutExactKubeletExit(t *testing.T) {
	for _, mode := range []string{"exact", "no-pods", "running", "waiting", "missing-termination", "missing-container-id", "missing-finished-at", "different-container-id", "failed-exit", "restart", "extra-container", "ephemeral-status", "wrong-node-empty", "missing-pod-rv", "foreign-owner", "extra-owner", "duplicate-pod", "second-owned-pod", "changed-task-label", "deleting", "changed-command", "changed-service-account"} {
		t.Run(mode, func(t *testing.T) {
			job, pod, _, _ := publicationUploadExitData(t)
			pods := []corev1.Pod{pod}
			switch mode {
			case "no-pods":
				pods = nil
			case "running":
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
			case "waiting":
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}}
			case "missing-termination":
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{}
			case "missing-container-id":
				pods[0].Status.ContainerStatuses[0].ContainerID = ""
			case "missing-finished-at":
				pods[0].Status.ContainerStatuses[0].State.Terminated.FinishedAt = metav1.Time{}
			case "different-container-id":
				pods[0].Status.ContainerStatuses[0].State.Terminated.ContainerID = "containerd://foreign"
			case "failed-exit":
				pods[0].Status.ContainerStatuses[0].State.Terminated.ExitCode = 1
			case "restart":
				pods[0].Status.ContainerStatuses[0].RestartCount = 1
			case "extra-container":
				pods[0].Spec.Containers = append(pods[0].Spec.Containers, corev1.Container{Name: "extra"})
			case "ephemeral-status":
				pods[0].Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "foreign"}}
			case "wrong-node-empty":
				pods[0].Spec.NodeName = ""
			case "missing-pod-rv":
				pods[0].ResourceVersion = ""
			case "foreign-owner":
				pods[0].OwnerReferences[0].UID = "job-foreign"
			case "extra-owner":
				pods[0].OwnerReferences = append(pods[0].OwnerReferences, metav1.OwnerReference{UID: "foreign"})
			case "duplicate-pod":
				pods = append(pods, pod)
			case "second-owned-pod":
				other := pod.DeepCopy()
				other.UID = types.UID("second-pod")
				other.Name += "-second"
				pods = append(pods, *other)
			case "changed-task-label":
				pods[0].Labels["backup.clawmanager.io/v2-task"] = "foreign"
			case "deleting":
				at := metav1.Now()
				pods[0].DeletionTimestamp = &at
			case "changed-command":
				pods[0].Spec.Containers[0].Command = []string{"foreign"}
			case "changed-service-account":
				pods[0].Spec.ServiceAccountName = "foreign"
			}
			identities, err := publicationUploadPodIdentities(job, pods)
			if mode == "exact" {
				if err != nil || len(identities) != 1 || identities[0].Containers[0] != "containerd://original" {
					t.Fatal("actual terminated identity DATA rejected", err)
				}
				return
			}
			if err == nil || identities != nil {
				t.Fatal("Job Complete substituted for kubelet exit", mode)
			}
		})
	}
}

func TestPublicationUploadExitRejectsReplacedOrUnfinishedJob(t *testing.T) {
	for _, mode := range []string{"exact", "empty-request", "foreign-uid", "foreign-generation", "foreign-namespace", "wrong-spec", "active", "failed", "no-completion-time", "no-complete-condition"} {
		t.Run(mode, func(t *testing.T) {
			job, _, material, a := publicationUploadExitData(t)
			switch mode {
			case "empty-request":
				material.RequestSHA256 = ""
			case "foreign-uid":
				job.UID = "foreign"
			case "foreign-generation":
				job.Generation++
			case "foreign-namespace":
				job.Namespace = "foreign"
			case "wrong-spec":
				job.Annotations["backup.clawmanager.io/v2-spec-sha256"] = hash([]byte("foreign"))
			case "active":
				job.Status.Active = 1
			case "failed":
				job.Status.Failed = 1
			case "no-completion-time":
				job.Status.CompletionTime = nil
			case "no-complete-condition":
				job.Status.Conditions = nil
			}
			if publicationCompletedUploadJob(job, material, a, "publisher") != (mode == "exact") {
				t.Fatal("unbound/unfinished Job admitted", mode)
			}
		})
	}
}

func TestPublicationUploadExitRequiresActualTypedMarker(t *testing.T) {
	service := &DeploymentService{}
	claim := c.ClaimToken{}
	for _, marker := range []nativePublicationObject{{}, {receipt: &publicationObjectReceipt{}}, {receipt: &publicationObjectReceipt{service: service, postManifestMarker: &publicationPostManifestMarker{}}}} {
		if receipt, err := service.observeOriginalPublicationUploadExit(context.Background(), claim, 1, marker); !errors.Is(err, c.ErrExecutionAuthority) || receipt != nil {
			t.Fatal("ordinary JSON marker minted upload exit", err)
		}
	}
	if err := (publicationUploadExitStore{}).Save(context.Background(), quiesce.ExitWitness{}); !errors.Is(err, c.ErrExecutionRecord) {
		t.Fatal("missing original scope accepted")
	}
}

func TestPublicationUploadExitRejectsForeignNodeAndFutureExit(t *testing.T) {
	_, pod, material, a := publicationUploadExitData(t)
	service := &DeploymentService{Config: DeploymentConfig{Security: kube.WorkerSecurity{NodeUIDs: map[string]string{pod.Spec.NodeName: "node-uid-original"}}}}
	identity := quiesce.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{"containerd://original"}}
	exit := &publicationUploadExit{service: service, material: material, activation: a, pods: map[string]quiesce.PodIdentity{identity.UID: identity}}
	now := time.Now()
	for _, mode := range []string{"exact", "foreign-node", "foreign-node-uid", "foreign-pod", "different-set", "future", "before-start", "zero-time"} {
		t.Run(mode, func(t *testing.T) {
			w := quiesce.ExitWitness{Namespace: material.Namespace, PodName: identity.Name, PodUID: identity.UID, Node: identity.Node, NodeUID: "node-uid-original", ResourceVersion: "11", Containers: map[string]time.Time{"containerd://original": now.Add(-time.Second)}}
			switch mode {
			case "foreign-node":
				w.Node = "foreign"
			case "foreign-node-uid":
				w.NodeUID = "foreign"
			case "foreign-pod":
				w.PodUID = "foreign"
			case "different-set":
				w.Containers = map[string]time.Time{"containerd://foreign": now.Add(-time.Second)}
			case "future":
				w.Containers["containerd://original"] = now.Add(time.Second)
			case "before-start":
				w.Containers["containerd://original"] = a.BoundAt.Add(-time.Second)
			case "zero-time":
				w.Containers["containerd://original"] = time.Time{}
			}
			valid := (publicationUploadExitStore{exit: exit}).validWitness(w) && publicationUploadExitTimes(w, a.BoundAt, now)
			if valid != (mode == "exact") {
				t.Fatal("foreign or future exit admitted", mode)
			}
		})
	}
}
