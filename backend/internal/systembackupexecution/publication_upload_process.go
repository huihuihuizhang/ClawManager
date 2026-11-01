package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/quiesce"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Immutable first authenticated107 process DATA, not an authority. Only the
// actual mTLS/TokenReview/native Pod receiver registers it with sequence1 in
// the same original transaction. Later messages and exit may not replace it.
type publicationUploadProcess struct {
	Version, Installation, Backup, RequestSHA256, JobUID, ServiceAccountUID, NodeUID, FirstResourceVersion string
	Attempt                                                                                                uint64
	Generation                                                                                             int64
	Pod                                                                                                    quiesce.PodIdentity
	ObservedAt                                                                                             time.Time
}

func publicationProcessID(m publicationMaterialIntent) string {
	return publicationMaterialID(m.Installation, m.Backup, m.Attempt) + "_process"
}

func publicationUploadPodRelated(job *batchv1.Job, pod *corev1.Pod) bool {
	if job == nil || pod == nil {
		return false
	}
	for _, owner := range pod.OwnerReferences {
		if owner.UID == job.UID {
			return true
		}
	}
	if strings.HasPrefix(pod.Name, job.Name+"-") || pod.Spec.ServiceAccountName == job.Spec.Template.Spec.ServiceAccountName && pod.Labels["backup.clawmanager.io/v2-task"] == job.Labels["backup.clawmanager.io/v2-task"] {
		return true
	}
	secrets := map[string]bool{}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Secret != nil {
			secrets[volume.Secret.SecretName] = true
		}
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && secrets[volume.Secret.SecretName] {
			return true
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil && secrets[source.Secret.Name] {
					return true
				}
			}
		}
	}
	return false
}

func publicationOnlyOriginalUploader(job *batchv1.Job, pods []corev1.Pod, process publicationUploadProcess) bool {
	found := false
	for i := range pods {
		pod := &pods[i]
		if !publicationUploadPodRelated(job, pod) && string(pod.UID) != process.Pod.UID {
			continue
		}
		if found || string(pod.UID) != process.Pod.UID || pod.Name != process.Pod.Name {
			return false
		}
		found = true
	}
	return found
}

func publicationUploadProcessData(job *batchv1.Job, pod *corev1.Pod, m publicationMaterialIntent, serviceAccountUID, nodeUID string) (publicationUploadProcess, error) {
	var zero publicationUploadProcess
	if job == nil || pod == nil || serviceAccountUID == "" || nodeUID == "" || pod.Namespace != m.Namespace || pod.Namespace != job.Namespace || pod.Name == "" || pod.UID == "" || pod.ResourceVersion == "" || pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil || len(pod.OwnerReferences) != 1 || pod.Labels["backup.clawmanager.io/v2-task"] != m.Backup || pod.Status.Phase != corev1.PodRunning {
		return zero, c.ErrExecutionRecord
	}
	owner := pod.OwnerReferences[0]
	if owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != job.Name || owner.UID != job.UID || owner.Controller == nil || !*owner.Controller {
		return zero, c.ErrExecutionRecord
	}
	comparison := job.DeepCopy()
	comparison.Spec.Template.Spec = *pod.Spec.DeepCopy()
	comparison.Spec.Template.Spec.NodeName = job.Spec.Template.Spec.NodeName
	if !sameJob(job, comparison) || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
		return zero, c.ErrExecutionRecord
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != pod.Spec.Containers[0].Name || status.ContainerID == "" || status.RestartCount != 0 || status.State.Running == nil || status.State.Running.StartedAt.IsZero() || status.State.Terminated != nil || status.State.Waiting != nil {
		return zero, c.ErrExecutionRecord
	}
	process := publicationUploadProcess{Version: "system-backup-original-publication-process.v1", Installation: m.Installation, Backup: m.Backup, Attempt: m.Attempt, RequestSHA256: m.RequestSHA256, JobUID: string(job.UID), Generation: job.Generation, ServiceAccountUID: serviceAccountUID, NodeUID: nodeUID, FirstResourceVersion: pod.ResourceVersion, Pod: quiesce.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{status.ContainerID}}}
	return process, nil
}

func (p publicationUploadProcess) valid(m publicationMaterialIntent, a publicationActivation) bool {
	return p.Version == "system-backup-original-publication-process.v1" && p.Installation == m.Installation && p.Backup == m.Backup && p.Attempt == m.Attempt && p.RequestSHA256 == m.RequestSHA256 && p.JobUID == a.JobUID && p.Generation == a.AfterGeneration && p.ServiceAccountUID != "" && p.NodeUID != "" && p.FirstResourceVersion != "" && p.Pod.Name != "" && p.Pod.UID != "" && p.Pod.Node != "" && len(p.Pod.Containers) == 1 && p.Pod.Containers[0] != "" && !p.ObservedAt.IsZero() && !p.ObservedAt.Before(a.BoundAt) && p.ObservedAt.Before(a.ExpiresAt)
}

func samePublicationUploadProcess(a, b publicationUploadProcess) bool {
	a.FirstResourceVersion, b.FirstResourceVersion = "", ""
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	left, _ := ce.Canonical(a)
	right, _ := ce.Canonical(b)
	return bytes.Equal(left, right)
}

func loadPublicationProcessTx(ctx context.Context, tx *sql.Tx, m publicationMaterialIntent, a publicationActivation) (publicationUploadProcess, []byte, error) {
	var process publicationUploadProcess
	raw, err := loadPublicationMetadata(ctx, tx, m.Backup, publicationProcessID(m))
	if err != nil {
		return process, nil, c.ErrExecutionRecord
	}
	if decodeProviderDeploymentJSON(raw, &process) != nil || !process.valid(m, a) {
		return publicationUploadProcess{}, nil, c.ErrExecutionRecord
	}
	canonical, err := ce.Canonical(process)
	if err != nil || !bytes.Equal(canonical, raw) {
		return publicationUploadProcess{}, nil, c.ErrExecutionRecord
	}
	return process, raw, nil
}

// Original identity is required even if the Pod has lost its owner/label or
// has been removed entirely. Current Job-child discovery cannot substitute a
// new UID, container or node for the authenticated uploader.
func publicationOriginalUploadExitPods(job *batchv1.Job, pods []corev1.Pod, process publicationUploadProcess) ([]quiesce.PodIdentity, error) {
	identities, err := publicationUploadPodIdentities(job, pods)
	if err != nil || len(identities) != 1 {
		return nil, c.ErrExecutionRecord
	}
	if process.Pod.UID == "" || process.Pod.Name == "" || process.Pod.Node == "" || len(process.Pod.Containers) != 1 {
		return nil, c.ErrExecutionRecord
	}
	original := process.Pod
	original.Containers = append([]string(nil), original.Containers...)
	sort.Strings(original.Containers)
	want, _ := ce.Canonical(original)
	actual, _ := ce.Canonical(identities[0])
	if !bytes.Equal(want, actual) {
		return nil, c.ErrExecutionRecord
	}
	return identities, nil
}

func (s *DeploymentService) originalPublicationProcessFromPod(ctx context.Context, job *batchv1.Job, pod *corev1.Pod, m publicationMaterialIntent, sequence uint64) (publicationUploadProcess, error) {
	if s == nil || s.Config.PublicationWorker == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Client == nil || pod == nil {
		return publicationUploadProcess{}, c.ErrExecutionAuthority
	}
	nodeUID := s.Config.Security.NodeUIDs[pod.Spec.NodeName]
	process, err := publicationUploadProcessData(job, pod, m, s.Config.PublicationWorker.ServiceAccountUID, nodeUID)
	if err != nil {
		return publicationUploadProcess{}, err
	}
	if sequence == 1 {
		node, err := s.Runtime.Owner.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil || string(node.UID) != nodeUID || node.DeletionTimestamp != nil {
			return publicationUploadProcess{}, c.ErrExecutionAuthority
		}
		pods, err := s.Runtime.Owner.Client.CoreV1().Pods(m.Namespace).List(ctx, metav1.ListOptions{Limit: 1001})
		if err != nil || pods.Continue != "" || len(pods.Items) > 1000 || !publicationOnlyOriginalUploader(job, pods.Items, process) {
			return publicationUploadProcess{}, c.ErrExecutionRecord
		}
	}
	return process, nil
}
