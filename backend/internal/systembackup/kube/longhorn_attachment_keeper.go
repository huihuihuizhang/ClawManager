package kube

import (
	"context"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const LonghornKeeperResource = "AttachmentKeeper"

type LonghornAttachmentKeeper struct {
	Identity                                                       Identity
	NamespaceUID, Node, NodeUID, ServiceAccount, Image, Executable string
	Source                                                         MountIdentity
}

// Invoke before the original writer stops. The selected immutable image must
// contain the same qualified Node owner executable with --attachment-keeper.
// The returned journal record is kept until physical source release.
func ReconcileLonghornAttachmentKeeper(ctx context.Context, client kubernetes.Interface, runner Runner, in LonghornAttachmentKeeper) (ResourceRecord, error) {
	var zero ResourceRecord
	if ctx == nil || client == nil || !in.Identity.valid() || in.NamespaceUID == "" || in.Node == "" || in.NodeUID == "" ||
		in.ServiceAccount == "" || !strings.Contains(in.Image, "@sha256:") ||
		in.Executable == "" || in.Executable[0] != '/' || in.Source.Kind != "PersistentVolumeClaim" {
		return zero, ErrResource
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, in.Identity.Namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil || string(ns.UID) != in.NamespaceUID {
		return zero, ErrOwnership
	}
	source := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: in.Source.Name, ReadOnly: true}}}
	mount := in.Source
	mount.Volume = "source"
	if (WorkerObserver{Client: client}).mounts(ctx, in.Identity.Namespace, []corev1.Volume{source}, []MountIdentity{mount}) != nil {
		return zero, ErrOwnership
	}
	job, err := LonghornAttachmentKeeperJob(in)
	if err != nil {
		return zero, err
	}
	// Ensure verifies the original exact request and durable resource fence.
	record, err := runner.Ensure(ctx, LonghornKeeperResource, job)
	if err != nil {
		return record, err
	}
	_, err = (WorkerObserver{Client: client}).Observe(ctx, record,
		WorkerSecurity{NodeUIDs: map[string]string{in.Node: in.NodeUID}, Volumes: []MountIdentity{mount}})
	return record, err
}

// LonghornAttachmentKeeperJob reconstructs the exact journal request; it performs no IO.
func LonghornAttachmentKeeperJob(in LonghornAttachmentKeeper) (*batchv1.Job, error) {
	if !in.Identity.valid() || in.NamespaceUID == "" || in.Node == "" || in.NodeUID == "" || in.ServiceAccount == "" || !strings.Contains(in.Image, "@sha256:") || in.Executable == "" || in.Executable[0] != '/' || in.Source.Kind != "PersistentVolumeClaim" {
		return nil, ErrResource
	}
	source := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: in.Source.Name, ReadOnly: true}}}
	off, on, uid := false, true, int64(0)
	grace, retries := int64(30), int32(0)
	job := &batchv1.Job{ObjectMeta: in.Identity.meta(), Spec: batchv1.JobSpec{BackoffLimit: &retries,
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{OwnerLabel: in.Identity.Owner}},
			Spec: corev1.PodSpec{NodeName: in.Node, ServiceAccountName: in.ServiceAccount, AutomountServiceAccountToken: &off,
				RestartPolicy: corev1.RestartPolicyNever, TerminationGracePeriodSeconds: &grace,
				Containers: []corev1.Container{{Name: "attachment", Image: in.Image, ImagePullPolicy: corev1.PullIfNotPresent,
					Command: []string{in.Executable}, Args: []string{"--attachment-keeper", "--keeper-root=/source"},
					SecurityContext: &corev1.SecurityContext{RunAsUser: &uid, ReadOnlyRootFilesystem: &on,
						AllowPrivilegeEscalation: &off, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					VolumeMounts: []corev1.VolumeMount{{Name: "source", MountPath: "/source", ReadOnly: true}}}},
				Volumes: []corev1.Volume{source}}}}}
	return job, nil
}
