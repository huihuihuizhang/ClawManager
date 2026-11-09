package kube

import (
	"context"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// LonghornCaptureClone selects the admitted worker namespace, temporary
// storage class and resource names for a single task attempt.
type LonghornCaptureClone struct {
	Claim, Alias                 Identity
	NamespaceUID                 string
	Class, ClassUID, ClassSHA256 string
}

// VerifyLonghornCaptureSource reads the frozen original and storage classes
// during discovery. It does not attest a provider hold or issue a mutation.
func VerifyLonghornCaptureSource(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, sourceNamespace string, target LonghornCaptureClone) error {
	if !target.Claim.valid() || target.NamespaceUID == "" || target.Class == "" || target.ClassUID == "" || len(target.ClassSHA256) != 64 || pin.ProviderNamespace == "" || pin.ProviderNamespaceUID == "" {
		return ErrResource
	}
	if _, _, err := verifyLonghornSnapshotSource(ctx, client, api, pin, sourceNamespace); err != nil {
		return err
	}
	for _, expected := range []struct{ name, uid string }{{target.Claim.Namespace, target.NamespaceUID}, {pin.ProviderNamespace, pin.ProviderNamespaceUID}} {
		current, err := client.CoreV1().Namespaces().Get(ctx, expected.name, metav1.GetOptions{})
		if err != nil || string(current.UID) != expected.uid || current.DeletionTimestamp != nil {
			return ErrOwnership
		}
	}
	class, err := client.StorageV1().StorageClasses().Get(ctx, target.Class, metav1.GetOptions{})
	if err != nil || !longhornCloneStorageClassMatches(class, target) {
		return ErrOwnership
	}
	return ctx.Err()
}

// ReconcileLonghornCaptureJob prepares the storage for the frozen Job before
// its creation. The namespaced runner must enforce the held task fence.
func ReconcileLonghornCaptureJob(ctx context.Context, client kubernetes.Interface, namespaced, cluster Runner, pin LonghornSnapshotPin, target LonghornCaptureClone, job *batchv1.Job) (LonghornSnapshotPin, LonghornSnapshotBinding, error) {
	if !longhornCaptureJobMountsClone(job, target.Claim) ||
		target.Claim.Namespace == pin.Snapshot.Intent.Identity.Namespace && target.Claim.Name == pin.Source.Name {
		return pin, LonghornSnapshotBinding{}, ErrOwnership
	}
	pin, binding, err := ReconcileLonghornCaptureClone(ctx, client, namespaced, cluster, pin, target)
	if err != nil {
		return pin, LonghornSnapshotBinding{}, err
	}
	if err := namespaced.ready(ctx); err != nil {
		return pin, LonghornSnapshotBinding{}, err
	}
	return pin, binding, nil
}

func longhornCaptureJobMountsClone(job *batchv1.Job, claim Identity) bool {
	if job == nil || !claim.valid() || job.Namespace != claim.Namespace || job.Labels[OwnerLabel] != claim.Owner {
		return false
	}
	pod := job.Spec.Template.Spec
	if len(pod.Containers) != 1 || pod.Containers[0].Name != "worker" || len(pod.InitContainers) != 0 || len(pod.EphemeralContainers) != 0 || len(pod.Containers[0].VolumeDevices) != 0 {
		return false
	}
	workspace := false
	for _, volume := range pod.Volumes {
		if volume.Name == "workspace" {
			if workspace || volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != claim.Name || !volume.PersistentVolumeClaim.ReadOnly {
				return false
			}
			workspace = true
		} else if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim.Name {
			return false
		}
	}
	if !workspace {
		return false
	}
	mounted := false
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "workspace" {
			if mounted || !mount.ReadOnly || mount.MountPath != "/workspace" || mount.SubPathExpr != "" {
				return false
			}
			mounted = true
		} else if mount.MountPath == "/workspace" {
			return false
		}
	}
	return mounted
}

// ReconcileLonghornCaptureClone advances one task-owned clone. The original
// snapshot must be journaled and proven against the provider cut first.
// Return the updated records even when CSI needs another reconciliation.
func ReconcileLonghornCaptureClone(ctx context.Context, client kubernetes.Interface, namespaced, cluster Runner, pin LonghornSnapshotPin, target LonghornCaptureClone) (LonghornSnapshotPin, LonghornSnapshotBinding, error) {
	var binding LonghornSnapshotBinding
	if ctx == nil || client == nil || namespaced.Client == nil || !target.Claim.valid() || target.Claim.Owner != pin.Snapshot.Intent.Identity.Owner ||
		target.NamespaceUID == "" || target.Class == "" || target.ClassUID == "" || len(target.ClassSHA256) != 64 {
		return pin, binding, ErrResource
	}
	if err := namespaced.ready(ctx); err != nil {
		return pin, binding, err
	}
	if pin.Clone.Intent.Kind != "" && pin.Clone.Intent.Identity != target.Claim {
		return pin, binding, ErrOwnership
	}
	crossNamespace := target.Claim.Namespace != pin.Snapshot.Intent.Identity.Namespace
	if crossNamespace {
		if !target.Alias.valid() || target.Alias.Namespace != target.Claim.Namespace || target.Alias.Owner != target.Claim.Owner ||
			cluster.AuthorizeRetainedContent == nil {
			return pin, binding, ErrResource
		}
		if pin.Alias != nil && (pin.Alias.NamespaceUID != target.NamespaceUID ||
			pin.Alias.Snapshot.Intent.Kind != "" && pin.Alias.Snapshot.Intent.Identity != target.Alias) {
			return pin, binding, ErrOwnership
		}
		cluster.Journal = namespaced.Journal
		if err := cluster.ready(ctx); err != nil {
			return pin, binding, err
		}
	} else if target.Alias != (Identity{}) || pin.Alias != nil || target.NamespaceUID != pin.NamespaceUID {
		return pin, binding, ErrResource
	}
	cut, err := verifyLonghornSourceCut(ctx, client, namespaced.Client, pin)
	if err != nil {
		return pin, binding, err
	}
	class, err := client.StorageV1().StorageClasses().Get(ctx, target.Class, metav1.GetOptions{})
	if err != nil || !longhornCloneStorageClassMatches(class, target) {
		return pin, binding, ErrOwnership
	}
	snapshotName := pin.Snapshot.Intent.Identity.Name
	if crossNamespace {
		request, err := longhornAliasRequest(ctx, client, pin, target.Alias, target.NamespaceUID)
		if err != nil {
			return pin, binding, err
		}
		alias := LonghornSnapshotAliasPin{NamespaceUID: target.NamespaceUID}
		alias.Snapshot, err = namespaced.Ensure(ctx, "VolumeSnapshot", request)
		if pin.Alias != nil {
			alias.Content = pin.Alias.Content
		}
		pin.Alias = &alias
		if err != nil {
			return pin, binding, err
		}
		_, content, err := longhornAliasObjects(ctx, client, namespaced.Client, pin, cut)
		if err != nil {
			return pin, binding, err
		}
		alias.Content, err = cluster.Ensure(ctx, "VolumeSnapshotContent", content)
		if err != nil {
			return pin, binding, err
		}
		if err := verifyLonghornSnapshotAlias(ctx, client, namespaced.Client, pin, cut); err != nil {
			return pin, binding, err
		}
		snapshotName = target.Alias.Name
	}
	group := longhornSnapshotGroup
	mode := corev1.PersistentVolumeFilesystem
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: target.Claim.meta(), Spec: corev1.PersistentVolumeClaimSpec{
		StorageClassName: &target.Class, VolumeMode: &mode, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		Resources:  corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: cut.capacity}},
		DataSource: &corev1.TypedLocalObjectReference{APIGroup: &group, Kind: "VolumeSnapshot", Name: snapshotName},
	}}
	pin.Clone, err = namespaced.Ensure(ctx, "PersistentVolumeClaim", claim)
	if err != nil {
		return pin, binding, err
	}
	// The namespaced reader must also have read-only access to content and
	// provider objects. Cluster write credentials stay with the content runner.
	binding, err = VerifyLonghornSnapshotBinding(ctx, client, namespaced.Client, pin)
	return pin, binding, err
}

func longhornCloneStorageClassMatches(class *storagev1.StorageClass, target LonghornCaptureClone) bool {
	return class != nil && string(class.UID) == target.ClassUID && class.DeletionTimestamp == nil && class.Provisioner == longhornSnapshotDriver &&
		class.ReclaimPolicy != nil && *class.ReclaimPolicy == corev1.PersistentVolumeReclaimDelete &&
		class.VolumeBindingMode != nil && *class.VolumeBindingMode == storagev1.VolumeBindingImmediate &&
		ContentHash([]any{class.Provisioner, class.Parameters, class.ReclaimPolicy, class.VolumeBindingMode, class.MountOptions, class.AllowedTopologies}) == target.ClassSHA256
}
