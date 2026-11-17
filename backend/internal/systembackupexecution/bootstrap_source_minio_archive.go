package systembackupexecution

import (
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

const originalMinIOArchivePart = "original_minio_archive"

// The one explicitly selected installation MinIO volume is an additional
// native source. It never enters or relaxes the RunningTenantPro branch.
func observeOriginalMinIOArchivePod(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, source originalLonghornSource) (*core.Pod, error) {
	if api == nil || ctx == nil || source.Namespace != cfg.Namespace || source.NamespaceUID != cfg.NamespaceUID || source.Source.PVUID == "" || source.Source.PVName == "" || source.AccessMode != core.ReadWriteOnce {
		return nil, install.ErrInstall
	}
	uid := ""
	for _, w := range cfg.Writers {
		if w.Namespace == cfg.Namespace && w.Name == "minio" {
			if uid != "" {
				return nil, install.ErrInstall
			}
			uid = w.UID
		}
	}
	if uid == "" {
		return nil, install.ErrInstall
	}
	dep, err := api.AppsV1().Deployments(cfg.Namespace).Get(ctx, "minio", metav1.GetOptions{})
	if err != nil || string(dep.UID) != uid || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ReadyReplicas != 1 || dep.Status.ObservedGeneration < dep.Generation || dep.Spec.Selector == nil {
		return nil, install.ErrInstall
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, install.ErrInstall
	}
	pods, err := api.CoreV1().Pods(cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil || pods.Continue != "" || len(pods.Items) != 1 {
		return nil, install.ErrInstall
	}
	pod := &pods.Items[0]
	if pod.UID == "" || pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" || !selector.Matches(labels.Set(pod.Labels)) || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "minio" || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 {
		return nil, install.ErrInstall
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != "minio" || !status.Ready || status.State.Running == nil || status.ContainerID == "" || status.ImageID == "" {
		return nil, install.ErrInstall
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		return nil, install.ErrInstall
	}
	rs, err := api.AppsV1().ReplicaSets(cfg.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || rs.UID != owner.UID {
		return nil, install.ErrInstall
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.Kind != "Deployment" || parent.Name != dep.Name || parent.UID != dep.UID {
		return nil, install.ErrInstall
	}
	volume := ""
	for _, m := range pod.Spec.Containers[0].VolumeMounts {
		if m.MountPath == "/data" {
			if volume != "" || m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" {
				return nil, install.ErrInstall
			}
			volume = m.Name
		}
	}
	if volume == "" {
		return nil, install.ErrInstall
	}
	found := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == volume {
			if found || v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ReadOnly || v.PersistentVolumeClaim.ClaimName != source.Source.Name {
				return nil, install.ErrInstall
			}
			found = true
		} else if v.PersistentVolumeClaim != nil || v.HostPath != nil || v.CSI != nil || v.NFS != nil {
			return nil, install.ErrInstall
		}
	}
	if !found {
		return nil, install.ErrInstall
	}
	pvc, err := api.CoreV1().PersistentVolumeClaims(cfg.Namespace).Get(ctx, source.Source.Name, metav1.GetOptions{})
	if err != nil || string(pvc.UID) != source.Source.UID || pvc.Spec.VolumeName != source.Source.PVName || pvc.DeletionTimestamp != nil || pvc.Status.Phase != core.ClaimBound {
		return nil, install.ErrInstall
	}
	pv, err := api.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || string(pv.UID) != source.Source.PVUID || pv.DeletionTimestamp != nil || kube.ContentHash(pv.Spec) != source.Source.SHA256 || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != source.Handle || pv.Spec.CSI.ReadOnly || pv.Spec.CSI.FSType != "ext4" || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Namespace != cfg.Namespace || pv.Spec.ClaimRef.Name != pvc.Name || (pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != core.PersistentVolumeFilesystem) {
		return nil, install.ErrInstall
	}
	return pod, nil
}
