package install

import (
	"context"
	"reflect"
	"sort"

	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// This is a complete observed mount cohort, not a registration or a SQL claim.
// Keep read-only attachments too: their mount still belongs to the RWX drain.
type originalLonghornRWXClient struct {
	Template                       q.LonghornRWXClientCoordinates
	PodName, PodUID, ContainerID   string
	ContainerName, Volume, SpecSHA string
}

// Enumerate without label selectors. The installed node templates select the
// volume/node/mount; the current API, never caller-supplied Pod fields, supplies
// each running process identity. A second census fences replacement and extra
// clients before native register-client/sync-client dispatch.
func originalLonghornRWXClients(ctx context.Context, k kubernetes.Interface, material q.LonghornExt4Materials) ([]originalLonghornRWXClient, error) {
	if ctx == nil || k == nil || ctx.Err() != nil {
		return nil, ErrInstall
	}
	out := []originalLonghornRWXClient{}
	seenSources := map[string]bool{}
	for _, source := range material.Sources {
		key := source.Binding.Namespace + "/" + source.PVCName
		if seenSources[key] {
			return nil, ErrInstall
		}
		seenSources[key] = true
		claim, err := k.CoreV1().PersistentVolumeClaims(source.Binding.Namespace).Get(ctx, source.PVCName, metav1.GetOptions{})
		if err != nil || string(claim.UID) != source.PVCUID || claim.DeletionTimestamp != nil || claim.Status.Phase != core.ClaimBound {
			return nil, ErrInstall
		}
		pv, err := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || string(pv.UID) != source.PVUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != source.VolumeHandle {
			return nil, ErrInstall
		}
		if reflect.DeepEqual(pv.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteOnce}) {
			continue // The RWO keeper has its own drain and process observation.
		}
		if !reflect.DeepEqual(pv.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteMany}) {
			return nil, ErrInstall
		}
		ns, err := k.CoreV1().Namespaces().Get(ctx, claim.Namespace, metav1.GetOptions{})
		if err != nil || string(ns.UID) != source.Binding.NamespaceUID || ns.DeletionTimestamp != nil {
			return nil, ErrInstall
		}
		pods, err := k.CoreV1().Pods(claim.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil || pods.Continue != "" {
			return nil, ErrInstall
		}
		count := len(out)
		for _, pod := range pods.Items {
			volumes := map[string]bool{}
			for _, volume := range pod.Spec.Volumes {
				if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim.Name {
					volumes[volume.Name] = true
				}
			}
			if len(volumes) == 0 {
				continue
			}
			statuses := map[string]core.ContainerStatus{}
			for _, status := range append(append(append([]core.ContainerStatus{}, pod.Status.ContainerStatuses...), pod.Status.InitContainerStatuses...), pod.Status.EphemeralContainerStatuses...) {
				if _, duplicate := statuses[status.Name]; duplicate {
					return nil, ErrInstall
				}
				statuses[status.Name] = status
			}
			containers := append(append([]core.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...)
			for _, ephemeral := range pod.Spec.EphemeralContainers {
				containers = append(containers, core.Container{Name: ephemeral.Name, VolumeMounts: ephemeral.VolumeMounts})
			}
			for _, container := range containers {
				status := statuses[container.Name]
				for _, mount := range container.VolumeMounts {
					if !volumes[mount.Name] {
						continue
					}
					if status.State.Running == nil {
						// A completed init is absent. A pending mount is an unresolved
						// possible client, rather than proof that there is no writer.
						if status.State.Terminated != nil {
							continue
						}
						return nil, ErrInstall
					}
					if pod.UID == "" || pod.DeletionTimestamp != nil || status.ContainerID == "" || mount.SubPath != "" || mount.SubPathExpr != "" {
						return nil, ErrInstall
					}
					var selected *q.LonghornRWXClientCoordinates
					for _, candidate := range material.Clients {
						if candidate.OriginalSourceSHA256 != source.OriginalSourceSHA256 || candidate.Binding.Node != pod.Spec.NodeName || candidate.PodNamespace != pod.Namespace || candidate.MountPoint != mount.MountPath {
							continue
						}
						if selected != nil || candidate.PVCName != claim.Name || candidate.PVCUID != source.PVCUID || candidate.PVUID != source.PVUID || candidate.VolumeHandle != source.VolumeHandle || candidate.ProviderNamespaceUID != source.ProviderNamespaceUID || candidate.Binding.Namespace != pod.Namespace || candidate.Binding.NamespaceUID != source.Binding.NamespaceUID || candidate.Binding.InstallationID != source.Binding.InstallationID || candidate.Binding.Kind != q.LonghornExt4Protocol || candidate.Binding.OperationID != "" || candidate.Binding.ReservationID != "" || candidate.Binding.Generation != 0 || candidate.Binding.FenceEpoch != 0 || candidate.Binding.InventorySHA256 != "" || !candidate.Binding.ExpiresAt.IsZero() || candidate.Attempt != 0 || candidate.Claim != (q.LonghornExt4Claim{}) || candidate.PodName != "" || candidate.PodUID != "" || candidate.ContainerID != "" || candidate.NFSSource == "" || candidate.Endpoint == "" {
							return nil, ErrInstall
						}
						node, err := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
						identity, identityErr := q.LonghornExt4SourceIdentity(candidate.OriginalSourceSHA256, candidate.ProviderNamespaceUID, candidate.Binding.NodeUID)
						if err != nil || string(node.UID) != candidate.Binding.NodeUID || node.DeletionTimestamp != nil || identityErr != nil || candidate.Identity != identity {
							return nil, ErrInstall
						}
						copy := candidate
						selected = &copy
					}
					if selected == nil {
						return nil, ErrInstall
					}
					out = append(out, originalLonghornRWXClient{Template: *selected, PodName: pod.Name, PodUID: string(pod.UID), ContainerID: status.ContainerID, ContainerName: container.Name, Volume: mount.Name, SpecSHA: originalObjectSHA(pod.Spec)})
				}
			}
		}
		if len(out) == count {
			return nil, ErrInstall
		}
	}
	sort.Slice(out, func(i, j int) bool { return originalObjectSHA(out[i]) < originalObjectSHA(out[j]) })
	return out, nil
}
