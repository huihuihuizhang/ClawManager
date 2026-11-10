package install

import (
	"context"
	"path"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// originalPodVolumeKind is the storage shape of one Pod volume that carries
// source data. "host" is a hostPath or local PV whose native fence is a
// filesystem root. "longhorn" is a Longhorn CSI volume whose fence is the
// engine/share-manager hold carried by the signed Longhorn materials, so it has
// no host root to freeze.
const (
	originalPodVolumeHost     = "host"
	originalPodVolumeLonghorn = "longhorn"
)

// originalPodVolumeClass is the classified identity of one data volume. It is
// plain observed coordinates: no hold, grant, generation or signature.
type originalPodVolumeClass struct {
	VolumeName, ClaimName, ClaimUID, PVName, PVUID, Handle, Kind string
}

// classifyPodPersistentVolumes separates host-rooted data volumes from Longhorn
// CSI volumes. Unknown providers remain a real unsupported source, not an empty
// scope. Only the host branch appends the physical volume pin the existing
// recheck consumes; Longhorn coverage is proved by the signed materials, not by
// a host path.
func classifyPodPersistentVolumes(ctx context.Context, k kubernetes.Interface, pod *corev1.Pod, pins *[]originalPhysicalVolumePin) ([]string, []originalPodVolumeClass, error) {
	if pod == nil || pod.Spec.NodeName == "" || k == nil {
		return nil, nil, ErrInstall
	}
	var roots []string
	var longhorn []originalPodVolumeClass
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			roots = append(roots, v.HostPath.Path)
			continue
		}
		if v.PersistentVolumeClaim != nil {
			claim, err := k.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if err != nil || claim.Status.Phase != corev1.ClaimBound || claim.DeletionTimestamp != nil {
				return nil, nil, ErrInstall
			}
			pv, err := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if err != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != pod.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.DeletionTimestamp != nil {
				return nil, nil, ErrInstall
			}
			if pv.Spec.CSI != nil {
				if pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle == "" {
					return nil, nil, OriginalWriterSourceFailure{Dependency: "persistent_volume_native_fence_required"}
				}
				longhorn = append(longhorn, originalPodVolumeClass{
					VolumeName: v.Name, ClaimName: claim.Name, ClaimUID: string(claim.UID),
					PVName: pv.Name, PVUID: string(pv.UID), Handle: pv.Spec.CSI.VolumeHandle,
					Kind: originalPodVolumeLonghorn,
				})
				continue
			}
			root := ""
			if pv.Spec.HostPath != nil {
				root = pv.Spec.HostPath.Path
			}
			if pv.Spec.Local != nil {
				if root != "" {
					return nil, nil, ErrInstall
				}
				root = pv.Spec.Local.Path
			}
			if root == "" {
				return nil, nil, OriginalWriterSourceFailure{Dependency: "persistent_volume_native_fence_required"}
			}
			if pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
				return nil, nil, OriginalWriterSourceFailure{Dependency: "hostpath_data_node_affinity_required"}
			}
			nodes, err := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, nil, ErrInstall
			}
			matched := 0
			for n := range nodes.Items {
				yes, e := originalPVMatchesNode(pv.Spec.NodeAffinity.Required, &nodes.Items[n])
				if e != nil {
					return nil, nil, ErrInstall
				}
				if yes {
					matched++
					if nodes.Items[n].Name != pod.Spec.NodeName {
						return nil, nil, ErrInstall
					}
				}
			}
			if matched != 1 {
				return nil, nil, ErrInstall
			}
			pin := originalPhysicalVolumePin{pod.Namespace, claim.Name, string(claim.UID), originalObjectSHA(claim.Spec), pv.Name, string(pv.UID), originalObjectSHA(pv.Spec), pod.Spec.NodeName}
			found := false
			if pins != nil {
				for _, old := range *pins {
					if old.ClaimUID == pin.ClaimUID {
						if old != pin {
							return nil, nil, ErrInstall
						}
						found = true
					}
				}
				if !found {
					*pins = append(*pins, pin)
				}
			}
			roots = append(roots, root)
			continue
		}
		if v.EmptyDir != nil || v.Secret != nil || v.ConfigMap != nil || v.Projected != nil || v.DownwardAPI != nil {
			continue
		}
		return nil, nil, OriginalWriterSourceFailure{Dependency: "unmapped_persistent_volume_source"}
	}
	return originalNonOverlappingRoots(roots), longhorn, nil
}

// classifyPodPersistentVolumes is the writer-set binding of the same
// classification. It keeps the physical volume pins on the prepared set so the
// later recheck sees exactly the host volumes this call accepted.
func (s *PreparedOriginalWriterSet) classifyPodPersistentVolumes(ctx context.Context, pod *corev1.Pod) ([]string, []originalPodVolumeClass, error) {
	return classifyPodPersistentVolumes(ctx, s.owner.operator.installer.kube, pod, &s.volumes)
}

// originalSharedRuntimeVolumeRecords turns the Longhorn branch of the existing
// classifier into reviewable, observed volume identities. Host roots stay in
// the existing physical pin path; this list is the Longhorn half only, so a
// mixed Pod is covered by both records and roots. A volume with no observed
// container mount, or a non-literal subPath, is not a complete record.
func (s *PreparedOriginalWriterSet) originalSharedRuntimeVolumeRecords(ctx context.Context, pod *corev1.Pod, longhorn []originalPodVolumeClass) ([]OriginalSharedRuntimeVolume, error) {
	if s == nil || s.owner == nil || s.owner.operator == nil || s.owner.operator.installer == nil || pod == nil || pod.Namespace == "" || pod.Name == "" || pod.UID == "" || pod.Spec.NodeName == "" || len(longhorn) == 0 {
		return nil, ErrInstall
	}
	node, err := s.owner.operator.installer.kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	records := make([]OriginalSharedRuntimeVolume, 0, len(longhorn))
	for _, class := range longhorn {
		if class.Kind != originalPodVolumeLonghorn || class.VolumeName == "" || class.ClaimName == "" || class.ClaimUID == "" || class.PVName == "" || class.PVUID == "" || class.Handle == "" {
			return nil, ErrInstall
		}
		mounts, err := originalPodVolumeMounts(pod, class.VolumeName)
		if err != nil {
			return nil, err
		}
		records = append(records, OriginalSharedRuntimeVolume{
			VolumeName: class.VolumeName, ClaimName: class.ClaimName, ClaimUID: class.ClaimUID,
			PVName: class.PVName, PVUID: class.PVUID, Handle: class.Handle,
			Namespace: pod.Namespace, Pod: pod.Name, PodUID: string(pod.UID),
			Node: pod.Spec.NodeName, NodeUID: string(node.UID), Mounts: mounts,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].VolumeName < records[j].VolumeName })
	return records, nil
}

func originalPodVolumeMounts(pod *corev1.Pod, volumeName string) ([]OriginalSharedRuntimeVolumeMount, error) {
	if pod == nil || volumeName == "" {
		return nil, ErrInstall
	}
	var out []OriginalSharedRuntimeVolumeMount
	seen := map[string]bool{}
	add := func(container corev1.Container) error {
		if container.Name == "" {
			return ErrInstall
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name != volumeName {
				continue
			}
			if !originalVolumeMountPath(mount.MountPath) || mount.SubPathExpr != "" || !originalVolumeSubPath(mount.SubPath) {
				return ErrInstall
			}
			key := container.Name + "\x00" + mount.MountPath + "\x00" + mount.SubPath
			if seen[key] {
				return ErrInstall
			}
			seen[key] = true
			out = append(out, OriginalSharedRuntimeVolumeMount{Container: container.Name, MountPath: mount.MountPath, SubPath: mount.SubPath})
		}
		return nil
	}
	for _, container := range pod.Spec.InitContainers {
		if err := add(container); err != nil {
			return nil, err
		}
	}
	for _, container := range pod.Spec.Containers {
		if err := add(container); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, ErrInstall
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Container != out[j].Container {
			return out[i].Container < out[j].Container
		}
		if out[i].MountPath != out[j].MountPath {
			return out[i].MountPath < out[j].MountPath
		}
		return out[i].SubPath < out[j].SubPath
	})
	return out, nil
}

func originalVolumeMountPath(value string) bool {
	return value != "" && path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\\\x00\r\n")
}

func originalVolumeSubPath(value string) bool {
	return value == "" || !path.IsAbs(value) && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\x00\r\n:")
}
