package systembackupexecution

import (
	"context"
	"path"
	"strings"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (x *bootstrapSourceRegistryReader) checkAdditionalRuntimeMounts(ctx context.Context, client kubernetes.Interface, source b.InstanceIdentity, pod *corev1.Pod) error {
	if x.checkPhysical(ctx) != nil || x.materials.Discovery == nil {
		return install.ErrInstall
	}
	if err := checkInstancePersistentMountPins(ctx, client, x.config, source, pod, x.materials.Discovery.PersistentMounts); err != nil {
		return err
	}
	return x.checkPhysical(ctx)
}

func (x *bootstrapSourceRegistryReader) verifiedNativeWriter(id int, all []bootstrapSourceNativeWriter) (bootstrapSourceNativeWriter, error) {
	for _, actual := range all {
		if actual.InstanceID == id {
			return actual, nil
		}
	}
	return bootstrapSourceNativeWriter{}, install.ErrInstall
}

func (x *bootstrapSourceRegistryReader) checkRuntimeWorkspace(ctx context.Context, client kubernetes.Interface, instances []b.InstanceIdentity, native []bootstrapSourceNativeWriter) error {
	var scope *productionPersistentMountScope
	if x.materials.Discovery != nil {
		scope = x.materials.Discovery.PersistentMounts
	}
	if _, err := persistentMountsForInstances(scope, instances); err != nil {
		return err
	}
	if checkCurrentStoppedProScopes(ctx, client, x.config, scope, instances) != nil {
		return install.ErrInstall
	}
	if !hasRunningSourceInstances(instances) {
		return x.checkPhysical(ctx)
	}
	if x.config.Workspace.NFS != nil {
		return x.checkNFSRuntimeWorkspace(ctx, client, instances, native)
	}
	target, e := client.CoreV1().PersistentVolumeClaims(x.config.Namespace).Get(ctx, x.config.Workspace.Claim, metav1.GetOptions{})
	if e != nil || target.Spec.VolumeName == "" || target.DeletionTimestamp != nil {
		return install.ErrInstall
	}
	pinned := false
	for _, ref := range x.config.Security.Volumes {
		if ref.Kind == "PersistentVolumeClaim" && ref.Name == target.Name && ref.UID == string(target.UID) && ref.PVName == target.Spec.VolumeName && ref.PVUID != "" {
			pv, e := client.CoreV1().PersistentVolumes().Get(ctx, ref.PVName, metav1.GetOptions{})
			if e == nil && string(pv.UID) == ref.PVUID && pv.DeletionTimestamp == nil {
				pinned = true
			}
		}
	}
	if !pinned {
		return install.ErrInstall
	}
	for _, source := range instances {
		if source.Status != "running" {
			continue
		}
		namespace, name, uid := source.Namespace, source.Pod, ""
		if source.Mode == "lite" {
			if native == nil {
				return install.ErrInstall
			}
			mapped, e := x.verifiedNativeWriter(source.ID, native)
			if e != nil {
				return e
			}
			namespace, name, uid = mapped.Namespace, mapped.Pod, mapped.PodUID
		}
		if namespace != x.config.Namespace || name == "" {
			return install.ErrInstall
		}
		pod, e := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil || pod.DeletionTimestamp != nil {
			return install.ErrInstall
		}
		if uid != "" && string(pod.UID) != uid {
			return install.ErrInstall
		}
		if err := x.checkAdditionalRuntimeMounts(ctx, client, source, pod); err != nil {
			return err
		}
		found := false
		expected := path.Join(x.config.Workspace.SubPath, strings.TrimPrefix(source.Workspace, x.config.RuntimeSources.WorkspaceRoot+"/"))
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				ancestor := source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/")
				descendant := strings.HasPrefix(mount.MountPath, source.Workspace+"/")
				if !ancestor && !descendant {
					continue
				}
				if mount.SubPathExpr != "" || path.Clean(mount.MountPath) != mount.MountPath {
					return install.ErrInstall
				}
				relative := mount.SubPath
				wanted := expected
				if ancestor && source.Workspace != mount.MountPath {
					relative = path.Join(mount.SubPath, strings.TrimPrefix(source.Workspace, mount.MountPath+"/"))
				}
				if descendant {
					wanted = path.Join(x.config.Workspace.SubPath, strings.TrimPrefix(mount.MountPath, x.config.RuntimeSources.WorkspaceRoot+"/"))
				}
				if path.Clean(relative) != path.Clean(wanted) {
					return install.ErrInstall
				}
				matched := false
				for _, volume := range pod.Spec.Volumes {
					if volume.Name != mount.Name || volume.PersistentVolumeClaim == nil {
						continue
					}
					claim, e := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
					if e == nil && claim.DeletionTimestamp == nil && claim.Spec.VolumeName == target.Spec.VolumeName {
						matched = true
					}
				}
				if !matched {
					return install.ErrInstall
				}
				found = found || ancestor
			}
		}
		if !found {
			return install.ErrInstall
		}
	}
	return nil
}

// The NFS worker mounts only the installation-owned subpath. Every live source
// must resolve to that exact export and a descendant of that subpath; a nested
// or aliased mount cannot silently add content outside the capture tree.
func (x *bootstrapSourceRegistryReader) checkNFSRuntimeWorkspace(ctx context.Context, client kubernetes.Interface, instances []b.InstanceIdentity, native []bootstrapSourceNativeWriter) error {
	cfg := x.config.Workspace
	if cfg.NFS == nil || !cfg.validSource(x.config.InstallationID) {
		return install.ErrInstall
	}
	ownedRoot := path.Join(x.config.RuntimeSources.WorkspaceRoot, cfg.SubPath)
	for _, source := range instances {
		if !strings.HasPrefix(source.Workspace, ownedRoot+"/") {
			return install.ErrInstall
		}
		if source.Status != "running" {
			continue
		}
		namespace, name, uid := source.Namespace, source.Pod, ""
		if source.Mode == "lite" {
			if native == nil {
				return install.ErrInstall
			}
			mapped, err := x.verifiedNativeWriter(source.ID, native)
			if err != nil {
				return err
			}
			namespace, name, uid = mapped.Namespace, mapped.Pod, mapped.PodUID
		}
		if namespace != x.config.Namespace || name == "" {
			return install.ErrInstall
		}
		pod, err := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || (uid != "" && string(pod.UID) != uid) {
			return install.ErrInstall
		}
		if err := x.checkAdditionalRuntimeMounts(ctx, client, source, pod); err != nil {
			return err
		}
		found := false
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				ancestor := source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/")
				descendant := strings.HasPrefix(mount.MountPath, source.Workspace+"/")
				if !ancestor && !descendant {
					continue
				}
				if descendant || mount.SubPathExpr != "" || !path.IsAbs(mount.MountPath) || path.Clean(mount.MountPath) != mount.MountPath ||
					(mount.SubPath != "" && (path.IsAbs(mount.SubPath) || path.Clean(mount.SubPath) != mount.SubPath || mount.SubPath == ".." || strings.HasPrefix(mount.SubPath, "../"))) {
					return install.ErrInstall
				}
				relative := strings.TrimPrefix(source.Workspace, mount.MountPath)
				relative = strings.TrimPrefix(relative, "/")
				physical := path.Join(mount.SubPath, relative)
				if physical != cfg.SubPath && !strings.HasPrefix(physical, cfg.SubPath+"/") {
					return install.ErrInstall
				}
				matched := false
				for _, volume := range pod.Spec.Volumes {
					if volume.Name != mount.Name {
						continue
					}
					if volume.NFS == nil || volume.NFS.Server != cfg.NFS.Server || volume.NFS.Path != cfg.NFS.Export {
						return install.ErrInstall
					}
					matched = true
				}
				if !matched {
					return install.ErrInstall
				}
				found = true
			}
		}
		if !found {
			return install.ErrInstall
		}
	}
	return nil
}
