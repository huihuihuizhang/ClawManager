package systembackupexecution

import (
	"context"
	"path"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type runningTenantProMount struct {
	Source                                   b.InstanceIdentity
	NamespaceUID, PodUID, PodSpecSHA256      string
	ReplicaSetUID, Deployment, DeploymentUID string
	SubPath                                  string
	Identity                                 kube.MountIdentity
}

func isRunningTenantPro(instance b.InstanceIdentity) bool {
	return instance.Mode == "pro" && instance.OS == "linux" && instance.Status == "running"
}

func validTenantProNamespace(systemNamespace string, source b.InstanceIdentity) bool {
	stem, ok := strings.CutSuffix(systemNamespace, "-system")
	return ok && stem != "" && source.UserID > 0 && source.Namespace == stem+"-user-"+strconv.Itoa(source.UserID)
}

func (m runningTenantProMount) valid() bool {
	s := m.Source
	return isRunningTenantPro(s) && s.ID > 0 && s.UserID > 0 && s.Generation > 0 && s.Namespace != "" && s.Pod != "" && cleanMountRoot(s.Workspace) &&
		m.NamespaceUID != "" && m.PodUID != "" && formalCandidateDigest(m.PodSpecSHA256) && m.ReplicaSetUID != "" && m.Deployment != "" && m.DeploymentUID != "" &&
		m.Identity.Volume == "workspace" && m.Identity.Kind == "PersistentVolumeClaim" && m.Identity.Name != "" && m.Identity.UID != "" &&
		m.Identity.PVName != "" && m.Identity.PVUID != "" && formalCandidateDigest(m.Identity.SHA256) && validTenantMountSubPath(m.SubPath)
}

func validTenantMountSubPath(value string) bool {
	return value == "" || !path.IsAbs(value) && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\x00\r\n:")
}

func tenantWorkspaceSubPath(mount corev1.VolumeMount, workspace string) (string, bool) {
	if !cleanMountRoot(mount.MountPath) || mount.SubPathExpr != "" || !validTenantMountSubPath(mount.SubPath) ||
		workspace != mount.MountPath && !strings.HasPrefix(workspace, mount.MountPath+"/") {
		return "", false
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(workspace, mount.MountPath), "/")
	if relative == "" {
		return mount.SubPath, true
	}
	value := path.Join(mount.SubPath, relative)
	return value, validTenantMountSubPath(value)
}

func runningTenantProMountFor(scope *productionPersistentMountScope, instance b.InstanceIdentity) *runningTenantProMount {
	if scope == nil || !isRunningTenantPro(instance) {
		return nil
	}
	for i := range scope.RunningTenantPro {
		if scope.RunningTenantPro[i].Source == instance {
			return &scope.RunningTenantPro[i]
		}
	}
	return nil
}

func (m runningTenantProMount) matchesWriter(spec b.RuntimeWriterSpec) bool {
	return spec.Source == m.Source && (spec.Kind == "pod" && spec.Name == m.Source.Pod && spec.UID == m.PodUID ||
		spec.Kind == "deployment" && spec.Name == m.Deployment && spec.UID == m.DeploymentUID)
}

func observeRunningTenantProMount(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, source b.InstanceIdentity, spec b.RuntimeWriterSpec) (runningTenantProMount, error) {
	var empty runningTenantProMount
	if !validTenantProNamespace(cfg.Namespace, source) || !isRunningTenantPro(source) || source.Pod == "" || spec.Source != source {
		return empty, d.ErrNotReady
	}
	pod, err := client.CoreV1().Pods(source.Namespace).Get(ctx, source.Pod, metav1.GetOptions{})
	if err != nil || pod.Spec.NodeName == "" || cfg.Security.NodeUIDs[pod.Spec.NodeName] == "" {
		return empty, d.ErrNotReady
	}
	parent := metav1.GetControllerOf(pod)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "ReplicaSet" {
		return empty, d.ErrNotReady
	}
	rs, err := client.AppsV1().ReplicaSets(source.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if err != nil || rs.UID != parent.UID {
		return empty, d.ErrNotReady
	}
	deployment := metav1.GetControllerOf(rs)
	if deployment == nil || deployment.APIVersion != "apps/v1" || deployment.Kind != "Deployment" {
		return empty, d.ErrNotReady
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, source.Namespace, metav1.GetOptions{})
	if err != nil {
		return empty, err
	}
	m := runningTenantProMount{Source: source, NamespaceUID: string(ns.UID), PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec),
		ReplicaSetUID: string(rs.UID), Deployment: deployment.Name, DeploymentUID: string(deployment.UID)}
	if !m.matchesWriter(spec) {
		return empty, d.ErrNotReady
	}
	claimName := ""
	for _, container := range pod.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			subPath, ok := tenantWorkspaceSubPath(mount, source.Workspace)
			if !ok {
				continue
			}
			for _, volume := range pod.Spec.Volumes {
				if volume.Name != mount.Name || volume.PersistentVolumeClaim == nil {
					continue
				}
				if claimName != "" && (claimName != volume.PersistentVolumeClaim.ClaimName || m.SubPath != subPath) {
					return empty, d.ErrNotReady
				}
				claimName, m.SubPath = volume.PersistentVolumeClaim.ClaimName, subPath
			}
		}
	}
	if claimName == "" {
		return empty, d.ErrNotReady
	}
	claim, err := client.CoreV1().PersistentVolumeClaims(source.Namespace).Get(ctx, claimName, metav1.GetOptions{})
	if err != nil || claim.Spec.VolumeName == "" {
		return empty, d.ErrNotReady
	}
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return empty, err
	}
	m.Identity = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
	if err := m.check(ctx, client, cfg.Namespace); err != nil {
		return empty, err
	}
	node, err := client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.DeletionTimestamp != nil || string(node.UID) != cfg.Security.NodeUIDs[pod.Spec.NodeName] || node.Labels[corev1.LabelOSStable] != "linux" {
		return empty, d.ErrNotReady
	}
	return m, nil
}

func (m runningTenantProMount) check(ctx context.Context, client kubernetes.Interface, systemNamespace string) error {
	s := m.Source
	user, instance := strconv.Itoa(s.UserID), strconv.Itoa(s.ID)
	if !m.valid() || !validTenantProNamespace(systemNamespace, s) {
		return d.ErrNotReady
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, s.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != m.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["app"] != "clawreef" || ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != user {
		return d.ErrNotReady
	}
	labels := func(values map[string]string) bool {
		return values["app"] == "clawreef" && values["managed-by"] == "clawreef" && values["user-id"] == user && values["instance-id"] == instance
	}
	pod, err := client.CoreV1().Pods(s.Namespace).Get(ctx, s.Pod, metav1.GetOptions{})
	if err != nil || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !labels(pod.Labels) ||
		string(pod.UID) != m.PodUID || kube.ContentHash(pod.Spec) != m.PodSpecSHA256 || checkPersistentMountCoverage(s, pod, nil) != nil || !m.matchesPodMount(pod) {
		return d.ErrNotReady
	}
	ref := metav1.GetControllerOf(pod)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "ReplicaSet" || string(ref.UID) != m.ReplicaSetUID {
		return d.ErrNotReady
	}
	rs, err := client.AppsV1().ReplicaSets(s.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil || rs.DeletionTimestamp != nil || string(rs.UID) != m.ReplicaSetUID || !labels(rs.Spec.Template.Labels) {
		return d.ErrNotReady
	}
	ref = metav1.GetControllerOf(rs)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "Deployment" || ref.Name != m.Deployment || string(ref.UID) != m.DeploymentUID {
		return d.ErrNotReady
	}
	deployment, err := client.AppsV1().Deployments(s.Namespace).Get(ctx, m.Deployment, metav1.GetOptions{})
	if err != nil || deployment.DeletionTimestamp != nil || string(deployment.UID) != m.DeploymentUID || !labels(deployment.Spec.Template.Labels) {
		return d.ErrNotReady
	}
	claim, err := client.CoreV1().PersistentVolumeClaims(s.Namespace).Get(ctx, m.Identity.Name, metav1.GetOptions{})
	if err != nil || claim.DeletionTimestamp != nil || string(claim.UID) != m.Identity.UID || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName != m.Identity.PVName ||
		len(claim.Spec.AccessModes) != 1 || claim.Spec.AccessModes[0] != corev1.ReadWriteOnce {
		return d.ErrNotReady
	}
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, m.Identity.PVName, metav1.GetOptions{})
	if err != nil || pv.DeletionTimestamp != nil || string(pv.UID) != m.Identity.PVUID || kube.ContentHash(pv.Spec) != m.Identity.SHA256 ||
		pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != s.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID {
		return d.ErrNotReady
	}
	return ctx.Err()
}

func (m runningTenantProMount) matchesPodMount(pod *corev1.Pod) bool {
	volumes := map[string]corev1.Volume{}
	for _, volume := range pod.Spec.Volumes {
		volumes[volume.Name] = volume
	}
	found := false
	for _, container := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
		for _, mount := range container.VolumeMounts {
			volume := volumes[mount.Name]
			if !persistentSource(volume) {
				continue
			}
			subPath, ok := tenantWorkspaceSubPath(mount, m.Source.Workspace)
			if !ok || volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != m.Identity.Name {
				return false
			}
			if subPath != m.SubPath {
				return false
			}
			found = true
		}
	}
	return found
}
