package systembackupexecution

import (
	"context"
	"encoding/hex"
	"path"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/kube"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const stagingLocationVersion = "original-staging-location.v1"

// StagingLocationReference is part of the signed deployment, never a task input.
// The controller and every worker use the root of this exact PVC on this node.
// API mount observations do not claim inspection of a process mount namespace.
type StagingLocationReference struct {
	Version       string `json:"schema_version"`
	Node          string `json:"node"`
	NodeUID       string `json:"node_uid"`
	Container     string `json:"container"`
	Volume        string `json:"volume"`
	ContainerPath string `json:"container_path"`
	Claim         string `json:"claim"`
	ClaimUID      string `json:"claim_uid"`
	PV            string `json:"pv"`
	PVUID         string `json:"pv_uid"`
	PVSpecSHA256  string `json:"pv_spec_sha256"`
}

func (r *StagingLocationReference) validate(cfg DeploymentConfig) error {
	if r == nil || r.Version != stagingLocationVersion || r.Node == "" || r.Node != cfg.Workspace.Node || r.NodeUID == "" || cfg.Security.NodeUIDs[r.Node] != r.NodeUID || r.Container == "" || r.Volume == "" || r.Claim == "" || r.Claim != cfg.StagingClaim || r.ClaimUID == "" || r.PV == "" || r.PVUID == "" || len(r.PVSpecSHA256) != 64 || strings.ToLower(r.PVSpecSHA256) != r.PVSpecSHA256 || r.ContainerPath != cfg.StagingDirectory || !path.IsAbs(r.ContainerPath) || path.Clean(r.ContainerPath) != r.ContainerPath || strings.ContainsAny(r.ContainerPath, "\\\x00\r\n") {
		return c.ErrExecutionAuthority
	}
	if _, err := hex.DecodeString(r.PVSpecSHA256); err != nil {
		return c.ErrExecutionAuthority
	}
	count := 0
	for _, pin := range cfg.Security.Volumes {
		if pin.Kind == "PersistentVolumeClaim" && pin.Name == r.Claim {
			if pin.UID != r.ClaimUID || pin.PVName != r.PV || pin.PVUID != r.PVUID || pin.SHA256 != r.PVSpecSHA256 {
				return c.ErrExecutionAuthority
			}
			count++
		}
	}
	if count != 1 {
		return c.ErrExecutionAuthority
	}
	return nil
}

// checkStagingLocation reads only the configured controller, node, PVC and PV.
// Missing objects, replacement UIDs, shadow mounts and subpath aliases refuse;
// no current volume or available node is adopted as a replacement.
func (s *DeploymentService) checkStagingLocation(ctx context.Context, client kubernetes.Interface) error {
	if s == nil || ctx == nil || ctx.Err() != nil || client == nil || s.Config.StagingLocation.validate(s.Config) != nil || s.controllerActor.PodName == "" || s.controllerActor.PodUID == "" || s.controllerActor.ServiceAccountName == "" {
		return c.ErrExecutionAuthority
	}
	r, cfg := s.Config.StagingLocation, s.Config
	ns, err := client.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	pod, err := client.CoreV1().Pods(cfg.Namespace).Get(ctx, s.controllerActor.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != s.controllerActor.PodUID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName != r.Node || pod.Spec.ServiceAccountName != s.controllerActor.ServiceAccountName {
		return c.ErrExecutionAuthority
	}
	node, err := client.CoreV1().Nodes().Get(ctx, r.Node, metav1.GetOptions{})
	if err != nil || string(node.UID) != r.NodeUID || node.DeletionTimestamp != nil || node.Spec.Unschedulable || node.Labels[corev1.LabelOSStable] != "linux" {
		return c.ErrExecutionAuthority
	}
	ready := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			ready = condition.Status == corev1.ConditionTrue
		}
		if (condition.Type == corev1.NodeDiskPressure || condition.Type == corev1.NodeMemoryPressure || condition.Type == corev1.NodePIDPressure) && condition.Status != corev1.ConditionFalse {
			return c.ErrExecutionAuthority
		}
	}
	if !ready || !stagingControllerMountMatches(pod, r) {
		return c.ErrExecutionAuthority
	}
	claim, err := client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Get(ctx, r.Claim, metav1.GetOptions{})
	if err != nil || string(claim.UID) != r.ClaimUID || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName != r.PV || (claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) {
		return c.ErrExecutionAuthority
	}
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, r.PV, metav1.GetOptions{})
	if err != nil || string(pv.UID) != r.PVUID || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || kube.ContentHash(pv.Spec) != r.PVSpecSHA256 || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != cfg.Namespace || pv.Spec.ClaimRef.Name != r.Claim || string(pv.Spec.ClaimRef.UID) != r.ClaimUID || (pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) || !stagingPVMatchesNode(pv, node) {
		return c.ErrExecutionAuthority
	}
	if (pv.Spec.NFS != nil && pv.Spec.NFS.ReadOnly) || (pv.Spec.CSI != nil && pv.Spec.CSI.ReadOnly) {
		return c.ErrExecutionAuthority
	}
	for _, option := range pv.Spec.MountOptions {
		if option == "ro" {
			return c.ErrExecutionAuthority
		}
	}
	writable := false
	for _, mode := range claim.Spec.AccessModes {
		writable = writable || mode == corev1.ReadWriteOnce || mode == corev1.ReadWriteMany || mode == corev1.ReadWriteOncePod
	}
	if !writable {
		return c.ErrExecutionAuthority
	}
	return nil
}

func stagingControllerMountMatches(pod *corev1.Pod, r *StagingLocationReference) bool {
	// This is the controller's own startup path. Its readiness probe depends on
	// this check, so require a real running container rather than PodReady.
	volumes, containers, statuses := 0, 0, 0
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == r.Volume {
			if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != r.Claim || volume.PersistentVolumeClaim.ReadOnly {
				return false
			}
			volumes++
		}
	}
	for _, container := range pod.Spec.Containers {
		if container.Name != r.Container {
			continue
		}
		containers++
		mounts := 0
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == r.ContainerPath && mount.Name == r.Volume && !mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == "" {
				mounts++
				continue
			}
			if mount.Name == r.Volume || mount.MountPath == r.ContainerPath || strings.HasPrefix(mount.MountPath, r.ContainerPath+"/") {
				return false
			}
		}
		if mounts != 1 {
			return false
		}
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == r.Container {
			if status.ContainerID == "" || status.State.Running == nil || status.State.Terminated != nil || status.State.Waiting != nil {
				return false
			}
			statuses++
		}
	}
	return volumes == 1 && containers == 1 && statuses == 1
}

func stagingPVMatchesNode(pv *corev1.PersistentVolume, node *corev1.Node) bool {
	if pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
		// Local and HostPath data cannot use an unscoped node selection.
		return pv.Spec.Local == nil && pv.Spec.HostPath == nil
	}
	for _, term := range pv.Spec.NodeAffinity.Required.NodeSelectorTerms {
		if len(term.MatchExpressions)+len(term.MatchFields) == 0 {
			continue
		}
		matches := true
		for _, requirement := range term.MatchExpressions {
			value, exists := node.Labels[requirement.Key]
			matches = matches && stagingNodeRequirement(requirement, value, exists)
		}
		for _, requirement := range term.MatchFields {
			matches = matches && requirement.Key == "metadata.name" && stagingNodeRequirement(requirement, node.Name, true)
		}
		if matches {
			return true
		}
	}
	return false
}

func stagingNodeRequirement(r corev1.NodeSelectorRequirement, value string, exists bool) bool {
	contains := false
	for _, candidate := range r.Values {
		contains = contains || candidate == value
	}
	switch r.Operator {
	case corev1.NodeSelectorOpIn:
		return len(r.Values) > 0 && exists && contains
	case corev1.NodeSelectorOpNotIn:
		return len(r.Values) > 0 && (!exists || !contains)
	case corev1.NodeSelectorOpExists:
		return len(r.Values) == 0 && exists
	case corev1.NodeSelectorOpDoesNotExist:
		return len(r.Values) == 0 && !exists
	case corev1.NodeSelectorOpGt, corev1.NodeSelectorOpLt:
		if !exists || len(r.Values) != 1 {
			return false
		}
		actual, e1 := strconv.ParseInt(value, 10, 64)
		bound, e2 := strconv.ParseInt(r.Values[0], 10, 64)
		return e1 == nil && e2 == nil && ((r.Operator == corev1.NodeSelectorOpGt && actual > bound) || (r.Operator == corev1.NodeSelectorOpLt && actual < bound))
	}
	return false
}

// Publication definitions call this before constructing the native Job. The
// return value is never an empty legacy node and never derives from capacity.
func (s *DeploymentService) publicationStagingNode(ctx context.Context) (string, error) {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.checkStagingLocation(ctx, s.Runtime.Owner.Client) != nil {
		return "", c.ErrExecutionAuthority
	}
	return s.Config.StagingLocation.Node, nil
}

// The native constructor requires StagingLocation. Older direct component
// compositions still pin their original workspace node rather than producing
// unplaced Jobs; they do not prove a deployed staging location.
func (s *DeploymentService) captureOperationsAtStagingNode() (map[string]productionCaptureOperation, error) {
	if s == nil || s.captureMaterials == nil || s.Config.Workspace.Node == "" {
		return nil, c.ErrExecutionAuthority
	}
	node := s.Config.Workspace.Node
	if s.Config.StagingLocation != nil {
		if s.Config.StagingLocation.validate(s.Config) != nil {
			return nil, c.ErrExecutionAuthority
		}
		node = s.Config.StagingLocation.Node
	}
	if node != s.Config.Workspace.Node || s.Config.Security.NodeUIDs[node] == "" {
		return nil, c.ErrExecutionAuthority
	}
	operations := make(map[string]productionCaptureOperation, len(s.captureMaterials.Operations))
	for name, original := range s.captureMaterials.Operations {
		if original.Workload.NodeName != "" && original.Workload.NodeName != node {
			return nil, c.ErrExecutionAuthority
		}
		original.Workload.NodeName = node
		operations[name] = original
	}
	return operations, nil
}
