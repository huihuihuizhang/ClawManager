package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// InstanceMountInputError carries only stable diagnostic coordinates, never
// credentials, observed Pod bodies or a substitute authorization receipt.
type InstanceMountInputError struct {
	Code       string
	InstanceID int
	MountID    string
}

func (e *InstanceMountInputError) Error() string {
	return "original instance mount input unavailable: " + e.Code
}
func (*InstanceMountInputError) Is(target error) bool { return target == d.ErrNotReady }
func (e *InstanceMountInputError) Unwrap() error {
	if e.Code == "stopped_original_snapshot_and_witness_required" {
		return c.ErrSourceRecoveryStoppedWitnessRequired
	}
	return d.ErrNotReady
}

func mountInputError(code string, instance int, mount string) error {
	return &InstanceMountInputError{Code: code, InstanceID: instance, MountID: mount}
}

// Layout selects an owner-approved per-instance directory. The builder derives
// Kubernetes identity/hash fields itself; it never infers ownership from a
// pathname or a common Runtime Pod. This is original private authoring input,
// not a public request or authority for a later task.
type InstancePersistentMountLayout struct {
	InstanceID                                      int
	MountID, Container, Volume, MountPath, DataPath string
}

// BuildOriginalInstanceMountScope prepares UNSIGNED comparison data for the
// existing original material definition. D must supply SQL/native observations
// under its original maintenance/source authority, then use A's unchanged
// producer/sequence to sign the definition. This helper only GETs metadata. A
// returned document is neither completeness, stopped proof nor a source grant.
// Two full bounded reads and exact original pins reject drift; they do not turn
// separate API reads into a storage/SQL consistency point.
func BuildOriginalInstanceMountScope(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, instances []b.InstanceIdentity, specs []b.RuntimeWriterSpec, layouts []InstancePersistentMountLayout) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || cfg.Namespace == "" || cfg.NamespaceUID == "" || len(instances) > 9998 || len(layouts) > 9998 || len(specs) != len(instances) {
		return nil, mountInputError("invalid_original_inventory", 0, "")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, mountInputError("bounded_original_context_required", 0, "")
	}
	byID := map[int]b.RuntimeWriterSpec{}
	for _, spec := range specs {
		if byID[spec.Source.ID].Source.ID != 0 {
			return nil, mountInputError("duplicate_runtime_binding", spec.Source.ID, "")
		}
		byID[spec.Source.ID] = spec
	}
	owners := map[int]b.InstanceIdentity{}
	for _, instance := range instances {
		if instance.ID <= 0 || instance.UserID <= 0 || instance.Generation <= 0 || owners[instance.ID].ID != 0 || instance.Mode != "lite" || instance.OS != "linux" {
			return nil, mountInputError("unsupported_or_ambiguous_instance", instance.ID, "")
		}
		if instance.Status == "stopped" {
			return nil, mountInputError("stopped_original_snapshot_and_witness_required", instance.ID, "")
		}
		spec := byID[instance.ID]
		if instance.Status != "running" || spec.Source != instance || spec.Kind != "gateway" || spec.UID == "" || spec.Runtime.Version != "runtime-locator.v2" || spec.Runtime.RegisteredPodUID != "" && spec.Runtime.RegisteredPodUID != spec.UID || spec.RuntimeNamespace() != cfg.Namespace || spec.RuntimePod() == "" || instance.Namespace != "" && instance.Namespace != spec.RuntimeNamespace() || instance.Pod != "" && instance.Pod != spec.RuntimePod() {
			return nil, mountInputError("sql_runtime_binding_mismatch", instance.ID, "")
		}
		owners[instance.ID] = instance
	}
	for _, layout := range layouts {
		if owners[layout.InstanceID].ID == 0 {
			return nil, mountInputError("foreign_instance_layout", layout.InstanceID, layout.MountID)
		}
	}
	var originalPods map[int]string
	read := func() (*productionPersistentMountScope, error) {
		ns, err := client.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
		if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
			return nil, mountInputError("namespace_identity_changed", 0, "")
		}
		scope := &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{}}
		observedPods := map[int]string{}
		for _, instance := range instances {
			spec := byID[instance.ID]
			pod, err := client.CoreV1().Pods(cfg.Namespace).Get(ctx, spec.RuntimePod(), metav1.GetOptions{})
			if err != nil || string(pod.UID) != spec.UID || pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" || cfg.Security.NodeUIDs[pod.Spec.NodeName] == "" {
				return nil, mountInputError("original_runtime_pod_changed", instance.ID, "")
			}
			node, err := client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err != nil || string(node.UID) != cfg.Security.NodeUIDs[pod.Spec.NodeName] || node.DeletionTimestamp != nil || node.Labels[corev1.LabelOSStable] != "linux" {
				return nil, mountInputError("original_node_identity_changed", instance.ID, "")
			}
			observedPods[instance.ID] = string(pod.UID) + "/" + kube.ContentHash(pod.Spec)
			primary := false
			for _, container := range pod.Spec.Containers {
				for _, mount := range container.VolumeMounts {
					primary = primary || cleanMountRoot(instance.Workspace) && (instance.Workspace == mount.MountPath || strings.HasPrefix(instance.Workspace, mount.MountPath+"/"))
				}
			}
			if !primary {
				return nil, mountInputError("primary_workspace_mount_missing", instance.ID, "")
			}
			var selected []productionPersistentMountBinding
			for _, layout := range layouts {
				if layout.InstanceID != instance.ID {
					continue
				}
				mapping := productionPersistentMountBinding{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, MountID: layout.MountID, Container: layout.Container, Volume: layout.Volume, MountPath: layout.MountPath, DataPath: layout.DataPath, Namespace: cfg.Namespace, Pod: pod.Name, PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec), Node: pod.Spec.NodeName, NodeUID: cfg.Security.NodeUIDs[pod.Spec.NodeName]}
				for _, volume := range pod.Spec.Volumes {
					if volume.Name == layout.Volume {
						mapping.VolumeSourceSHA256 = kube.ContentHash(volume.VolumeSource)
					}
				}
				selected = append(selected, mapping)
			}
			if checkPersistentMountCoverage(instance, pod, selected) != nil {
				return nil, mountInputError("incomplete_persistent_mount_layout", instance.ID, "")
			}
			scope.Mounts = append(scope.Mounts, selected...)
		}
		sort.Slice(scope.Mounts, func(i, j int) bool {
			a, b := scope.Mounts[i], scope.Mounts[j]
			if a.InstanceID != b.InstanceID {
				return a.InstanceID < b.InstanceID
			}
			return a.MountID < b.MountID
		})
		if err := checkOriginalPersistentMountPins(ctx, client, cfg, scope); err != nil {
			return nil, err
		}
		if originalPods != nil && !reflect.DeepEqual(originalPods, observedPods) {
			return nil, mountInputError("original_mount_inventory_drift", 0, "")
		}
		originalPods = observedPods
		return scope, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	last, err := read()
	if err != nil {
		return nil, err
	}
	a, _ := json.Marshal(first)
	z, _ := json.Marshal(last)
	if string(a) != string(z) || ctx.Err() != nil {
		return nil, mountInputError("original_mount_inventory_drift", 0, "")
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil || ctx.Err() != nil {
		return nil, mountInputError("namespace_identity_changed", 0, "")
	}
	return z, nil
}

func checkInstancePersistentMountPins(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, instance b.InstanceIdentity, pod *corev1.Pod, scope *productionPersistentMountScope) error {
	if scope.validate() != nil || pod == nil {
		return mountInputError("original_mount_scope_required", instance.ID, "")
	}
	var declarations []productionPersistentMountBinding
	for _, mapping := range scope.Mounts {
		if mapping.InstanceID == instance.ID {
			declarations = append(declarations, mapping)
		}
	}
	if checkPersistentMountCoverage(instance, pod, declarations) != nil {
		return mountInputError("incomplete_persistent_mount_layout", instance.ID, "")
	}
	for _, mapping := range declarations {
		if _, _, err := resolvePersistentMount(ctx, client, cfg, instance, pod, mapping, productionInstanceMount{InstanceID: instance.ID}); err != nil {
			return mountInputError("original_mount_pin_changed", instance.ID, mapping.MountID)
		}
	}
	after, err := client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || after.UID != pod.UID || after.DeletionTimestamp != nil || !reflect.DeepEqual(after.Spec, pod.Spec) || ctx.Err() != nil {
		return mountInputError("original_mount_inventory_drift", instance.ID, "")
	}
	return nil
}

// Called inside existing authenticated materialization/finalization. It only
// verifies selected pins; SQL owner/generation and the complete mount universe
// are independently checked again by the task/first-install readers.
func checkOriginalPersistentMountPins(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, scope *productionPersistentMountScope) error {
	if scope == nil {
		return nil
	} // prior material stays readable; nonempty task admission still requires a scope
	if ctx == nil || ctx.Err() != nil || client == nil || scope.validate() != nil {
		return mountInputError("invalid_persistent_mount_scope", 0, "")
	}
	var resolved []productionInstanceMount
	for _, mapping := range scope.Mounts {
		pod, err := client.CoreV1().Pods(cfg.Namespace).Get(ctx, mapping.Pod, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil {
			return mountInputError("original_mount_pod_unavailable", mapping.InstanceID, mapping.MountID)
		}
		instance := b.InstanceIdentity{ID: mapping.InstanceID, UserID: mapping.UserID, Generation: mapping.Generation}
		mount, _, err := resolvePersistentMount(ctx, client, cfg, instance, pod, mapping, productionInstanceMount{InstanceID: mapping.InstanceID})
		if err != nil {
			return mountInputError("original_mount_pin_changed", mapping.InstanceID, mapping.MountID)
		}
		resolved = append(resolved, mount)
	}
	if overlappingInstanceMounts(resolved) {
		return mountInputError("overlapping_instance_mount_roots", 0, "")
	}
	return ctx.Err()
}

func persistentMountsForInstances(scope *productionPersistentMountScope, instances []b.InstanceIdentity) (map[int][]productionPersistentMountBinding, error) {
	out := map[int][]productionPersistentMountBinding{}
	if len(instances) == 0 && scope == nil {
		return out, nil
	}
	if scope.validate() != nil {
		return nil, mountInputError("original_mount_scope_required", 0, "")
	}
	owners := map[int]b.InstanceIdentity{}
	for _, instance := range instances {
		if instance.ID <= 0 || instance.UserID <= 0 || instance.Generation <= 0 || owners[instance.ID].ID != 0 {
			return nil, mountInputError("invalid_original_inventory", instance.ID, "")
		}
		if instance.Status == "stopped" {
			return nil, mountInputError("stopped_original_snapshot_and_witness_required", instance.ID, "")
		}
		if instance.Mode != "lite" || instance.OS != "linux" || instance.Status != "running" {
			return nil, mountInputError("unsupported_instance", instance.ID, "")
		}
		owners[instance.ID] = instance
	}
	for _, mapping := range scope.Mounts {
		instance := owners[mapping.InstanceID]
		if instance.ID == 0 || instance.UserID != mapping.UserID || instance.Generation != mapping.Generation {
			return nil, mountInputError("sql_mount_owner_generation_mismatch", mapping.InstanceID, mapping.MountID)
		}
		out[mapping.InstanceID] = append(out[mapping.InstanceID], mapping)
	}
	return out, nil
}
