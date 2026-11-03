package systembackupexecution

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Diagnostics cannot be supplied as authority to any capture/first-adoption
// constructor. No token, endpoint, Pod env/args or business file is returned.
type InstanceMountObservation struct {
	CurrentStoppedPro                                                                        *CurrentStoppedProSourceMaterial `json:",omitempty"`
	InstanceID, UserID, Generation                                                           int
	Type, Status, Workspace                                                                  string
	Namespace, RuntimePod, RuntimePodUID, PodSpecSHA256, Node, NodeUID, RuntimeBindingSHA256 string
	Mounts                                                                                   []InstanceMountObservationEntry
	Issues                                                                                   []InstanceMountInputIssue
}
type InstanceMountObservationEntry struct {
	Container, Volume, MountPath, SubPath, StorageKind string
	ReadOnly                                           bool
}
type InstanceMountInputIssue struct {
	Code       string
	InstanceID int
	MountID    string
}
type InstanceMountInputObservation struct {
	Version, InstallationID, NamespaceUID, InventorySHA256, SourceScopeSHA256 string
	CheckedAt, Until                                                          time.Time
	Instances                                                                 []InstanceMountObservation
	Issues                                                                    []InstanceMountInputIssue
	DiagnosticOnly                                                            bool
}

// ObserveInstanceMountInputs is the concrete B-1 read entry. It uses the SAME
// original signed delegation, independent least-privilege SQL snapshot and
// native runtime resolver as production. It never prepares a writer, stops an
// Agent, creates a task or fills a missing physical witness. Stopped sources
// are reported without probing/starting an old or guessed runtime Pod.
func (s *DeploymentService) ObserveInstanceMountInputs(ctx context.Context) (InstanceMountInputObservation, error) {
	var zero InstanceMountInputObservation
	x, err := s.newSourceSQLObservation(ctx)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	first, err := x.observeInventory(ctx)
	if err != nil {
		return zero, err
	}
	issues := []InstanceMountInputIssue{}
	if _, err := persistentMountsForInstances(s.captureMaterials.Discovery.PersistentMounts, first.source.Instances); err != nil {
		var missing *InstanceMountInputError
		if !errors.As(err, &missing) {
			return zero, err
		}
		issues = append(issues, InstanceMountInputIssue{Code: missing.Code, InstanceID: missing.InstanceID, MountID: missing.MountID})
	}
	read := func() ([]InstanceMountObservation, error) {
		rows := []InstanceMountObservation{}
		for _, instance := range first.source.Instances {
			if x.recheck(ctx) != nil {
				return nil, d.ErrNotReady
			}
			if isCurrentStoppedPro(instance) {
				material, err := currentStoppedProMaterialFor(s.captureMaterials.Discovery.PersistentMounts, instance)
				if err != nil {
					return nil, err
				}
				actual, err := observeCurrentStoppedPro(ctx, x.delegation.owner.Client, s.Config, instance, first.sql.metadata.CurrentStoppedProStorage[instance.ID])
				if err != nil || !reflect.DeepEqual(actual, *material) {
					return nil, mountInputError("current_stopped_pro_baseline_changed", instance.ID, "")
				}
				rows = append(rows, currentStoppedProDiagnostic(instance, actual))
				continue
			}
			if instance.Status == "stopped" {
				rows = append(rows, projectInstanceMountObservation(instance, b.RuntimeWriterSpec{}, nil, s.Config, s.captureMaterials.Discovery.PersistentMounts))
				continue
			}
			if instance.Mode != "lite" || instance.OS != "linux" || s.RuntimeControl == nil {
				return nil, mountInputError("unsupported_instance", instance.ID, "")
			}
			spec, err := s.RuntimeControl.ResolveGatewaySource(ctx, instance)
			if err != nil {
				return nil, err
			}
			pod, err := s.Runtime.Owner.Client.CoreV1().Pods(spec.RuntimeNamespace()).Get(ctx, spec.RuntimePod(), metav1.GetOptions{})
			if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) != spec.UID || spec.Source != instance || pod.Namespace != s.Config.Namespace || x.recheck(ctx) != nil {
				return nil, mountInputError("sql_runtime_binding_mismatch", instance.ID, "")
			}
			node, err := s.Runtime.Owner.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err != nil || node.DeletionTimestamp != nil || string(node.UID) != s.Config.Security.NodeUIDs[pod.Spec.NodeName] || node.Labels[corev1.LabelOSStable] != "linux" {
				return nil, mountInputError("original_node_identity_changed", instance.ID, "")
			}
			row := projectInstanceMountObservation(instance, spec, pod, s.Config, s.captureMaterials.Discovery.PersistentMounts)
			if len(row.Issues) == 0 {
				if err := checkInstancePersistentMountPins(ctx, s.Runtime.Owner.Client, s.Config, instance, pod, s.captureMaterials.Discovery.PersistentMounts); err != nil {
					return nil, err
				}
			}
			rows = append(rows, row)
		}
		return rows, nil
	}
	rows, err := read()
	if err != nil {
		return zero, err
	}
	lastRows, err := read()
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(rows, lastRows) {
		return zero, mountInputError("original_mount_inventory_drift", 0, "")
	}
	last, err := x.observeInventory(ctx)
	if err != nil {
		return zero, err
	}
	if first.sha256 != last.sha256 || !reflect.DeepEqual(first.sql.metadata, last.sql.metadata) || x.recheck(ctx) != nil || !time.Now().Before(x.delegation.until) {
		return zero, d.ErrNotReady
	}
	return InstanceMountInputObservation{Version: "b-original-instance-mount-diagnostic.v1", InstallationID: s.Config.InstallationID, NamespaceUID: s.Config.NamespaceUID, InventorySHA256: last.sha256, SourceScopeSHA256: x.delegation.scope, CheckedAt: last.sql.observedAt, Until: x.delegation.until, Instances: lastRows, Issues: issues, DiagnosticOnly: true}, nil
}

func projectInstanceMountObservation(instance b.InstanceIdentity, spec b.RuntimeWriterSpec, pod *corev1.Pod, cfg DeploymentConfig, scope *productionPersistentMountScope) InstanceMountObservation {
	out := InstanceMountObservation{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, Type: instance.Type, Status: instance.Status, Workspace: instance.Workspace, Mounts: []InstanceMountObservationEntry{}, Issues: []InstanceMountInputIssue{}}
	issue := func(code, mount string) {
		out.Issues = append(out.Issues, InstanceMountInputIssue{Code: code, InstanceID: instance.ID, MountID: mount})
	}
	if instance.Status == "stopped" {
		issue("stopped_original_snapshot_and_witness_required", "")
		return out
	}
	if pod == nil || spec.Source != instance || spec.UID != string(pod.UID) || pod.Namespace != cfg.Namespace {
		issue("sql_runtime_binding_mismatch", "")
		return out
	}
	out.Namespace, out.RuntimePod, out.RuntimePodUID, out.PodSpecSHA256, out.Node, out.NodeUID = pod.Namespace, pod.Name, string(pod.UID), kube.ContentHash(pod.Spec), pod.Spec.NodeName, cfg.Security.NodeUIDs[pod.Spec.NodeName]
	out.RuntimeBindingSHA256 = kube.ContentHash(spec)
	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		volumes[v.Name] = v
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
		for _, mount := range container.VolumeMounts {
			volume := volumes[mount.Name]
			if transientSource(volume) {
				continue
			}
			kind := "unsupported"
			switch {
			case volume.PersistentVolumeClaim != nil:
				kind = "pvc"
			case volume.HostPath != nil:
				kind = "hostpath"
			case volume.NFS != nil:
				kind = "nfs"
			}
			out.Mounts = append(out.Mounts, InstanceMountObservationEntry{Container: container.Name, Volume: mount.Name, MountPath: mount.MountPath, SubPath: mount.SubPath, ReadOnly: mount.ReadOnly, StorageKind: kind})
		}
	}
	sort.Slice(out.Mounts, func(i, j int) bool {
		a, b := out.Mounts[i], out.Mounts[j]
		return a.Container+"/"+a.MountPath < b.Container+"/"+b.MountPath
	})
	if scope.validate() != nil {
		issue("original_mount_scope_required", "")
		return out
	}
	var selected []productionPersistentMountBinding
	for _, mapping := range scope.Mounts {
		if mapping.InstanceID != instance.ID {
			continue
		}
		selected = append(selected, mapping)
		if mapping.UserID != instance.UserID || mapping.Generation != instance.Generation {
			issue("sql_mount_owner_generation_mismatch", mapping.MountID)
		}
	}
	if checkPersistentMountCoverage(instance, pod, selected) != nil {
		issue("incomplete_persistent_mount_layout", "")
	}
	return out
}
