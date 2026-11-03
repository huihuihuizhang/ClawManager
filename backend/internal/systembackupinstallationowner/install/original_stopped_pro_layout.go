package install

import (
	"context"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Independently selected CURRENT original source configuration. This is DATA
// inside the original selection pin, not a historical Pod or absence witness.
// It covers shared claims without inventing per-instance claim labels.
type OriginalStoppedProMountSelection struct{ MountID, Claim, MountPath, DataPath, SubPath string }
type originalStoppedProStorage struct{ Claim, MountPath string }

func originalStoppedCleanRoot(s string) bool {
	return path.IsAbs(s) && path.Clean(s) == s && s != "/" && !strings.ContainsAny(s, "\\\x00\r\n")
}
func originalStoppedRelative(s string) bool {
	return s == "" || !path.IsAbs(s) && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00\r\n:")
}
func originalStoppedLayoutValid(s OriginalStoppedProSelection) bool {
	if s.InstanceID <= 0 || len(s.PVCs) != 0 || len(s.Mounts) == 0 || len(s.Mounts) > 128 || s.ControllerName != "" && len(validation.IsDNS1123Subdomain(s.ControllerName)) != 0 {
		return false
	}
	workspace := false
	for i, m := range s.Mounts {
		if !namePattern.MatchString(m.MountID) || len(validation.IsDNS1123Subdomain(m.Claim)) != 0 || i > 0 && s.Mounts[i-1].MountID >= m.MountID || !originalStoppedCleanRoot(m.MountPath) || !originalStoppedCleanRoot(m.DataPath) || m.DataPath != m.MountPath && !strings.HasPrefix(m.DataPath, m.MountPath+"/") || !originalStoppedRelative(m.SubPath) {
			return false
		}
		workspace = workspace || m.MountID == "workspace"
	}
	return workspace
}
func (p *OriginalWriterMaintenance) prepareStoppedProLayout(ctx context.Context, selection OriginalStoppedProSelection) (*originalStoppedProObservation, error) {
	if p.check(ctx) != nil || p.checkInstances(ctx) != nil || !originalStoppedLayoutValid(selection) {
		return nil, ErrInstall
	}
	var source domain.SourceInstance
	found := false
	for _, i := range p.instances {
		if i.ID == selection.InstanceID {
			source = i
			found = true
		}
	}
	plan, err := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
	if !found || err != nil || plan.Mode != "pro" || source.Status != "stopped" || source.OS != "linux" {
		return nil, ErrInstall
	}
	var storage originalStoppedProStorage
	if p.operator.installer.db.QueryRowContext(ctx, `SELECT COALESCE(pvc_name,''),mount_path FROM instances WHERE id=?`, source.ID).Scan(&storage.Claim, &storage.MountPath) != nil || storage.Claim == "" || !originalStoppedCleanRoot(storage.MountPath) {
		return nil, ErrInstall
	}
	for _, mount := range selection.Mounts {
		if mount.MountID == "workspace" && (mount.Claim != storage.Claim || mount.MountPath != storage.MountPath || mount.DataPath != source.Workspace) {
			return nil, ErrInstall
		}
	}
	census, pods, deployments, claims, err := p.readKubernetesCensus(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	id, user := strconv.Itoa(source.ID), strconv.Itoa(source.UserID)
	for _, pod := range pods {
		if pod.Labels["instance-id"] == id || source.Pod != "" && pod.Name == source.Pod {
			if pod.Labels["instance-id"] != id || pod.Labels["user-id"] != user || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
				return nil, ErrInstall
			}
		}
	}
	baseline := domain.OriginalStoppedSourceBaseline{Version: domain.OriginalStoppedSourceBaselineVersion, SourceKey: "stopped/" + id, InstallationID: p.operator.installer.plan.Target.InstallationID, Namespace: census.Namespace, NamespaceUID: census.NamespaceUID, Source: source, SQLProjectionSHA256: originalObjectSHA(struct {
		Instances []domain.SourceInstance
		Storage   originalStoppedProStorage
		Layout    OriginalStoppedProSelection
	}{p.instances, storage, selection}), KubernetesCensusSHA256: originalObjectSHA(census), ControllerKind: "absent"}
	for _, dep := range deployments {
		selected := selection.ControllerName != "" && dep.Name == selection.ControllerName
		related := dep.Labels["instance-id"] == id
		if related && !selected {
			return nil, ErrInstall
		}
		if !selected {
			continue
		}
		if baseline.ControllerKind != "absent" || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 || dep.Status.ObservedGeneration < dep.Generation || originalStoppedTemplateLayout(dep.Spec.Template.Spec, selection.Mounts) != nil {
			return nil, ErrInstall
		}
		baseline.ControllerKind = "Deployment"
		baseline.ControllerName = dep.Name
		baseline.ControllerUID = string(dep.UID)
		baseline.ControllerGeneration = dep.Generation
		baseline.ControllerSpecSHA256 = originalObjectSHA(dep.Spec)
	}
	k := p.operator.installer.kube
	nodes, err := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, ErrInstall
	}
	for _, mount := range selection.Mounts {
		var claim *corev1.PersistentVolumeClaim
		for n := range claims {
			if claims[n].Name == mount.Claim {
				claim = &claims[n]
			}
		}
		if claim == nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" || claim.Status.Phase != corev1.ClaimBound {
			return nil, ErrInstall
		}
		pv, err := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != baseline.Namespace || pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
			return nil, ErrInstall
		}
		root := ""
		if pv.Spec.HostPath != nil {
			root = pv.Spec.HostPath.Path
		}
		if pv.Spec.Local != nil {
			if root != "" {
				return nil, ErrInstall
			}
			root = pv.Spec.Local.Path
		}
		if !originalStoppedCleanRoot(root) {
			return nil, ErrInstall
		}
		relative := path.Join(mount.SubPath, strings.TrimPrefix(strings.TrimPrefix(mount.DataPath, mount.MountPath), "/"))
		if relative == "." {
			relative = ""
		}
		sourcePath := path.Join(root, relative)
		if sourcePath != root && !strings.HasPrefix(sourcePath, root+"/") {
			return nil, ErrInstall
		}
		var chosen *corev1.Node
		for n := range nodes.Items {
			node := &nodes.Items[n]
			matches, err := originalPVMatchesNode(pv.Spec.NodeAffinity.Required, node)
			if err != nil {
				return nil, ErrInstall
			}
			if matches {
				if chosen != nil {
					return nil, ErrInstall
				}
				chosen = node
			}
		}
		if chosen == nil || chosen.UID == "" || chosen.DeletionTimestamp != nil || chosen.Status.NodeInfo.MachineID == "" || chosen.Status.NodeInfo.BootID == "" {
			return nil, ErrInstall
		}
		for _, old := range baseline.Volumes {
			if old.SourcePath == sourcePath || strings.HasPrefix(old.SourcePath, sourcePath+"/") || strings.HasPrefix(sourcePath, old.SourcePath+"/") {
				return nil, ErrInstall
			}
		}
		baseline.Volumes = append(baseline.Volumes, domain.OriginalStoppedSourceVolume{ID: "instance/" + id + "/mount/" + mount.MountID, SourcePath: sourcePath, Kind: "local_pv", PVCName: claim.Name, PVCUID: string(claim.UID), PVCSpecSHA256: originalObjectSHA(claim.Spec), PVName: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: originalObjectSHA(pv.Spec), ClaimRefUID: string(pv.Spec.ClaimRef.UID), NodeAffinitySHA256: originalObjectSHA(pv.Spec.NodeAffinity), Node: chosen.Name, NodeUID: string(chosen.UID), MachineID: chosen.Status.NodeInfo.MachineID, BootID: chosen.Status.NodeInfo.BootID})
	}
	sort.Slice(baseline.Volumes, func(i, j int) bool { return baseline.Volumes[i].ID < baseline.Volumes[j].ID })
	sha, err := domain.OriginalStoppedSourceBaselineSHA256(baseline)
	if err != nil {
		return nil, ErrInstall
	}
	after, _, _, _, err := p.readKubernetesCensus(ctx)
	var final originalStoppedProStorage
	if err != nil || !reflect.DeepEqual(census, after) || p.checkInstances(ctx) != nil || p.operator.installer.db.QueryRowContext(ctx, `SELECT COALESCE(pvc_name,''),mount_path FROM instances WHERE id=?`, source.ID).Scan(&final.Claim, &final.MountPath) != nil || final != storage {
		return nil, ErrInstall
	}
	return &originalStoppedProObservation{baseline: baseline, sha: sha, selection: selection, census: census, storage: &storage}, nil
}

// An extant CURRENT zero-replica controller must have every persistent mount
// represented by the owner-selected layout. We never use an old historical
// controller template to reconstruct or start an originally stopped instance.
func originalStoppedTemplateLayout(spec corev1.PodSpec, declared []OriginalStoppedProMountSelection) error {
	if len(spec.EphemeralContainers) != 0 {
		return ErrInstall
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		volumes[v.Name] = v
	}
	used := map[string]bool{}
	containers := append(append([]corev1.Container(nil), spec.InitContainers...), spec.Containers...)
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			volume, ok := volumes[mount.Name]
			if !ok || mount.SubPathExpr != "" || !originalStoppedRelative(mount.SubPath) {
				return ErrInstall
			}
			if volume.EmptyDir != nil || volume.Secret != nil || volume.ConfigMap != nil || volume.Projected != nil || volume.DownwardAPI != nil {
				for _, decl := range declared {
					if mount.MountPath == decl.DataPath || strings.HasPrefix(mount.MountPath, decl.DataPath+"/") {
						return ErrInstall
					}
				}
				continue
			}
			if volume.PersistentVolumeClaim == nil {
				return ErrInstall
			}
			matched := false
			for _, decl := range declared {
				declaredRoot := path.Clean(path.Join(decl.SubPath, strings.TrimPrefix(strings.TrimPrefix(decl.DataPath, decl.MountPath), "/")))
				mountRoot := path.Clean(mount.SubPath)
				if volume.PersistentVolumeClaim.ClaimName == decl.Claim && (declaredRoot == "." || declaredRoot == mountRoot || strings.HasPrefix(mountRoot, declaredRoot+"/")) {
					used[decl.MountID] = true
					matched = true
				}
			}
			if !matched {
				return ErrInstall
			}
		}
	}
	for _, decl := range declared {
		if !used[decl.MountID] {
			return ErrInstall
		}
	}
	return nil
}

func (s *originalStoppedProMaintenance) recheckCurrentStoppedController(ctx context.Context) error {
	b := s.original.baseline
	selection := s.original.selection
	k := s.owner.operator.installer.kube
	deps, err := k.AppsV1().Deployments(b.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ErrInstall
	}
	found := false
	id := strconv.Itoa(b.Source.ID)
	for _, dep := range deps.Items {
		related := dep.Labels["instance-id"] == id || selection.ControllerName != "" && dep.Name == selection.ControllerName
		if !related {
			continue
		}
		if b.ControllerKind != "Deployment" || found || dep.Name != b.ControllerName || string(dep.UID) != b.ControllerUID || dep.Generation != b.ControllerGeneration || originalObjectSHA(dep.Spec) != b.ControllerSpecSHA256 || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 || dep.DeletionTimestamp != nil {
			return ErrInstall
		}
		found = true
	}
	if (b.ControllerKind == "Deployment") != found {
		return ErrInstall
	}
	pods, err := k.CoreV1().Pods(b.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ErrInstall
	}
	for _, pod := range pods.Items {
		if pod.Labels["instance-id"] == id || b.Source.Pod != "" && pod.Name == b.Source.Pod {
			if pod.Labels["user-id"] != strconv.Itoa(b.Source.UserID) || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
				return ErrInstall
			}
		}
	}
	return nil
}
