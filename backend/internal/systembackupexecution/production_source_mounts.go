package systembackupexecution

import (
	"context"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// These are original source-owner mapping inputs in the signed discovery scope,
// never public task parameters or a caller-supplied completeness/stop boolean.
// A nil scope does not prove that a nonempty installation has no extra mounts.
type productionPersistentMountScope struct {
	RuntimeTestScope   *domain.RuntimeTestScope          `json:",omitempty"`
	CurrentStoppedPro  []CurrentStoppedProSourceMaterial `json:",omitempty"`
	RunningTenantPro   []runningTenantProMount           `json:",omitempty"`
	TenantProCensusPVs map[string][]string               `json:",omitempty"`
	Version            string
	Mounts             []productionPersistentMountBinding
}

const persistentMountScopeVersion = "original-instance-persistent-mounts.v1"

var persistentMountID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

type productionPersistentMountBinding struct {
	InstanceID, UserID, Generation                       int
	MountID, Container, Volume, MountPath, DataPath      string
	Namespace, Pod, PodUID, PodSpecSHA256, Node, NodeUID string
	VolumeSourceSHA256                                   string
}

func cleanMountRoot(value string) bool {
	return path.IsAbs(value) && value != "/" && path.Clean(value) == value && !strings.ContainsAny(value, "\\\x00\r\n:")
}

func (s *productionPersistentMountScope) validate() error {
	if s != nil && s.RuntimeTestScope != nil && !s.RuntimeTestScope.ShapeValid() {
		return d.ErrNotReady
	}
	if s == nil || s.Version != persistentMountScopeVersion || len(s.Mounts) > 9998 || len(s.CurrentStoppedPro) > 9998 || len(s.RunningTenantPro) > 9998 {
		return d.ErrNotReady
	}
	currentSeen := map[int]bool{}
	var currentRoots []CurrentStoppedProMount
	for _, m := range s.CurrentStoppedPro {
		if s.RuntimeTestScope.IsDeferred(m.Source) || currentSeen[m.Source.ID] || m.validate() != nil {
			return d.ErrNotReady
		}
		for _, mount := range m.Mounts {
			for _, old := range currentRoots {
				if old.NodeUID == mount.NodeUID && (old.HostPath == mount.HostPath || strings.HasPrefix(old.HostPath, mount.HostPath+"/") || strings.HasPrefix(mount.HostPath, old.HostPath+"/")) {
					return d.ErrNotReady
				}
			}
			currentRoots = append(currentRoots, mount)
		}
		currentSeen[m.Source.ID] = true
	}
	for _, m := range s.RunningTenantPro {
		if !m.valid() || s.RuntimeTestScope.IsDeferred(m.Source) || currentSeen[m.Source.ID] {
			return d.ErrNotReady
		}
		currentSeen[m.Source.ID] = true
	}
	seen := map[string]bool{}
	for _, m := range s.Mounts {
		if s.RuntimeTestScope != nil {
			for _, deferred := range s.RuntimeTestScope.Deferred {
				if m.InstanceID == deferred.ID {
					return d.ErrNotReady
				}
			}
		}
		if currentSeen[m.InstanceID] {
			return d.ErrNotReady
		}
		key := strconv.Itoa(m.InstanceID) + "/" + m.MountID
		if m.InstanceID <= 0 || m.UserID <= 0 || m.Generation <= 0 || m.MountID == "workspace" || !persistentMountID.MatchString(m.MountID) || len("instance_"+strconv.Itoa(m.InstanceID)+"_"+m.MountID) > 64 || seen[key] ||
			len(validation.IsDNS1123Label(m.Container)) != 0 || len(validation.IsDNS1123Label(m.Volume)) != 0 ||
			len(validation.IsDNS1123Label(m.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(m.Pod)) != 0 ||
			m.PodUID == "" || m.Node == "" || m.NodeUID == "" || !formalCandidateDigest(m.PodSpecSHA256) || !formalCandidateDigest(m.VolumeSourceSHA256) ||
			!cleanMountRoot(m.MountPath) || !cleanMountRoot(m.DataPath) || (m.DataPath != m.MountPath && !strings.HasPrefix(m.DataPath, m.MountPath+"/")) {
			return d.ErrNotReady
		}
		seen[key] = true
	}
	return nil
}

func persistentSource(volume corev1.Volume) bool {
	return volume.PersistentVolumeClaim != nil || volume.HostPath != nil || volume.NFS != nil
}

func transientSource(volume corev1.Volume) bool {
	return reflect.DeepEqual(volume.VolumeSource, corev1.VolumeSource{EmptyDir: volume.EmptyDir, ConfigMap: volume.ConfigMap, Secret: volume.Secret, Projected: volume.Projected, DownwardAPI: volume.DownwardAPI}) &&
		(volume.EmptyDir != nil || volume.ConfigMap != nil || volume.Secret != nil || volume.Projected != nil || volume.DownwardAPI != nil)
}

// Check ALL containers, not just mounts intersecting the primary workspace.
// Unknown storage, block devices, unresolved subPathExpr and unregistered
// side-mounts reject. EmptyDir/config/secret projections are not instance data.
// Original writer admission/drain is separate and is NOT established here.
func checkPersistentMountCoverage(source b.InstanceIdentity, pod *corev1.Pod, declarations []productionPersistentMountBinding) error {
	if pod == nil || len(pod.Spec.EphemeralContainers) != 0 {
		return d.ErrNotReady
	}
	volumes := map[string]corev1.Volume{}
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "" || volumes[volume.Name].Name != "" {
			return d.ErrNotReady
		}
		volumes[volume.Name] = volume
	}
	used := map[string]bool{}
	containers := append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...)
	for _, container := range containers {
		if len(container.VolumeDevices) != 0 {
			return d.ErrNotReady
		}
		seen := map[string]bool{}
		for _, mount := range container.VolumeMounts {
			volume, exists := volumes[mount.Name]
			if !exists || seen[mount.MountPath] {
				return d.ErrNotReady
			}
			seen[mount.MountPath] = true
			if transientSource(volume) {
				// A temporary/config mount overlay still masks the backing data.
				if mount.MountPath == source.Workspace || strings.HasPrefix(mount.MountPath, source.Workspace+"/") {
					return d.ErrNotReady
				}
				continue
			}
			if !persistentSource(volume) || mount.SubPathExpr != "" || !cleanMountRoot(mount.MountPath) {
				return d.ErrNotReady
			}
			if source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/") {
				continue // existing primary PVC/NFS identity/subpath checks still run
			}
			matched := 0
			for _, declaration := range declarations {
				if declaration.InstanceID == source.ID && declaration.Container == container.Name && declaration.Volume == mount.Name && declaration.MountPath == mount.MountPath {
					matched++
					used[declaration.MountID] = true
				}
			}
			if matched != 1 {
				return d.ErrNotReady
			}
		}
	}
	for _, declaration := range declarations {
		if declaration.InstanceID != source.ID || declaration.UserID != source.UserID || declaration.Generation != source.Generation || !used[declaration.MountID] {
			return d.ErrNotReady
		}
	}
	return nil
}

// Concrete production resolution; only GETs run under the caller's original
// source authority. No keys, Jobs, claims, new RBAC or physical stop operations.
func (x *originalSourceMetadataAuthority) additionalInstanceMounts(ctx context.Context, source b.SourceInventory, records []productionRuntimeRecord, primary []productionInstanceMount) ([]productionInstanceMount, map[string]kube.MountIdentity, error) {
	scope := x.service.captureMaterials.Discovery.PersistentMounts
	if len(source.Instances) == 0 && scope == nil {
		return nil, nil, nil
	}
	if scope.validate() != nil || x.Recheck(ctx) != nil {
		return nil, nil, d.ErrNotReady
	}
	byInstance := map[int]productionRuntimeRecord{}
	for _, record := range records {
		byInstance[record.Spec.Source.ID] = record
	}
	base := map[int]productionInstanceMount{}
	for _, mount := range primary {
		base[mount.InstanceID] = mount
	}
	configured, err := persistentMountsForInstances(scope, source.Instances)
	if err != nil {
		return nil, nil, err
	}
	out := []productionInstanceMount{}
	identities := map[string]kube.MountIdentity{}
	for _, instance := range source.Instances {
		if deferredRuntimeTestInstance(x.service.Config, instance) {
			continue
		}
		record := byInstance[instance.ID]
		if tenant := runningTenantProMountFor(scope, instance); tenant != nil {
			if !tenant.matchesWriter(record.Spec) || base[instance.ID].Source.PersistentVolumeClaim == nil || base[instance.ID].Source.PersistentVolumeClaim.ClaimName != tenant.Identity.Name {
				return nil, nil, d.ErrNotReady
			}
			continue
		}
		if isCurrentStoppedPro(instance) {
			material, err := currentStoppedProMaterialFor(scope, instance)
			if err != nil || record.Spec.Kind != "stopped" || record.Spec.Stopped != material.OriginalState() || !record.Stopped || recheckCurrentStoppedProMaterial(ctx, x.owner.Client, x.service.Config, *material) != nil {
				return nil, nil, d.ErrNotReady
			}
			for _, decl := range material.Mounts {
				if decl.Layout.MountID == "workspace" {
					continue
				}
				mount := currentStoppedProCaptureMount(*material, decl, base[instance.ID])
				out = append(out, mount)
				identities["instance_"+strconv.Itoa(instance.ID)+"_"+decl.Layout.MountID] = decl.Identity
			}
			continue
		}
		// D currently stores {} for original stopped sources. Neither SQL stopped
		// nor a missing Pod establishes its last complete persistent mount set.
		// Do not invent this missing original snapshot or start the instance.
		if record.Spec.Source != instance || !runtimeMountProtocolMatches(x.service.Config, record.Spec) || record.Spec.UID == "" {
			return nil, nil, d.ErrNotReady
		}
		pod, err := x.owner.Client.CoreV1().Pods(record.Spec.RuntimeNamespace()).Get(ctx, record.Spec.RuntimePod(), metav1.GetOptions{})
		if err != nil || string(pod.UID) != record.Spec.UID || pod.DeletionTimestamp != nil || pod.Namespace != x.service.Config.Namespace || x.Recheck(ctx) != nil || checkPersistentMountCoverage(instance, pod, configured[instance.ID]) != nil {
			return nil, nil, d.ErrNotReady
		}
		for _, mapping := range configured[instance.ID] {
			mount, identity, err := x.resolvePersistentMount(ctx, instance, pod, mapping, base[instance.ID])
			if err != nil {
				return nil, nil, err
			}
			out = append(out, mount)
			if identity != nil {
				identities["instance_"+strconv.Itoa(instance.ID)+"_"+mapping.MountID] = *identity
			}
		}
		// Detect spec/identity replacement over the complete bounded read set.
		after, err := x.owner.Client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil || after.UID != pod.UID || after.DeletionTimestamp != nil || !reflect.DeepEqual(after.Spec, pod.Spec) || x.Recheck(ctx) != nil {
			return nil, nil, d.ErrNotReady
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].InstanceID != out[j].InstanceID {
			return out[i].InstanceID < out[j].InstanceID
		}
		return out[i].MountID < out[j].MountID
	})
	if overlappingInstanceMounts(append(append([]productionInstanceMount{}, primary...), out...)) {
		return nil, nil, d.ErrNotReady
	}
	return out, identities, nil
}

func (x *originalSourceMetadataAuthority) resolvePersistentMount(ctx context.Context, instance b.InstanceIdentity, pod *corev1.Pod, mapping productionPersistentMountBinding, base productionInstanceMount) (productionInstanceMount, *kube.MountIdentity, error) {
	if x.Recheck(ctx) != nil {
		return productionInstanceMount{}, nil, d.ErrNotReady
	}
	mount, identity, err := resolvePersistentMount(ctx, x.owner.Client, x.service.Config, instance, pod, mapping, base)
	if err != nil || x.Recheck(ctx) != nil {
		return productionInstanceMount{}, nil, d.ErrNotReady
	}
	return mount, identity, nil
}

// Metadata resolver only: source grant checks belong to the concrete caller.
// Isolated tests use Kubernetes fake GETs here, not fabricated source authority.
func resolvePersistentMount(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, instance b.InstanceIdentity, pod *corev1.Pod, mapping productionPersistentMountBinding, base productionInstanceMount) (productionInstanceMount, *kube.MountIdentity, error) {
	var zero productionInstanceMount
	if pod == nil || cfg.Workspace.Node == "" || cfg.Security.NodeUIDs[cfg.Workspace.Node] == "" || base.InstanceID != instance.ID || mapping.InstanceID != instance.ID || mapping.UserID != instance.UserID || mapping.Generation != instance.Generation || pod.Namespace != cfg.Namespace || pod.Namespace != mapping.Namespace || pod.Name != mapping.Pod || string(pod.UID) != mapping.PodUID || kube.ContentHash(pod.Spec) != mapping.PodSpecSHA256 || pod.Spec.NodeName != mapping.Node || cfg.Security.NodeUIDs[mapping.Node] != mapping.NodeUID {
		return zero, nil, d.ErrNotReady
	}
	node, err := client.CoreV1().Nodes().Get(ctx, mapping.Node, metav1.GetOptions{})
	if err != nil || string(node.UID) != mapping.NodeUID || node.DeletionTimestamp != nil || node.Labels[corev1.LabelOSStable] != "linux" {
		return zero, nil, d.ErrNotReady
	}
	var selected *corev1.VolumeMount
	for _, container := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
		if container.Name != mapping.Container {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name == mapping.Volume && mount.MountPath == mapping.MountPath {
				copy := mount
				selected = &copy
			}
			if mount.MountPath != mapping.MountPath && !strings.HasPrefix(mapping.MountPath, mount.MountPath+"/") && (mount.MountPath == mapping.DataPath || strings.HasPrefix(mount.MountPath, mapping.DataPath+"/") || strings.HasPrefix(mapping.DataPath, mount.MountPath+"/")) {
				return zero, nil, d.ErrNotReady // a nested mount masks selected content
			}
		}
	}
	if selected == nil {
		return zero, nil, d.ErrNotReady
	}
	relative, err := kube.VolumeRelativePath(*selected, mapping.DataPath)
	if err != nil || relative == "." || relative == "" || strings.ContainsAny(relative, "\r\n") {
		return zero, nil, d.ErrNotReady // whole shared-volume ownership is unproved
	}
	var volume corev1.Volume
	for _, candidate := range pod.Spec.Volumes {
		if candidate.Name == mapping.Volume {
			volume = *candidate.DeepCopy()
		}
	}
	if kube.ContentHash(volume.VolumeSource) != mapping.VolumeSourceSHA256 || !reflect.DeepEqual(volume.VolumeSource, corev1.VolumeSource{PersistentVolumeClaim: volume.PersistentVolumeClaim, HostPath: volume.HostPath, NFS: volume.NFS}) {
		return zero, nil, d.ErrNotReady
	}
	kinds := 0
	if volume.PersistentVolumeClaim != nil {
		kinds++
	}
	if volume.HostPath != nil {
		kinds++
	}
	if volume.NFS != nil {
		kinds++
	}
	if kinds != 1 {
		return zero, nil, d.ErrNotReady
	}
	var identity *kube.MountIdentity
	switch {
	case volume.PersistentVolumeClaim != nil:
		if mapping.Node != cfg.Workspace.Node {
			return zero, nil, d.ErrNotReady
		}
		claim, err := client.CoreV1().PersistentVolumeClaims(mapping.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
		if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" || (claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) {
			return zero, nil, d.ErrNotReady
		}
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != claim.Namespace {
			return zero, nil, d.ErrNotReady
		}
		identity = &kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
		pinned := false
		for _, pin := range cfg.Security.Volumes {
			pinned = pinned || pin.Kind == identity.Kind && pin.Name == identity.Name && pin.UID == identity.UID && pin.PVName == identity.PVName && pin.PVUID == identity.PVUID && pin.SHA256 == identity.SHA256
		}
		if !pinned {
			return zero, nil, d.ErrNotReady
		}
		volume.PersistentVolumeClaim.ReadOnly = true
	case volume.HostPath != nil:
		if mapping.Node != cfg.Workspace.Node || !cleanMountRoot(volume.HostPath.Path) || volume.HostPath.Type == nil || *volume.HostPath.Type != corev1.HostPathDirectory {
			return zero, nil, d.ErrNotReady
		}
	case volume.NFS != nil:
		nfs := cfg.Workspace.NFS
		allowed := false
		if nfs != nil && len(nfs.OriginalPaths) > 0 && cfg.RuntimeSources != nil {
			primary, err := originalNFSInstanceSubPath(cfg.Workspace, cfg.RuntimeSources.WorkspaceRoot, instance)
			allowed = err == nil && (relative == primary || strings.HasPrefix(relative, primary+"/")) && nfs.recheckOriginalProvider(ctx, client) == nil
		} else {
			allowed = strings.HasPrefix(relative, cfg.Workspace.SubPath+"/")
		}
		if nfs == nil || volume.NFS.Server != nfs.Server || volume.NFS.Path != nfs.Export || !allowed {
			return zero, nil, d.ErrNotReady
		}
		volume.NFS.ReadOnly = true
	default:
		return zero, nil, d.ErrNotReady
	}

	volume.Name = "source"
	// Preserve the existing original staging placement. Local/PVC sources must
	// already be on that node; installation-owned NFS can be read there without
	// pretending the runtime Pod itself ran on the staging node.
	base.MountID, base.Source, base.SubPath, base.NodeName = mapping.MountID, volume, relative, cfg.Workspace.Node
	base.DataOnly, base.Skills, base.WorkBuddy = true, nil, nil
	return base, identity, nil
}

// Physical overlap is not independent ownership, including NFS export aliases
// and nested hostPaths. Refuse duplicate/overlapping captures across instances.
func overlappingInstanceMounts(mounts []productionInstanceMount) bool {
	type location struct{ key, root string }
	var previous []location
	for _, m := range mounts {
		var at location
		switch {
		case m.Source.PersistentVolumeClaim != nil:
			at = location{"pvc/" + m.Source.PersistentVolumeClaim.ClaimName, path.Clean(m.SubPath)}
		case m.Source.HostPath != nil:
			at = location{"host/" + m.NodeName, path.Join(m.Source.HostPath.Path, m.SubPath)}
		case m.Source.NFS != nil:
			at = location{"nfs/" + strings.ToLower(m.Source.NFS.Server), path.Join(m.Source.NFS.Path, m.SubPath)}
		default:
			return true
		}
		for _, old := range previous {
			if old.key == at.key && (old.root == at.root || old.root == "." || at.root == "." || strings.HasPrefix(old.root, at.root+"/") || strings.HasPrefix(at.root, old.root+"/")) {
				return true
			}
		}
		previous = append(previous, at)
	}
	return false
}
