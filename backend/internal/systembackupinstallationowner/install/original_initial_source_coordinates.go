package install

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	c "clawreef/internal/systembackupcontroller"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalInitialInstanceStorage struct {
	InstanceID                              int
	Claim, MountPath, RuntimeImageReference string
	OSVersion, ImageRegistry, ImageTag      *string
	Additional                              []OriginalInitialAdditionalMount
}
type OriginalInitialAdditionalMount struct {
	ID                          int
	Claim, Namespace, MountPath string
}
type OriginalInitialSourceDependency struct {
	InstanceID               int
	Mode, Status, Dependency string
}
type OriginalInitialSharedStorageDependency struct {
	Namespace, Pod, PodUID, Reason string
}
type OriginalInitialMountCoordinates struct {
	Volume   core.Volume
	Mount    core.VolumeMount
	DataPath string
}
type OriginalInitialSourceLayout struct {
	Source                                                   domain.SourceInstance
	Storage                                                  OriginalInitialInstanceStorage
	CurrentPod, CurrentPodUID, CurrentNamespace, CurrentNode string
	Binding                                                  *originalSharedRuntimeBinding
	RuntimePod                                               *originalSharedRuntimePodRow
	Mounts                                                   []OriginalInitialMountCoordinates
	Dependency                                               string
}
type OriginalInitialSourceDataReceipt struct {
	Version                         string
	Coordinates, KubernetesSnapshot BootstrapSourceFilePin
	InstanceCount                   int
	WriterQualified, BackupReady    bool
}

func (p *OriginalWriterMaintenance) initialInstanceStorage(ctx context.Context) ([]OriginalInitialInstanceStorage, error) {
	out := []OriginalInitialInstanceStorage{}
	for _, source := range p.instances {
		s := OriginalInitialInstanceStorage{InstanceID: source.ID, Additional: []OriginalInitialAdditionalMount{}}
		if p.operator.installer.db.QueryRowContext(ctx, `SELECT COALESCE(pvc_name,''),COALESCE(mount_path,''),os_version,image_registry,image_tag FROM instances WHERE id=?`, source.ID).Scan(&s.Claim, &s.MountPath, &s.OSVersion, &s.ImageRegistry, &s.ImageTag) != nil {
			return nil, ErrInstall
		}
		imageRef, err := json.Marshal(struct {
			Version                  string
			Runtime                  scope.Runtime
			OSVersion, Registry, Tag *string
		}{
			"original-runtime-image-source.v1", scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS}, s.OSVersion, s.ImageRegistry, s.ImageTag})
		if err != nil {
			return nil, ErrInstall
		}
		s.RuntimeImageReference = string(imageRef)
		rows, err := p.operator.installer.db.QueryContext(ctx, `SELECT id,pvc_name,pvc_namespace,COALESCE(mount_path,'') FROM persistent_volumes WHERE instance_id=? ORDER BY id`, source.ID)
		if err != nil {
			return nil, ErrInstall
		}
		for rows.Next() {
			var extra OriginalInitialAdditionalMount
			if rows.Scan(&extra.ID, &extra.Claim, &extra.Namespace, &extra.MountPath) != nil || len(s.Additional) >= 128 {
				rows.Close()
				return nil, ErrInstall
			}
			s.Additional = append(s.Additional, extra)
		}
		if err = rows.Err(); rows.Close() != nil || err != nil {
			return nil, ErrInstall
		}
		out = append(out, s)
	}
	return out, nil
}

// Infer CURRENT source layout only from original SQL storage and a current
// controller, when present. No historical Pod, guessed per-instance claim name,
// copied witness, exclusion of stopped sources or absence proof is created.
func initialStoppedLayouts(instances []domain.SourceInstance, storage []OriginalInitialInstanceStorage, deployments []apps.Deployment, namespace string) ([]OriginalStoppedProSelection, error) {
	out := []OriginalStoppedProSelection{}
	for _, source := range instances {
		if source.Status != "stopped" {
			continue
		}
		plan, err := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
		if err != nil || plan.Mode != "pro" {
			continue
		} // Full native reader still rejects unsupported stopped modes.
		var record *OriginalInitialInstanceStorage
		for n := range storage {
			if storage[n].InstanceID == source.ID {
				record = &storage[n]
			}
		}
		if record == nil || record.Claim == "" || !originalStoppedCleanRoot(record.MountPath) || !originalStoppedCleanRoot(source.Workspace) {
			return nil, ErrInstall
		}
		selected := OriginalStoppedProSelection{InstanceID: source.ID, Mounts: []OriginalStoppedProMountSelection{}}
		var current *apps.Deployment
		for n := range deployments {
			dep := &deployments[n]
			if dep.Labels["instance-id"] == strconv.Itoa(source.ID) {
				if current != nil || dep.Labels["user-id"] != strconv.Itoa(source.UserID) {
					return nil, ErrInstall
				}
				current = dep
			}
		}
		if current == nil {
			selected.Mounts = append(selected.Mounts, OriginalStoppedProMountSelection{MountID: "workspace", Claim: record.Claim, MountPath: record.MountPath, DataPath: source.Workspace})
			for _, mount := range record.Additional {
				if mount.Namespace != namespace || mount.Claim == "" || !originalStoppedCleanRoot(mount.MountPath) {
					return nil, ErrInstall
				}
				if mount.Claim == record.Claim && mount.MountPath == record.MountPath {
					continue
				}
				selected.Mounts = append(selected.Mounts, OriginalStoppedProMountSelection{MountID: "volume-" + strconv.Itoa(mount.ID), Claim: mount.Claim, MountPath: mount.MountPath, DataPath: mount.MountPath})
			}
		} else {
			if current.Spec.Replicas == nil || *current.Spec.Replicas != 0 || current.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			selected.ControllerName = current.Name
			volumes := map[string]core.Volume{}
			for _, volume := range current.Spec.Template.Spec.Volumes {
				volumes[volume.Name] = volume
			}
			seen := map[string]bool{}
			containers := append(append([]core.Container(nil), current.Spec.Template.Spec.InitContainers...), current.Spec.Template.Spec.Containers...)
			workspace := false
			for _, container := range containers {
				for _, mount := range container.VolumeMounts {
					volume, ok := volumes[mount.Name]
					if !ok || mount.SubPathExpr != "" {
						return nil, ErrInstall
					}
					if volume.PersistentVolumeClaim == nil {
						if volume.EmptyDir != nil || volume.Secret != nil || volume.ConfigMap != nil || volume.Projected != nil || volume.DownwardAPI != nil {
							continue
						}
						return nil, ErrInstall
					}
					key := volume.PersistentVolumeClaim.ClaimName + "\x00" + mount.MountPath + "\x00" + mount.SubPath
					if seen[key] {
						continue
					}
					seen[key] = true
					id, dataPath := "volume-"+volume.Name, mount.MountPath
					if volume.PersistentVolumeClaim.ClaimName == record.Claim && mount.MountPath == record.MountPath {
						if workspace {
							return nil, ErrInstall
						}
						workspace = true
						id, dataPath = "workspace", source.Workspace
					}
					selected.Mounts = append(selected.Mounts, OriginalStoppedProMountSelection{MountID: id, Claim: volume.PersistentVolumeClaim.ClaimName, MountPath: mount.MountPath, DataPath: dataPath, SubPath: mount.SubPath})
				}
			}
			if !workspace {
				return nil, ErrInstall
			}
		}
		sort.Slice(selected.Mounts, func(i, j int) bool { return selected.Mounts[i].MountID < selected.Mounts[j].MountID })
		if !originalStoppedLayoutValid(selected) {
			return nil, ErrInstall
		}
		out = append(out, selected)
	}
	return out, nil
}

type initialSourceCoordinatesError struct {
	stage string
	cause error
}

func (e initialSourceCoordinatesError) Error() string { return e.stage }
func (e initialSourceCoordinatesError) Unwrap() error { return e.cause }

// This is the earliest authenticated DATA author: no writer source config,
// full DeploymentConfig, native observer certificate, grant or selection is
// needed to read the original complete SQL/Kube coordinates. The original
// prepare-selection/facts owners independently authenticate them later.
func (i *Installer) ProduceOriginalInitialSourceCoordinates(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string, runningOnly ...string) (_ OriginalInitialSourceDataReceipt, resultErr error) {
	var zero OriginalInitialSourceDataReceipt
	stage := "output_directory"
	defer func() {
		if resultErr != nil {
			resultErr = initialSourceCoordinatesError{stage: stage, cause: resultErr}
		}
	}()
	if i == nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	stage = "operator_enrollment"
	p, err := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, c.GatePolicy{LockTTL: c.DefaultMaintenanceLockTTL, AcquisitionTimeout: c.DefaultGateAcquisitionTime, MaxHold: c.DefaultQuiesceMaxHold})
	if err != nil {
		return zero, err
	}
	stage = "system_census"
	first, pods, deployments, claims, err := p.readKubernetesCensus(ctx)
	if err != nil {
		return zero, err
	}
	stage = "runtime_scope"
	var testScope *domain.RuntimeTestScope
	if len(runningOnly) > 1 {
		return zero, ErrInstall
	}
	if len(runningOnly) == 1 && runningOnly[0] != "" {
		target := i.plan.Target
		testScope, err = domain.NewRunningOnlyRuntimeTestScope(target.InstallationID, target.ServerUUID, target.Database, target.NamespaceUID, p.instances)
		if err != nil || p.checkSelectionRuntimeTestScope(testScope) != nil || !matchesRunningOnlyRoster(testScope, p.instances, runningOnly[0]) {
			return zero, ErrInstall
		}
	}
	stage = "instance_storage"
	storage, err := p.initialInstanceStorage(ctx)
	if err != nil {
		return zero, err
	}
	stage = "shared_runtime_sql"
	shared, err := p.readSharedRuntimeSQL(ctx)
	if err != nil {
		return zero, err
	}
	stage = "tenant_writer_chain"
	tenantObserved := map[int]OriginalInitialTenantProCoordinates{}
	var tenantSources []OriginalInitialTenantProCoordinates
	claimKeys := map[string]bool{}
	for _, claim := range claims {
		claimKeys[claim.Namespace+"/"+claim.Name] = true
	}
	for _, source := range p.instances {
		if originalInitialTenantNamespace(i.plan.Target.Namespace, source) == "" {
			continue
		}
		tenant, pod, deployment, tenantClaims, err := p.readInitialTenantPro(ctx, source)
		if err != nil {
			return zero, err
		}
		tenantObserved[source.ID] = tenant
		if pod == nil {
			continue
		}
		pods = append(pods, *pod)
		deployments = append(deployments, *deployment)
		tenantSources = append(tenantSources, tenant)
		for _, claim := range tenantClaims {
			key := claim.Namespace + "/" + claim.Name
			if !claimKeys[key] {
				claims = append(claims, claim)
				claimKeys[key] = true
			}
		}
	}
	recheckTenants := func() error {
		for _, source := range p.instances {
			if want, ok := tenantObserved[source.ID]; ok {
				actual, _, _, _, err := p.readInitialTenantPro(ctx, source)
				if err != nil || actual != want {
					return ErrInstall
				}
			}
		}
		return nil
	}
	// Keep the original per-instance controller chain above. Access authoring
	// also needs every PVC in each selected tenant, including unmounted claims.
	stage = "tenant_access"
	tenantAccess, err := p.initialTenantProAccess(ctx, testScope)
	if err != nil {
		return zero, err
	}
	stage = "application_scope"
	rows, err := i.db.QueryContext(ctx, `SELECT DISTINCT scope FROM system_backup_gate ORDER BY scope`)
	if err != nil {
		return zero, err
	}
	scopes := []string{}
	for rows.Next() {
		var scope string
		if rows.Scan(&scope) != nil || scope == "" || len(scope) > 128 || len(scopes) >= 128 {
			rows.Close()
			return zero, ErrInstall
		}
		scopes = append(scopes, scope)
	}
	if err = rows.Err(); rows.Close() != nil || err != nil {
		return zero, ErrInstall
	}
	applicationScope := ""
	if len(scopes) == 1 {
		applicationScope = scopes[0]
	}
	layouts := []OriginalStoppedProSelection{}
	dependencies := []OriginalInitialSourceDependency{}
	allLayouts := []OriginalInitialSourceLayout{}
	for _, source := range p.instances {
		layout := OriginalInitialSourceLayout{Source: source, Mounts: []OriginalInitialMountCoordinates{}}
		for _, record := range storage {
			if record.InstanceID == source.ID {
				layout.Storage = record
			}
		}
		podName, podNamespace := source.Pod, source.Namespace
		if source.Mode == "lite" {
			for n := range shared.Bindings {
				binding := &shared.Bindings[n]
				if binding.InstanceID != source.ID {
					continue
				}
				if layout.Binding != nil {
					layout.Dependency = "multiple_current_runtime_bindings_require_native_resolution"
					continue
				}
				copy := *binding
				layout.Binding = &copy
				for _, runtime := range shared.Pods {
					if runtime.ID == binding.RuntimePodID {
						copy := runtime
						layout.RuntimePod = &copy
						podName, podNamespace = runtime.Pod, runtime.Namespace
					}
				}
			}
		}
		for _, pod := range pods {
			if pod.Name != podName || pod.Namespace != podNamespace || podName == "" {
				continue
			}
			if layout.CurrentPodUID != "" {
				layout.Dependency = "duplicate_current_pod_coordinates"
				continue
			}
			layout.CurrentPod, layout.CurrentPodUID, layout.CurrentNamespace, layout.CurrentNode = pod.Name, string(pod.UID), pod.Namespace, pod.Spec.NodeName
			volumes := map[string]core.Volume{}
			for _, v := range pod.Spec.Volumes {
				volumes[v.Name] = v
			}
			seen := map[string]bool{}
			containers := append(append([]core.Container(nil), pod.Spec.InitContainers...), pod.Spec.Containers...)
			for _, container := range containers {
				for _, mount := range container.VolumeMounts {
					volume, ok := volumes[mount.Name]
					if !ok {
						layout.Dependency = "current_mount_volume_missing"
						continue
					}
					key := mount.Name + "\x00" + mount.MountPath + "\x00" + mount.SubPath + "\x00" + mount.SubPathExpr
					if seen[key] {
						continue
					}
					seen[key] = true
					dataPath := mount.MountPath
					if source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/") {
						dataPath = source.Workspace
					}
					layout.Mounts = append(layout.Mounts, OriginalInitialMountCoordinates{Volume: volume, Mount: mount, DataPath: dataPath})
					if mount.SubPathExpr != "" {
						layout.Dependency = "subpath_expression_requires_native_loaded_environment"
					}
				}
			}
		}
		if testScope.IsDeferred(source) {
			// The complete SQL, pod census and physical volume pins are retained.
			// Only runtime-specific layout and dependency selection is deferred.
			layout.Dependency = "explicit_running_only_runtime_test_scope_deferred"
		} else if source.Status == "stopped" {
			one, e := initialStoppedLayouts([]domain.SourceInstance{source}, storage, deployments, i.plan.Target.Namespace)
			if e != nil {
				layout.Dependency = "current_stopped_source_layout_requires_native_resolution"
			} else if len(one) != 1 {
				layout.Dependency = "stopped_shared_source_requires_native_nonrunning_owner"
			} else {
				layouts = append(layouts, one...)
			}
		}
		if source.Status == "running" && layout.CurrentPodUID == "" {
			layout.Dependency = "running_source_current_pod_or_binding_missing"
		} else if tenantObserved[source.ID].PodUID != "" && layout.Dependency == "" {
			layout.Dependency = "tenant_pro_native_writer_owner_required"
		}
		if !testScope.IsDeferred(source) && source.Status != "running" && source.Status != "stopped" {
			layout.Dependency = "original_state_requires_native_nonrunning_source_owner:" + source.Status
		}
		if layout.Dependency != "" {
			dependencies = append(dependencies, OriginalInitialSourceDependency{source.ID, source.Mode, source.Status, layout.Dependency})
		}
		allLayouts = append(allLayouts, layout)
	}
	stage = "node_pins"
	nodes := map[string]string{}
	for _, pod := range pods {
		if pod.Spec.NodeName == "" {
			continue
		}
		if _, ok := nodes[pod.Spec.NodeName]; ok {
			continue
		}
		node, e := i.kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if e != nil || node.UID == "" || node.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
		nodes[node.Name] = string(node.UID)
	}
	// The existing original DATA derivation authenticates the PVC/PV/node
	// relationship. It performs no gate/hold or observer mutation, exactly as
	// collectOriginalWriterSelection's preflight. CSI without a native fence is
	// still a concrete dependency; no guessed kubelet path is exported.
	stage = "shared_runtime_storage"
	physical := &PreparedOriginalWriterSet{owner: p}
	sharedRoots := map[string][]string{}
	var blockedShared []OriginalInitialSharedStorageDependency
	for _, runtime := range shared.Pods {
		for n := range pods {
			pod := &pods[n]
			if pod.Name != runtime.Pod || pod.Namespace != runtime.Namespace {
				continue
			}
			if runtime.UID != "" && runtime.UID != string(pod.UID) {
				return zero, ErrInstall
			}
			roots, e := physical.actualPodPersistentRoots(ctx, pod)
			if e != nil {
				var unsupported OriginalWriterSourceFailure
				if !errors.As(e, &unsupported) || unsupported.Dependency != "persistent_volume_native_fence_required" {
					return zero, e
				}
				blockedShared = append(blockedShared, OriginalInitialSharedStorageDependency{
					Namespace: pod.Namespace, Pod: pod.Name, PodUID: string(pod.UID), Reason: unsupported.Dependency,
				})
				continue
			}
			sharedRoots[pod.Spec.NodeName] = append(sharedRoots[pod.Spec.NodeName], roots...)
		}
	}
	sharedNodes := []c.RuntimeSharedNodeSources{}
	if len(blockedShared) == 0 {
		for node, roots := range sharedRoots {
			if node == "" || nodes[node] == "" {
				return zero, ErrInstall
			}
			sharedNodes = append(sharedNodes, c.RuntimeSharedNodeSources{Name: node, UID: nodes[node], Paths: originalNonOverlappingRoots(roots)})
		}
	}
	sort.Slice(sharedNodes, func(i, j int) bool { return sharedNodes[i].Name < sharedNodes[j].Name })
	sort.Slice(blockedShared, func(i, j int) bool {
		return blockedShared[i].Namespace+"/"+blockedShared[i].Pod < blockedShared[j].Namespace+"/"+blockedShared[j].Pod
	})
	stage = "volume_pins"
	volumes := []originalPhysicalVolumePin{}
	for _, claim := range claims {
		if claim.UID == "" || claim.Status.Phase != core.ClaimBound || claim.Spec.VolumeName == "" || claim.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
		pv, e := i.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID ||
			pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != claim.Namespace {
			return zero, ErrInstall
		}
		volumes = append(volumes, originalPhysicalVolumePin{Namespace: claim.Namespace, ClaimName: claim.Name, ClaimUID: string(claim.UID), ClaimSpecSHA256: originalObjectSHA(claim.Spec), PVName: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: originalObjectSHA(pv.Spec)})
	}
	physical.volumes = append(physical.volumes, volumes...)
	result := OriginalInitialSourceCoordinates{Version: "original-initial-source-coordinates.v1", InstallationID: i.plan.Target.InstallationID, Namespace: i.plan.Target.Namespace,
		NamespaceUID: i.plan.Target.NamespaceUID, ApplicationScope: applicationScope, ApplicationScopes: scopes, Instances: append([]domain.SourceInstance(nil), p.instances...),
		Volumes: volumes, Census: first, Storage: storage, StoppedProLayouts: layouts, NodeUIDs: nodes, SharedRuntime: shared, SharedNodes: sharedNodes,
		BlockedSharedStorage: blockedShared, TenantProSources: tenantSources, Layouts: allLayouts, Dependencies: dependencies, RuntimeTestScope: testScope,
		TenantProAccess: tenantAccess}
	stage = "encode_coordinates"
	coordinatesRaw, err := canonical(result)
	if err != nil || len(coordinatesRaw) > 8<<20 {
		return zero, ErrInstall
	}
	snapshotRaw, err := canonical(struct {
		Pods        []core.Pod
		Deployments []apps.Deployment
		Claims      []core.PersistentVolumeClaim
	}{pods, deployments, claims})
	if err != nil || len(snapshotRaw) > 8<<20 {
		return zero, ErrInstall
	}
	stage = "system_census_recheck"
	second, _, _, _, err := p.readKubernetesCensus(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return zero, ErrInstall
	}
	stage = "instance_storage_recheck"
	again, e := p.initialInstanceStorage(ctx)
	if e != nil || !reflect.DeepEqual(storage, again) {
		return zero, ErrInstall
	}
	stage = "shared_runtime_sql_recheck"
	sharedAgain, sharedErr := p.readSharedRuntimeSQL(ctx)
	if sharedErr != nil || !reflect.DeepEqual(shared, sharedAgain) {
		return zero, ErrInstall
	}
	stage = "tenant_access_recheck"
	tenantAccessAgain, accessErr := p.initialTenantProAccess(ctx, testScope)
	if accessErr != nil || !reflect.DeepEqual(tenantAccess, tenantAccessAgain) {
		return zero, ErrInstall
	}
	stage = "volume_pins_recheck"
	if physical.recheckVolumePins(ctx) != nil {
		return zero, ErrInstall
	}
	stage = "tenant_writer_chain_recheck"
	if recheckTenants() != nil {
		return zero, ErrInstall
	}
	stage = "operator_and_instances_recheck"
	if p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, ErrInstall
	}
	stage = "write_readback"
	files := map[string][]byte{"initial-source-coordinates.json": coordinatesRaw, "initial-source-kubernetes.private.json": snapshotRaw}
	if writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		actual, e := ReadSourceMaterialFile(filepath.Join(directory, name))
		if e != nil || string(actual) != string(expected) {
			clear(actual)
			return zero, ErrInstall
		}
		clear(actual)
	}
	stage = "final_recheck"
	final, _, _, _, err := p.readKubernetesCensus(ctx)
	tenantAccessFinal, accessErr := p.initialTenantProAccess(ctx, testScope)
	if err != nil || accessErr != nil || !reflect.DeepEqual(tenantAccess, tenantAccessFinal) || !reflect.DeepEqual(first, final) || physical.recheckVolumePins(ctx) != nil || recheckTenants() != nil || p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, ErrInstall
	}
	return OriginalInitialSourceDataReceipt{Version: "original-initial-source-data-authored.v1", Coordinates: BootstrapSourceFilePin{File: filepath.Join(directory, "initial-source-coordinates.json"), SHA256: hash(coordinatesRaw)},
		KubernetesSnapshot: BootstrapSourceFilePin{File: filepath.Join(directory, "initial-source-kubernetes.private.json"), SHA256: hash(snapshotRaw)}, InstanceCount: len(p.instances)}, nil
}
