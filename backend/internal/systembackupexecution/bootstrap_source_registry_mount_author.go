package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

// This selection contains owner-selected directories, never observed identities
// or authority. The original authenticated reader derives all identity fields.
type OriginalInstanceMountLayoutSelection struct {
	Version            string
	Layouts            []InstancePersistentMountLayout
	Longhorn           *OriginalLonghornStorageSelection `json:",omitempty"`
	AuthorLonghornHold bool                              `json:",omitempty"`
}

const OriginalInstanceMountLayoutSelectionVersion = "original-instance-mount-layout-selection.v1"

type OriginalInstanceMountMaterialsReceipt struct {
	Version, SelectionSHA256, LayoutSelectionSHA256, MountScopeSHA256 string
	MaterialsTemplate, SourceSelection                                install.BootstrapSourceFilePin
	LonghornHoldMaterials, Deployment                                 *install.BootstrapSourceFilePin `json:",omitempty"`
}

func readOriginalMountLayouts(file, digest string) (OriginalInstanceMountLayoutSelection, error) {
	raw, err := install.ReadPrivateFile(file, 262144)
	var selection OriginalInstanceMountLayoutSelection
	if err != nil || hash(raw) != digest || strictBootstrapSourceJSON(raw, &selection) != nil || selection.Version != OriginalInstanceMountLayoutSelectionVersion || selection.Layouts == nil || len(selection.Layouts) > 9998 {
		return OriginalInstanceMountLayoutSelection{}, install.ErrInstall
	}
	return selection, nil
}

func originalMountRunningInventory(instances []b.InstanceIdentity, scopes ...*domain.RuntimeTestScope) error {
	var testScope *domain.RuntimeTestScope
	if len(scopes) > 1 {
		return mountInputError("invalid_runtime_test_scope", 0, "")
	}
	if len(scopes) == 1 {
		testScope = scopes[0]
	}
	if testScope != nil && testScope.Validate(instances) != nil {
		return mountInputError("runtime_test_scope_drift", 0, "")
	}
	if len(instances) > 9998 {
		return mountInputError("invalid_original_inventory", 0, "")
	}
	seen := map[int]bool{}
	for _, instance := range instances {
		if testScope.IsDeferred(instance) {
			seen[instance.ID] = true
			continue
		}
		if instance.Status == "stopped" && !isCurrentStoppedPro(instance) {
			return mountInputError("stopped_original_snapshot_and_witness_required", instance.ID, "")
		}
		if instance.ID <= 0 || instance.UserID <= 0 || !instance.ValidRuntimeGeneration() || seen[instance.ID] || !isCurrentStoppedPro(instance) && !isRunningTenantPro(instance) && (instance.Mode != "lite" || instance.OS != "linux" || instance.Status != "running") {
			return mountInputError("unsupported_or_ambiguous_instance", instance.ID, "")
		}
		seen[instance.ID] = true
	}
	return nil
}

// Private comparison projection only: no restart reservation, stop capability,
// admitted writer or PreparedCoverage can be obtained from these values.
func originalMountNativeSpecs(instances []b.InstanceIdentity, native []bootstrapSourceNativeWriter, scopes ...*domain.RuntimeTestScope) ([]b.RuntimeWriterSpec, error) {
	var testScope *domain.RuntimeTestScope
	if len(scopes) > 1 {
		return nil, mountInputError("invalid_runtime_test_scope", 0, "")
	}
	if len(scopes) == 1 {
		testScope = scopes[0]
	}
	if err := originalMountRunningInventory(instances, testScope); err != nil {
		return nil, err
	}
	if len(instances) != len(native) {
		return nil, mountInputError("sql_runtime_binding_mismatch", 0, "")
	}
	byID := map[int]bootstrapSourceNativeWriter{}
	for _, n := range native {
		if n.InstanceID <= 0 || byID[n.InstanceID].InstanceID != 0 {
			return nil, mountInputError("duplicate_runtime_binding", n.InstanceID, "")
		}
		byID[n.InstanceID] = n
	}
	out := make([]b.RuntimeWriterSpec, 0, len(instances))
	for _, instance := range instances {
		n := byID[instance.ID]
		if testScope.IsDeferred(instance) {
			if n.RuntimeCaptureDeferred == nil || *n.RuntimeCaptureDeferred != instance || n.State != "runtime_capture_deferred_by_original_test_scope" {
				return nil, mountInputError("runtime_test_scope_native_marker_mismatch", instance.ID, "")
			}
			out = append(out, b.RuntimeWriterSpec{Source: instance, Kind: "runtime-test-deferred"})
			continue
		}
		if isCurrentStoppedPro(instance) {
			if n.CurrentStoppedPro == nil || n.CurrentStoppedPro.Source != instance || n.CurrentStoppedPro.validate() != nil {
				return nil, mountInputError("current_stopped_pro_material_required", instance.ID, "")
			}
			out = append(out, b.RuntimeWriterSpec{Source: instance, Kind: "stopped", Stopped: n.CurrentStoppedPro.OriginalState()})
			continue
		}
		if isRunningTenantPro(instance) {
			pin := n.RunningTenantPro
			if pin == nil || !pin.valid() || pin.Source != instance || n.UserID != instance.UserID || n.Generation != instance.Generation || n.State != "running" || n.Namespace != instance.Namespace || n.Pod != instance.Pod || n.PodUID != pin.PodUID || n.Deployment != pin.Deployment || n.DeploymentUID != pin.DeploymentUID || n.ReplicaSetUID != pin.ReplicaSetUID {
				return nil, mountInputError("tenant_pro_native_mapping_mismatch", instance.ID, "workspace")
			}
			out = append(out, b.RuntimeWriterSpec{Source: instance, Kind: "deployment", Name: pin.Deployment, UID: pin.DeploymentUID})
			continue
		}
		if n.RunningTenantPro != nil || n.UserID != instance.UserID || n.Generation != instance.Generation || n.State != "running" || n.PodUID == "" || n.Namespace == "" || n.Pod == "" || n.Deployment == "" || n.DeploymentUID == "" || n.ReplicaSetUID == "" || n.ServiceAccountUID == "" || n.NodeUID == "" || n.Endpoint == "" || n.AgentEpoch == "" || n.Gateway == "" || n.RuntimePodID <= 0 || n.PID <= 0 || n.Port <= 0 || n.Port > 65535 {
			return nil, mountInputError("sql_runtime_binding_mismatch", instance.ID, "")
		}
		out = append(out, b.RuntimeWriterSpec{Source: instance, Kind: "gateway", UID: n.PodUID, Name: n.Gateway, Endpoint: n.Endpoint, Port: n.Port, Runtime: b.RuntimeLocator{Version: "runtime-locator.v2", Namespace: n.Namespace, Pod: n.Pod, RegisteredPodUID: n.PodUID, Deployment: n.Deployment, AgentEpoch: n.AgentEpoch, RuntimePodID: n.RuntimePodID, GatewayPID: n.PID}})
	}
	return out, nil
}

func checkOriginalMountAuthoringAliases(materialsFile, nextSelectionFile, selectionFile, layoutsFile string, selection install.BootstrapSourceAuthoringSelection, cfg DeploymentConfig, materials productionCaptureMaterials) error {
	protected := []string{selectionFile, layoutsFile, selection.PartsFile, selection.SourceWritersFile, selection.RedisSourcesFile, selection.Deployment.File, selection.ExecutionProfile.File, selection.MaterialsTemplate.File, cfg.ForwardGrant.Path, cfg.RecoveryGrant.Path, materials.Redis.GrantFile, materials.Objects.GrantFile}
	if cfg.CaptureModules != nil {
		protected = append(protected, cfg.CaptureModules.Path)
	}
	if materials.Discovery != nil {
		protected = append(protected, materials.Discovery.GrantFile)
	}
	for _, connection := range selection.Connections {
		protected = append(protected, connection.Credential.File, connection.CA.File)
	}
	if selection.RuntimeAgent != nil {
		protected = append(protected, selection.RuntimeAgent.Credential.File, selection.RuntimeAgent.CA.File)
	}
	for _, file := range protected {
		if file == materialsFile || file == nextSelectionFile {
			return install.ErrInstall
		}
	}
	return nil
}

// ProduceOriginalInstanceMountMaterials runs BEFORE config/capture signing.
// Only the real Installer creates the bounded native-read capability. Neither
// supplied observations nor enabled Forward are accepted. Outputs are unsigned
// DATA for the unchanged final A producer, never stop/adoption authorization.
func ProduceOriginalInstanceMountMaterials(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA, layoutsFile, layoutsSHA, outputDirectory string) (OriginalInstanceMountMaterialsReceipt, error) {
	var zero OriginalInstanceMountMaterialsReceipt
	if ctx == nil || ctx.Err() != nil || installer == nil {
		return zero, install.ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, install.ErrInstall
	}
	layouts, err := readOriginalMountLayouts(layoutsFile, layoutsSHA)
	if err != nil {
		return zero, err
	}
	materialsFile := filepath.Join(outputDirectory, "mount-materials-template.json")
	nextSelectionFile := filepath.Join(outputDirectory, "mount-source-selection.json")
	longhornFile, coreFile := filepath.Join(outputDirectory, "longhorn-hold-materials.json"), filepath.Join(outputDirectory, "longhorn-deployment-core.json")
	if checkBootstrapSourceFactOutputs(materialsFile, nextSelectionFile) != nil {
		return zero, install.ErrInstall
	}
	if layouts.AuthorLonghornHold && (layouts.Longhorn == nil || checkBootstrapSourceFactOutputs(longhornFile, coreFile) != nil) {
		return zero, install.ErrInstall
	}
	authority, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionFile, selectionSHA)
	if err != nil {
		return zero, install.ErrInstall
	}
	defer authority.Close()
	x, err := newBootstrapSourceAuthoringReader(ctx, authority)
	if err != nil {
		return zero, install.ErrInstall
	}
	selection, _, err := authority.Selection(ctx)
	if err != nil {
		return zero, install.ErrInstall
	}
	if checkOriginalMountAuthoringAliases(materialsFile, nextSelectionFile, selectionFile, layoutsFile, selection, x.config, x.materials) != nil {
		return zero, install.ErrInstall
	}
	if layouts.AuthorLonghornHold && checkOriginalMountAuthoringAliases(longhornFile, coreFile, selectionFile, layoutsFile, selection, x.config, x.materials) != nil {
		return zero, install.ErrInstall
	}
	firstSQL, err := x.readSourceSQL()
	if err != nil {
		return zero, err
	}
	if err = originalMountRunningInventory(firstSQL.inventory.Instances, configuredRuntimeTestScope(x.config)); err != nil {
		return zero, err
	}
	clients, err := x.openMetadataClients()
	if err != nil {
		return zero, err
	}
	defer clients.Close()
	firstAPI, err := x.readWriterAPI(x.physical, clients, firstSQL.inventory.Instances)
	if err != nil {
		return zero, err
	}
	firstNative, err := x.readNativeWriters(firstSQL, firstAPI, clients)
	if err != nil {
		return zero, err
	}
	specs, err := originalMountNativeSpecs(firstSQL.inventory.Instances, firstNative, configuredRuntimeTestScope(x.config))
	if err != nil {
		return zero, err
	}
	scopeRaw, err := BuildOriginalInstanceMountScope(x.physical, clients.API, x.config, firstSQL.inventory.Instances, specs, layouts.Layouts)
	if err != nil {
		return zero, err
	}
	var scope productionPersistentMountScope
	if json.Unmarshal(scopeRaw, &scope) != nil || scope.validate() != nil {
		return zero, install.ErrInstall
	}
	longhorn, err := observeOriginalLonghornSources(x.physical, clients, x.config, firstSQL.inventory, &scope, layouts.Longhorn)
	if err != nil {
		return zero, err
	}
	var longhornMaterial q.LonghornExt4Materials
	recoveryURI := ""
	if layouts.AuthorLonghornHold {
		recoveryURI, err = originalLonghornRecoveryURI(x.config, x.materials, time.Now().UTC())
		if err != nil {
			return zero, err
		}
		longhornMaterial, err = observeOriginalLonghornHoldMaterials(x.physical, clients, x.config, &scope, longhorn, recoveryURI)
		if err != nil {
			return zero, err
		}
	}
	if authority.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	lastSQL, err := x.readSourceSQL()
	if err != nil || !sameBootstrapSourceSQL(firstSQL, lastSQL) {
		return zero, install.ErrInstall
	}
	lastAPI, err := x.readWriterAPI(x.physical, clients, lastSQL.inventory.Instances)
	if err != nil || !reflect.DeepEqual(firstAPI.objects, lastAPI.objects) {
		return zero, install.ErrInstall
	}
	lastNative, err := x.readNativeWriters(lastSQL, lastAPI, clients)
	if err != nil || !reflect.DeepEqual(firstNative, lastNative) {
		return zero, install.ErrInstall
	}
	lastScope, err := BuildOriginalInstanceMountScope(x.physical, clients.API, x.config, lastSQL.inventory.Instances, specs, layouts.Layouts)
	if err != nil || !bytes.Equal(scopeRaw, lastScope) {
		return zero, install.ErrInstall
	}
	currentLonghorn, err := observeOriginalLonghornSources(x.physical, clients, x.config, lastSQL.inventory, &scope, layouts.Longhorn)
	if err != nil || !reflect.DeepEqual(longhorn, currentLonghorn) {
		return zero, install.ErrInstall
	}
	if layouts.AuthorLonghornHold {
		uri, err := originalLonghornRecoveryURI(x.config, x.materials, time.Now().UTC())
		if err != nil || uri != recoveryURI {
			return zero, install.ErrInstall
		}
		current, err := observeOriginalLonghornHoldMaterials(x.physical, clients, x.config, &scope, currentLonghorn, uri)
		if err != nil || !reflect.DeepEqual(longhornMaterial, current) {
			return zero, install.ErrInstall
		}
	}
	if len(scope.RunningTenantPro) != 0 {
		scope.TenantProCensusPVs = make(map[string][]string)
		for _, mount := range scope.RunningTenantPro {
			scope.TenantProCensusPVs[mount.Source.Namespace] = nil
		}
		for _, observed := range firstAPI.objects {
			if _, selected := scope.TenantProCensusPVs[observed.Namespace]; selected && observed.Kind == "PersistentVolumeClaim" {
				scope.TenantProCensusPVs[observed.Namespace] = append(scope.TenantProCensusPVs[observed.Namespace], observed.Volume)
			}
		}
		for namespace, names := range scope.TenantProCensusPVs {
			scope.TenantProCensusPVs[namespace] = sortedUnique(names)
		}
		scopeRaw, err = json.Marshal(scope)
		if err != nil {
			return zero, install.ErrInstall
		}
	}
	x.materials.Discovery.PersistentMounts = &scope
	if layouts.Longhorn != nil {
		x.materials.Discovery.LonghornSources = longhorn
	}
	outputs := []struct {
		file string
		raw  []byte
	}{}
	var holdPin, corePin *install.BootstrapSourceFilePin
	if layouts.AuthorLonghornHold {
		raw, err := ce.Canonical(longhornMaterial)
		if err != nil || len(raw) > 1<<20 {
			return zero, install.ErrInstall
		}
		holdPin = &install.BootstrapSourceFilePin{File: longhornFile, SHA256: hash(raw)}
		cfg := x.config
		runtimeSources := *cfg.RuntimeSources
		cfg.RuntimeSources = &runtimeSources
		o := runtimeSources.SharedObserver
		runtimeSources.LonghornHold = &FormalLonghornHoldConfig{Observer: FormalSharedRuntimeObserverConfig{
			CAFile: o.CAFile, CASHA256: o.CASHA256, CertificateFile: o.CertificateFile, CertificateSHA256: o.CertificateSHA256,
			KeyFile: o.KeyFile, KeySHA256: o.KeySHA256, Endpoints: o.Endpoints}, Materials: []ProductionCaptureInput{{File: holdPin.File, SHA256: holdPin.SHA256}}}
		if cfg.Validate() != nil {
			return zero, install.ErrInstall
		}
		coreRaw, err := json.Marshal(cfg)
		if err != nil || len(coreRaw) > 262144 {
			return zero, install.ErrInstall
		}
		corePin = &install.BootstrapSourceFilePin{File: coreFile, SHA256: hash(coreRaw)}
		selection.Deployment = *corePin
		x.materials.DeploymentConfigSHA256 = corePin.SHA256
		outputs = append(outputs, struct {
			file string
			raw  []byte
		}{longhornFile, raw}, struct {
			file string
			raw  []byte
		}{coreFile, coreRaw})
	}
	materialsRaw, err := ce.Canonical(x.materials)
	if err != nil || len(materialsRaw) > 8<<20 {
		return zero, install.ErrInstall
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: materialsFile, SHA256: hash(materialsRaw)}
	selectionRaw, err := ce.Canonical(selection)
	if err != nil || len(selectionRaw) > 262144 {
		return zero, install.ErrInstall
	}
	outputs = append(outputs, []struct {
		file string
		raw  []byte
	}{{materialsFile, materialsRaw}, {nextSelectionFile, selectionRaw}}...)
	for _, output := range outputs {
		currentLayouts, err := readOriginalMountLayouts(layoutsFile, layoutsSHA)
		if err != nil || !reflect.DeepEqual(layouts, currentLayouts) || authority.RecheckAuthority(ctx) != nil {
			return zero, install.ErrInstall
		}
		if writeBootstrapSourceFactFile(output.file, output.raw) != nil {
			return zero, install.ErrInstall
		}
		actual, err := install.ReadSourceMaterialFile(output.file)
		if err != nil || !bytes.Equal(actual, output.raw) || authority.RecheckAuthority(ctx) != nil {
			return zero, install.ErrInstall
		}
	}
	if _, err := readOriginalMountLayouts(layoutsFile, layoutsSHA); err != nil || authority.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	if layouts.AuthorLonghornHold {
		// The successor changes the Core digest as well as the template. Have
		// the original installer/reader validate that new pairing before it
		// can be selected by the later signing/facts owners.
		next, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, nextSelectionFile, hash(selectionRaw))
		if err != nil {
			return zero, install.ErrInstall
		}
		defer next.Close()
		if _, err := newBootstrapSourceAuthoringReader(ctx, next); err != nil || next.RecheckAuthority(ctx) != nil || authority.RecheckAuthority(ctx) != nil {
			return zero, install.ErrInstall
		}
	}
	return OriginalInstanceMountMaterialsReceipt{Version: "original-instance-mount-materials-receipt.v1", SelectionSHA256: selectionSHA, LayoutSelectionSHA256: layoutsSHA, MountScopeSHA256: hash(scopeRaw), MaterialsTemplate: selection.MaterialsTemplate, SourceSelection: install.BootstrapSourceFilePin{File: nextSelectionFile, SHA256: hash(selectionRaw)}, LonghornHoldMaterials: holdPin, Deployment: corePin}, nil
}
