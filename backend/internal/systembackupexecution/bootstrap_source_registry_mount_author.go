package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

// This selection contains owner-selected directories, never observed identities
// or authority. The original authenticated reader derives all identity fields.
type OriginalInstanceMountLayoutSelection struct {
	Version string
	Layouts []InstancePersistentMountLayout
}

const OriginalInstanceMountLayoutSelectionVersion = "original-instance-mount-layout-selection.v1"

type OriginalInstanceMountMaterialsReceipt struct {
	Version, SelectionSHA256, LayoutSelectionSHA256, MountScopeSHA256 string
	MaterialsTemplate, SourceSelection                                install.BootstrapSourceFilePin
}

func readOriginalMountLayouts(file, digest string) ([]InstancePersistentMountLayout, error) {
	raw, err := install.ReadPrivateFile(file, 262144)
	var selection OriginalInstanceMountLayoutSelection
	if err != nil || hash(raw) != digest || strictBootstrapSourceJSON(raw, &selection) != nil || selection.Version != OriginalInstanceMountLayoutSelectionVersion || selection.Layouts == nil || len(selection.Layouts) > 9998 {
		return nil, install.ErrInstall
	}
	return selection.Layouts, nil
}

func originalMountRunningInventory(instances []b.InstanceIdentity) error {
	if len(instances) > 9998 {
		return mountInputError("invalid_original_inventory", 0, "")
	}
	seen := map[int]bool{}
	for _, instance := range instances {
		if instance.Status == "stopped" && !isCurrentStoppedPro(instance) {
			return mountInputError("stopped_original_snapshot_and_witness_required", instance.ID, "")
		}
		if instance.ID <= 0 || instance.UserID <= 0 || instance.Generation <= 0 || seen[instance.ID] || !isCurrentStoppedPro(instance) && (instance.Mode != "lite" || instance.OS != "linux" || instance.Status != "running") {
			return mountInputError("unsupported_or_ambiguous_instance", instance.ID, "")
		}
		seen[instance.ID] = true
	}
	return nil
}

// Private comparison projection only: no restart reservation, stop capability,
// admitted writer or PreparedCoverage can be obtained from these values.
func originalMountNativeSpecs(instances []b.InstanceIdentity, native []bootstrapSourceNativeWriter) ([]b.RuntimeWriterSpec, error) {
	if err := originalMountRunningInventory(instances); err != nil {
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
		if isCurrentStoppedPro(instance) {
			if n.CurrentStoppedPro == nil || n.CurrentStoppedPro.Source != instance || n.CurrentStoppedPro.validate() != nil {
				return nil, mountInputError("current_stopped_pro_material_required", instance.ID, "")
			}
			out = append(out, b.RuntimeWriterSpec{Source: instance, Kind: "stopped", Stopped: n.CurrentStoppedPro.OriginalState()})
			continue
		}
		if n.UserID != instance.UserID || n.Generation != instance.Generation || n.State != "running" || n.PodUID == "" || n.Namespace == "" || n.Pod == "" || n.Deployment == "" || n.DeploymentUID == "" || n.ReplicaSetUID == "" || n.ServiceAccountUID == "" || n.NodeUID == "" || n.Endpoint == "" || n.AgentEpoch == "" || n.Gateway == "" || n.RuntimePodID <= 0 || n.PID <= 0 || n.Port <= 0 || n.Port > 65535 {
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
	if checkBootstrapSourceFactOutputs(materialsFile, nextSelectionFile) != nil {
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
	firstSQL, err := x.readSourceSQL()
	if err != nil {
		return zero, err
	}
	if err = originalMountRunningInventory(firstSQL.inventory.Instances); err != nil {
		return zero, err
	}
	clients, err := x.openMetadataClients()
	if err != nil {
		return zero, err
	}
	defer clients.Close()
	firstAPI, err := x.readWriterAPI(x.physical, clients)
	if err != nil {
		return zero, err
	}
	firstNative, err := x.readNativeWriters(firstSQL, firstAPI, clients)
	if err != nil {
		return zero, err
	}
	specs, err := originalMountNativeSpecs(firstSQL.inventory.Instances, firstNative)
	if err != nil {
		return zero, err
	}
	scopeRaw, err := BuildOriginalInstanceMountScope(x.physical, clients.API, x.config, firstSQL.inventory.Instances, specs, layouts)
	if err != nil {
		return zero, err
	}
	if authority.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	lastSQL, err := x.readSourceSQL()
	if err != nil || !sameBootstrapSourceSQL(firstSQL, lastSQL) {
		return zero, install.ErrInstall
	}
	lastAPI, err := x.readWriterAPI(x.physical, clients)
	if err != nil || !reflect.DeepEqual(firstAPI.objects, lastAPI.objects) {
		return zero, install.ErrInstall
	}
	lastNative, err := x.readNativeWriters(lastSQL, lastAPI, clients)
	if err != nil || !reflect.DeepEqual(firstNative, lastNative) {
		return zero, install.ErrInstall
	}
	lastScope, err := BuildOriginalInstanceMountScope(x.physical, clients.API, x.config, lastSQL.inventory.Instances, specs, layouts)
	if err != nil || !bytes.Equal(scopeRaw, lastScope) {
		return zero, install.ErrInstall
	}
	var scope productionPersistentMountScope
	if json.Unmarshal(scopeRaw, &scope) != nil || scope.validate() != nil {
		return zero, install.ErrInstall
	}
	x.materials.Discovery.PersistentMounts = &scope
	materialsRaw, err := ce.Canonical(x.materials)
	if err != nil || len(materialsRaw) > 8<<20 {
		return zero, install.ErrInstall
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: materialsFile, SHA256: hash(materialsRaw)}
	selectionRaw, err := ce.Canonical(selection)
	if err != nil || len(selectionRaw) > 262144 {
		return zero, install.ErrInstall
	}
	for _, output := range []struct {
		file string
		raw  []byte
	}{{materialsFile, materialsRaw}, {nextSelectionFile, selectionRaw}} {
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
	return OriginalInstanceMountMaterialsReceipt{Version: "original-instance-mount-materials-receipt.v1", SelectionSHA256: selectionSHA, LayoutSelectionSHA256: layoutsSHA, MountScopeSHA256: hash(scopeRaw), MaterialsTemplate: selection.MaterialsTemplate, SourceSelection: install.BootstrapSourceFilePin{File: nextSelectionFile, SHA256: hash(selectionRaw)}}, nil
}
