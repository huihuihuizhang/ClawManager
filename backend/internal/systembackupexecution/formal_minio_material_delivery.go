package systembackupexecution

import (
	"bytes"
	sb "clawreef/internal/systembackup"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	adapter "clawreef/internal/systembackupkekadapter"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FormalMinIOMaterialDeliveryOptions struct {
	Version                      string
	Materials, HistoryDefinition install.BootstrapSourceFilePin
	OutputAccounts               []string
}
type FormalMinIOMaterialDeliveryReceipt struct {
	Version                                                                                                                           string
	Deployment, MaterialsTemplate, SourceSelection, WriterSelection, HistoryBindings, HistoryCensus, SecretManifests, DeploymentPatch install.BootstrapSourceFilePin
	ControllerMaterial                                                                                                                install.BootstrapSourceFilePin
}
type minioPrivateDeliveryEntry struct {
	Name, SHA256 string
	Size         int
	Chunks       []string
	Executable   bool
}
type minioPrivateDeliveryManifest struct {
	Version, Directory string
	Entries            []minioPrivateDeliveryEntry
}

// Concrete pre-signing ORIGINAL action. It preserves existing complete source
// scopes, creates both real reader formats, re-observes every original history
// prefix, and emits actual immutable Kube material plus a guarded same-image
// install-init patch on the already mounted durable staging claim. No new PVC,
// task/permission, fake native result, borrowed owner or synthetic scope exists.
func ProduceFormalMinIOMaterialDelivery(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA, writerFile, writerSHA, container, directory string, opt FormalMinIOMaterialDeliveryOptions) (FormalMinIOMaterialDeliveryReceipt, error) {
	var zero FormalMinIOMaterialDeliveryReceipt
	if ctx == nil || ctx.Err() != nil || installer == nil || opt.Version != "formal-minio-material-delivery-input.v1" || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	selected, e := readFormalObserverSelection(writerFile, writerSHA)
	if e != nil {
		return zero, install.ErrInstall
	}
	write, e := installer.PrepareOriginalWriterMaintenance(ctx, password, enrollment, selected.Policy)
	if e != nil {
		return zero, install.ErrInstall
	}
	authority, e := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionFile, selectionSHA)
	if e != nil {
		return zero, install.ErrInstall
	}
	defer authority.Close()
	if write.CheckOriginalMinIOSourceSetup(ctx, authority) != nil {
		return zero, install.ErrInstall
	}
	x, e := newBootstrapSourceAuthoringReader(ctx, authority)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection, target, e := authority.Selection(ctx)
	if e != nil || selected.ApplicationScope != selection.ApplicationScope || len(selected.MinIOReadKeepers) != 0 || len(x.config.MinIOReadKeepers) != 0 {
		return zero, install.ErrInstall
	}
	bindingDir := filepath.Join(directory, "reader-bindings")
	if os.Mkdir(bindingDir, 0700) != nil {
		return zero, install.ErrInstall
	}
	bindings, e := PrepareOriginalMinIOSourceReaderBindings(ctx, write, authority, opt.Materials.File, opt.Materials.SHA256, bindingDir)
	if e != nil {
		return zero, e
	}
	raw, e := pinnedDeploymentFile(opt.Materials.File, opt.Materials.SHA256, 262144)
	var original OriginalMinIOSourceReadMaterials
	if e != nil || strictBootstrapSourceJSON(raw, &original) != nil || original.Native.Namespace != target.Namespace || original.Native.NamespaceUID != target.NamespaceUID || original.Native.Operation != "" || original.Native.InventorySHA256 != "" || len(original.Native.OutputAccounts) != 0 {
		return zero, install.ErrInstall
	}
	if installer.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, opt.HistoryDefinition.File, opt.HistoryDefinition.SHA256) != nil {
		return zero, install.ErrInstall
	}
	historyOwner, e := readMinIOPermissionProductionInputs(opt.HistoryDefinition.File, opt.HistoryDefinition.SHA256)
	if e != nil {
		return zero, e
	}
	defer historyOwner.clear()
	if original.Native.Endpoint != historyOwner.grant.Provider.Endpoint || original.Native.CASHA256 != historyOwner.grant.Provider.CASHA256 {
		return zero, install.ErrInstall
	}
	scopes, e := originalMinIOCoverageScopes(historyOwner, bindings.HistoryCredential.SHA256)
	if e != nil || len(scopes) != 3 {
		return zero, install.ErrInstall
	}
	business := map[string]bool{}
	for _, bucket := range original.Native.BusinessBuckets {
		business[bucket] = true
	}
	for _, scope := range scopes {
		if !business[scope.Census.Scope.Bucket] {
			return zero, install.ErrInstall
		}
	}
	ca, e := pinnedDeploymentFile(original.Native.CAFile, original.Native.CASHA256, 65536)
	if e != nil {
		return zero, e
	}
	collection := OriginalMinIOCoverageCollection{Version: "original-minio-live-coverage-source-collection.v1", DefinitionSHA256: opt.HistoryDefinition.SHA256, State: "original_reader_live_EOF_not_fenced_not_adopted", Scopes: []OriginalMinIOCoverageSource{}}
	for _, scope := range scopes {
		if write.CheckOriginalMinIOSourceSetup(ctx, authority) != nil || installer.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, opt.HistoryDefinition.File, opt.HistoryDefinition.SHA256) != nil {
			return zero, install.ErrInstall
		}
		census, e := adapter.NewS3CoverageCensus(adapter.S3CoverageCensusConfig{Source: scope.Census.Source, Scope: scope.Census.Scope, CAPEM: ca, CredentialsFile: bindings.HistoryCredential.File})
		if e != nil {
			return zero, e
		}
		observed, e := census.Observe(ctx)
		if e != nil {
			return zero, e
		}
		scope.Census = observed.Facts()
		collection.Scopes = append(collection.Scopes, scope)
	}
	clients, e := x.openMetadataClients()
	if e != nil {
		return zero, e
	}
	defer clients.Close()
	controller := selection.Controller
	deployment, e := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != controller.DeploymentUID || deployment.DeletionTimestamp != nil || deployment.ResourceVersion == "" {
		return zero, install.ErrInstall
	}
	index := -1
	for n, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == container {
			index = n
		}
	}
	if index < 0 {
		return zero, install.ErrInstall
	}
	actualContainer := deployment.Spec.Template.Spec.Containers[index]
	if !strings.Contains(actualContainer.Image, "@sha256:") {
		return zero, install.ErrInstall
	}
	security := actualContainer.SecurityContext.DeepCopy()
	if security == nil {
		security = &core.SecurityContext{}
	}
	podSecurity := deployment.Spec.Template.Spec.SecurityContext
	uid := security.RunAsUser
	if uid == nil && podSecurity != nil {
		uid = podSecurity.RunAsUser
	}
	if uid == nil || *uid < 0 || *uid != 0 && (podSecurity == nil || podSecurity.FSGroup == nil || *podSecurity.FSGroup <= 0) {
		return zero, install.ErrInstall
	}
	security.RunAsUser = uid
	// The actual staging mount is persistent and distinct from source claims.
	// Native IAM custody must survive controller replacement; never use EmptyDir.
	stagingVolume := ""
	for _, mount := range actualContainer.VolumeMounts {
		if mount.MountPath == x.config.StagingDirectory && !mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == "" {
			for _, volume := range deployment.Spec.Template.Spec.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == x.config.StagingClaim && !volume.PersistentVolumeClaim.ReadOnly {
					stagingVolume = volume.Name
				}
			}
		}
	}
	if stagingVolume == "" || x.config.StagingClaim == x.config.Workspace.Claim || !path.IsAbs(x.config.StagingDirectory) {
		return zero, install.ErrInstall
	}
	claim, e := clients.API.CoreV1().PersistentVolumeClaims(controller.Namespace).Get(x.physical, x.config.StagingClaim, metav1.GetOptions{})
	if e != nil || claim.Status.Phase != core.ClaimBound || claim.Spec.VolumeName == "" || claim.DeletionTimestamp != nil {
		return zero, install.ErrInstall
	}
	pv, e := clients.API.CoreV1().PersistentVolumes().Get(x.physical, claim.Spec.VolumeName, metav1.GetOptions{})
	if e != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.DeletionTimestamp != nil {
		return zero, install.ErrInstall
	}
	name := "sbk-minio-" + opt.Materials.SHA256[:24]
	nativeDirectory := path.Join(x.config.StagingDirectory, name)
	// Freeze NEW identity-only records while the actual original installation
	// authorizations AND original v1 native credential descriptors are still live.
	// Old expired v1 material never upgrades itself in the runtime loader.
	if sb.ObserveOriginalMinIOBuiltinIdentityMaterial(ctx, clients.API, opt.Materials.File, opt.Materials.SHA256, func(current context.Context) error {
		if current != ctx {
			return install.ErrInstall
		}
		return write.CheckOriginalMinIOSourceSetup(ctx, authority)
	}) != nil {
		return zero, install.ErrInstall
	}
	staticOriginal := original
	staticOriginal.Version = "original-minio-source-read-identities.v2"
	staticOriginal.Until = time.Time{}
	staticDirectory := filepath.Join(directory, "builtin-identities")
	if os.Mkdir(staticDirectory, 0700) != nil {
		return zero, install.ErrInstall
	}
	identities := map[string][]byte{}
	defer func() {
		for _, raw := range identities {
			clear(raw)
		}
	}()
	for _, item := range []struct {
		name string
		pin  install.BootstrapSourceFilePin
		out  *install.BootstrapSourceFilePin
	}{{"root.json", original.RootCredential, &staticOriginal.RootCredential}, {"keeper.json", original.KeeperCredential, &staticOriginal.KeeperCredential}, {"reader.json", original.ReaderCredential, &staticOriginal.ReaderCredential}} {
		if write.CheckOriginalMinIOSourceSetup(ctx, authority) != nil || !time.Now().Before(original.Until) {
			return zero, install.ErrInstall
		}
		raw, e := pinnedDeploymentFile(item.pin.File, item.pin.SHA256, 16384)
		var old sb.MinIOGateCredential
		if e != nil || strictBootstrapSourceJSON(raw, &old) != nil || time.Now().Before(old.NotBefore) || !time.Now().Before(old.Until) || old.AccessKey == "" || old.Version == "" || old.Version == "latest" || old.Version == "current" || len(old.SecretKey) < 8 {
			clear(raw)
			clear(old.SecretKey)
			return zero, install.ErrInstall
		}
		clear(raw)
		identity := sb.MinIOBuiltinIdentity{Kind: "minio-builtin-static-identity.v1", AccessKey: old.AccessKey, SecretKey: old.SecretKey, Version: old.Version}
		frozen, e := ce.Canonical(identity)
		clear(old.SecretKey)
		if e != nil {
			return zero, e
		}
		file := filepath.Join(staticDirectory, item.name)
		if writeBootstrapSourceFactFile(file, frozen) != nil {
			clear(frozen)
			return zero, install.ErrInstall
		}
		*item.out = install.BootstrapSourceFilePin{File: file, SHA256: hash(frozen)}
		identities[item.name] = frozen
	}
	staticRaw, e := ce.Canonical(staticOriginal)
	if e != nil {
		return zero, e
	}
	staticFile := filepath.Join(staticDirectory, "source-read.identities.json")
	if writeBootstrapSourceFactFile(staticFile, staticRaw) != nil {
		return zero, install.ErrInstall
	}
	originalIdentityMaterial := install.BootstrapSourceFilePin{File: staticFile, SHA256: hash(staticRaw)}
	material := staticOriginal
	material.Native.CustodyDirectory = path.Join(nativeDirectory, "custody")
	material.Native.CAFile = path.Join(nativeDirectory, "ca.pem")
	material.Native.MCFile = path.Join(nativeDirectory, "mc")
	payloads := map[string][]byte{"ca.pem": ca}
	defer func() {
		for _, raw := range payloads {
			clear(raw)
		}
	}()
	for _, item := range []struct {
		name   string
		input  install.BootstrapSourceFilePin
		output *install.BootstrapSourceFilePin
	}{{"root.json", staticOriginal.RootCredential, &material.RootCredential}, {"keeper.json", staticOriginal.KeeperCredential, &material.KeeperCredential}, {"reader.json", staticOriginal.ReaderCredential, &material.ReaderCredential}, {"capture-reader.json", original.CaptureReaderCredential, &material.CaptureReaderCredential}, {"custody.key", original.CustodyKey, &material.CustodyKey}, {"keeper-policy.json", original.KeeperPolicy, &material.KeeperPolicy}, {"reader-policy.json", original.ReaderPolicy, &material.ReaderPolicy}, {"history-reader.json", bindings.HistoryCredential, nil}} {
		raw, e := pinnedDeploymentFile(item.input.File, item.input.SHA256, 262144)
		if e != nil {
			return zero, e
		}
		payloads[item.name] = raw
		if item.output != nil {
			*item.output = install.BootstrapSourceFilePin{File: path.Join(nativeDirectory, item.name), SHA256: item.input.SHA256}
		}
	}
	mc, e := pinnedDeploymentFile(original.Native.MCFile, original.Native.MCSHA256, 128<<20)
	if e != nil || len(mc) < 64 || !bytes.Equal(mc[:4], []byte{127, 'E', 'L', 'F'}) || mc[4] != 2 || mc[5] != 1 || mc[18] != 62 || mc[19] != 0 {
		return zero, install.ErrInstall
	}
	payloads["mc"] = mc
	materialRaw, e := ce.Canonical(material)
	if e != nil {
		return zero, e
	}
	payloads["source-read.materials.json"] = materialRaw
	controllerMaterial := install.BootstrapSourceFilePin{File: path.Join(nativeDirectory, "source-read.materials.json"), SHA256: hash(materialRaw)}
	manifest := minioPrivateDeliveryManifest{Version: "minio-private-material-delivery.v1", Directory: name, Entries: []minioPrivateDeliveryEntry{}}
	fileNames := make([]string, 0, len(payloads))
	for file := range payloads {
		fileNames = append(fileNames, file)
	}
	sort.Strings(fileNames)
	secrets := []core.Secret{}
	projected := []core.VolumeProjection{}
	immutable, mode := true, int32(0440)
	for _, file := range fileNames {
		body := payloads[file]
		entry := minioPrivateDeliveryEntry{Name: file, SHA256: hash(body), Size: len(body), Executable: file == "mc"}
		for offset := 0; offset < len(body); offset += 512 << 10 {
			end := offset + (512 << 10)
			if end > len(body) {
				end = len(body)
			}
			key := "part-" + strconv.Itoa(len(secrets))
			secretName := name + "-" + strconv.Itoa(len(secrets))
			entry.Chunks = append(entry.Chunks, key)
			secrets = append(secrets, core.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: controller.Namespace}, Immutable: &immutable, Type: core.SecretTypeOpaque, Data: map[string][]byte{key: body[offset:end]}})
			projected = append(projected, core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: secretName}, Items: []core.KeyToPath{{Key: key, Path: key}}}})
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	if len(secrets) > 192 {
		return zero, install.ErrInstall
	}
	manifestRaw, e := ce.Canonical(manifest)
	if e != nil {
		return zero, e
	}
	manifestName := name + "-manifest"
	secrets = append(secrets, core.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: manifestName, Namespace: controller.Namespace}, Immutable: &immutable, Type: core.SecretTypeOpaque, Data: map[string][]byte{"manifest.json": manifestRaw}})
	projected = append(projected, core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: manifestName}, Items: []core.KeyToPath{{Key: "manifest.json", Path: "manifest.json"}}}})
	volume := core.Volume{Name: "minio-keeper-install", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: &mode, Sources: projected}}}
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == volume.Name {
			return zero, install.ErrInstall
		}
	}
	init := core.Container{Name: "minio-keeper-install", Image: actualContainer.Image, ImagePullPolicy: actualContainer.ImagePullPolicy, Command: []string{"/usr/local/bin/system-backup-source-registries"}, Args: []string{"install-minio-files", "--manifest-sha256", hash(manifestRaw)}, SecurityContext: security, VolumeMounts: []core.VolumeMount{{Name: volume.Name, MountPath: "/input", ReadOnly: true}, {Name: stagingVolume, MountPath: "/output"}}}
	for _, c := range deployment.Spec.Template.Spec.InitContainers {
		if c.Name == init.Name {
			return zero, install.ErrInstall
		}
	}
	patch := []formalObserverPatchOperation{{"test", "/metadata/uid", string(deployment.UID)}, {"test", "/metadata/resourceVersion", deployment.ResourceVersion}, {"add", "/spec/template/spec/volumes/-", volume}}
	if len(deployment.Spec.Template.Spec.InitContainers) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers", []core.Container{init}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers/-", init})
	}
	// Retain the original source native material for A1. Only the formal runtime
	// selection uses the newly installed durable controller directory.
	sourceDeployment := ""
	for _, w := range selected.Deployments {
		if w.Role != "writer" {
			continue
		}
		for _, ref := range x.config.Writers {
			if ref.Name == w.Name && ref.UID == w.UID {
				pod, e := clients.API.CoreV1().Pods(original.Native.Namespace).Get(x.physical, original.Native.Pod, metav1.GetOptions{})
				if e != nil || string(pod.UID) != original.Native.PodUID {
					return zero, install.ErrInstall
				}
				parent := metav1.GetControllerOf(pod)
				if parent == nil || parent.Kind != "ReplicaSet" {
					return zero, install.ErrInstall
				}
				rs, e := clients.API.AppsV1().ReplicaSets(pod.Namespace).Get(x.physical, parent.Name, metav1.GetOptions{})
				if e != nil || rs.UID != parent.UID {
					return zero, install.ErrInstall
				}
				root := metav1.GetControllerOf(rs)
				if root != nil && root.Kind == "Deployment" && string(root.UID) == w.UID && root.Name == w.Name {
					if sourceDeployment != "" {
						return zero, install.ErrInstall
					}
					sourceDeployment = w.Name
				}
			}
		}
	}
	if sourceDeployment == "" {
		return zero, install.ErrInstall
	}
	selected.MinIOReadKeepers = []install.OriginalMinIOReadKeeperSelection{{Deployment: sourceDeployment, DeploymentUID: func() string {
		for _, w := range selected.Deployments {
			if w.Name == sourceDeployment {
				return w.UID
			}
		}
		return ""
	}(), Materials: originalIdentityMaterial, OutputAccounts: append([]string{}, opt.OutputAccounts...)}}
	x.config.MinIOReadKeepers = []FormalMinIOReadKeeperSelection{{Deployment: sourceDeployment, DeploymentUID: selected.MinIOReadKeepers[0].DeploymentUID, Materials: controllerMaterial, ReaderCredential: material.CaptureReaderCredential, ReaderAccount: bindings.Account, OutputAccounts: append([]string{}, opt.OutputAccounts...), Native: material.Native}}
	x.materials.Objects.CredentialFile = material.CaptureReaderCredential.File
	x.materials.Objects.CredentialSHA256 = material.CaptureReaderCredential.SHA256
	x.materials.Objects.Objects.CAFile = material.Native.CAFile
	selection.Connections[2].Account = bindings.Account
	selection.Connections[2].Credential = material.CaptureReaderCredential
	selection.Connections[2].CA = install.BootstrapSourceFilePin{File: material.Native.CAFile, SHA256: material.Native.CASHA256}
	if x.config.Validate() != nil {
		return zero, install.ErrInstall
	}
	configRaw, e := ce.Canonical(x.config)
	if e != nil {
		return zero, e
	}
	selection.Deployment = install.BootstrapSourceFilePin{File: filepath.Join(directory, "minio-deployment-config.json"), SHA256: hash(configRaw)}
	x.materials.DeploymentConfigSHA256 = selection.Deployment.SHA256
	materialsRaw, e := ce.Canonical(x.materials)
	if e != nil {
		return zero, e
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: filepath.Join(directory, "minio-materials-template.json"), SHA256: hash(materialsRaw)}
	historyBindings := struct {
		Original                    OriginalMinIOSourceReaderBindings
		ControllerHistoryCredential install.BootstrapSourceFilePin
	}{bindings, install.BootstrapSourceFilePin{File: path.Join(nativeDirectory, "history-reader.json"), SHA256: bindings.HistoryCredential.SHA256}}
	data := []any{x.config, x.materials, selection, selected, historyBindings, collection, struct {
		APIVersion, Kind string
		Items            []core.Secret
	}{"v1", "List", secrets}, patch}
	names := []string{"minio-deployment-config.json", "minio-materials-template.json", "minio-source-selection.json", "minio-writer-selection.json", "minio-history-reader-bindings.json", "minio-history-coverage.collection.json", "minio-private-secrets.json", "minio-controller-install.patch.json"}
	pins := make([]install.BootstrapSourceFilePin, len(names))
	for n, name := range names {
		if write.CheckOriginalMinIOSourceSetup(ctx, authority) != nil {
			return zero, install.ErrInstall
		}
		current, e := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
		if e != nil || !reflect.DeepEqual(current, deployment) {
			return zero, install.ErrInstall
		}
		actualClaim, e := clients.API.CoreV1().PersistentVolumeClaims(controller.Namespace).Get(x.physical, claim.Name, metav1.GetOptions{})
		if e != nil || !reflect.DeepEqual(actualClaim, claim) {
			return zero, install.ErrInstall
		}
		actualPV, e := clients.API.CoreV1().PersistentVolumes().Get(x.physical, pv.Name, metav1.GetOptions{})
		if e != nil || !reflect.DeepEqual(actualPV, pv) {
			return zero, install.ErrInstall
		}
		body, e := ce.Canonical(data[n])
		if e != nil {
			return zero, e
		}
		file := filepath.Join(directory, name)
		if writeBootstrapSourceFactFile(file, body) != nil {
			clear(body)
			return zero, install.ErrInstall
		}
		pins[n] = install.BootstrapSourceFilePin{File: file, SHA256: hash(body)}
		clear(body)
	}
	if write.CheckOriginalMinIOSourceSetup(ctx, authority) != nil {
		return zero, install.ErrInstall
	}
	return FormalMinIOMaterialDeliveryReceipt{Version: "formal-minio-material-delivery.v1", Deployment: pins[0], MaterialsTemplate: pins[1], SourceSelection: pins[2], WriterSelection: pins[3], HistoryBindings: pins[4], HistoryCensus: pins[5], SecretManifests: pins[6], DeploymentPatch: pins[7], ControllerMaterial: controllerMaterial}, nil
}

// Runs in the same immutable application image as a finite installation init
// actor. It accepts ONLY pinned immutable projected fragments, verifies every
// private file and ELF digest, then installs into the actual durable staging
// PVC. Replay verifies exact bytes and never overwrites another native journal.
func InstallFormalMinIOFiles(ctx context.Context, manifestSHA string) error {
	if ctx == nil || ctx.Err() != nil || len(manifestSHA) != 64 {
		return install.ErrInstall
	}
	read := func(name string, max int64) ([]byte, error) {
		if filepath.Base(name) != name {
			return nil, install.ErrInstall
		}
		f, e := os.Open("/input/" + name)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
			return nil, install.ErrInstall
		}
		raw, e := io.ReadAll(io.LimitReader(f, max+1))
		if e != nil || int64(len(raw)) != st.Size() {
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	raw, e := read("manifest.json", 262144)
	var manifest minioPrivateDeliveryManifest
	if e != nil || hash(raw) != manifestSHA || strictBootstrapSourceJSON(raw, &manifest) != nil || manifest.Version != "minio-private-material-delivery.v1" || !strings.HasPrefix(manifest.Directory, "sbk-minio-") || filepath.Base(manifest.Directory) != manifest.Directory || len(manifest.Entries) != 11 {
		return install.ErrInstall
	}
	directory := filepath.Join("/output", manifest.Directory)
	if e = os.Mkdir(directory, 0700); e != nil && !os.IsExist(e) {
		return install.ErrInstall
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return install.ErrInstall
	}
	defer root.Close()
	seen := map[string]bool{}
	chunks := map[string]bool{}
	for _, entry := range manifest.Entries {
		if filepath.Base(entry.Name) != entry.Name || seen[entry.Name] || entry.Size < 1 || entry.Size > 128<<20 || len(entry.Chunks) < 1 || len(entry.Chunks) > 256 || entry.Executable != (entry.Name == "mc") {
			return install.ErrInstall
		}
		seen[entry.Name] = true
		body := make([]byte, 0, entry.Size)
		for _, part := range entry.Chunks {
			if !strings.HasPrefix(part, "part-") || chunks[part] {
				clear(body)
				return install.ErrInstall
			}
			chunks[part] = true
			fragment, e := read(part, 512<<10)
			if e != nil {
				clear(body)
				return install.ErrInstall
			}
			body = append(body, fragment...)
			clear(fragment)
			if len(body) > entry.Size {
				clear(body)
				return install.ErrInstall
			}
		}
		if len(body) != entry.Size || hash(body) != entry.SHA256 {
			clear(body)
			return install.ErrInstall
		}
		mode := os.FileMode(0600)
		if entry.Executable {
			mode = 0500
			if len(body) < 64 || !bytes.Equal(body[:4], []byte{127, 'E', 'L', 'F'}) || body[4] != 2 || body[5] != 1 || body[18] != 62 || body[19] != 0 {
				clear(body)
				return install.ErrInstall
			}
		}
		file, e := root.OpenFile(entry.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if os.IsExist(e) {
			old, e := root.ReadFile(entry.Name)
			same := e == nil && bytes.Equal(old, body)
			clear(old)
			clear(body)
			actual, e2 := root.Lstat(entry.Name)
			if !same || e2 != nil || !actual.Mode().IsRegular() || actual.Mode().Perm() != mode {
				return install.ErrInstall
			}
			continue
		}
		if e != nil {
			clear(body)
			return install.ErrInstall
		}
		n, e := file.Write(body)
		clear(body)
		if e == nil && n != entry.Size {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = file.Sync()
		}
		closed := file.Close()
		if e != nil || closed != nil {
			return install.ErrInstall
		}
	}
	for _, name := range []string{"ca.pem", "root.json", "keeper.json", "reader.json", "capture-reader.json", "custody.key", "keeper-policy.json", "reader-policy.json", "history-reader.json", "mc", "source-read.materials.json"} {
		if !seen[name] {
			return install.ErrInstall
		}
	}
	custody := filepath.Join(directory, "custody")
	if e = os.Mkdir(custody, 0700); e != nil && !os.IsExist(e) {
		return install.ErrInstall
	}
	if sourceGateSyncDirectory(custody) != nil || sourceGateSyncDirectory(directory) != nil {
		return install.ErrInstall
	}
	return ctx.Err()
}
