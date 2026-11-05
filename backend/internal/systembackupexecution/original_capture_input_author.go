package systembackupexecution

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	a "clawreef/internal/systembackupkekadapter"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

// Actual producer pins and finite operational DATA only. This author grants
// nothing; the actual installer/source issuer and materializer authenticate all
// native observations/signatures/actors/windows before issuance or publication.
type OriginalCaptureInputAuthorInputs struct {
	Version                                                                                                                           string
	Core, Forward, RequestFiles, SourceSelection, ProviderResult, ProviderObserver, DatabaseCredential, SchemaRegistry, PartsRegistry install.BootstrapSourceFilePin
	DatabaseAccount, DatabaseService, DatabaseServiceUID                                                                              string
	DatabasePort                                                                                                                      int
	TeamsSource                                                                                                                       worker.FormalSourceMount
	TeamsFiles                                                                                                                        []OriginalCaptureMappingFile
}
type OriginalCaptureInputAuthorResult struct {
	Version, State                                                string
	SourceDefinition, ComponentsTemplate, DatabaseIssueDefinition install.BootstrapSourceFilePin
	ControlInput                                                  ce.CaptureInput
	GrantsIssued, NativeMappingsCreated, BackupReady              bool
}

func AuthorOriginalCaptureOperationalInputs(in OriginalCaptureInputAuthorInputs) (OriginalCaptureInputAuthorResult, error) {
	var zero OriginalCaptureInputAuthorResult
	if in.Version != "original-capture-operational-input-author.v1" {
		return zero, install.ErrInstall
	}
	read := func(p install.BootstrapSourceFilePin, max int64) ([]byte, error) {
		return pinnedDeploymentFile(p.File, p.SHA256, max)
	}
	core, e := LoadDeploymentConfig(in.Core.File, in.Core.SHA256)
	if e != nil || core.CaptureModules == nil {
		return zero, install.ErrInstall
	}
	pub, e := base64.StdEncoding.DecodeString(core.ForwardGrant.PublicKey)
	if e != nil {
		return zero, install.ErrInstall
	}
	forward, e := c.NewPinnedExecutionIdentity(in.Forward.File, in.Forward.SHA256, core.KeyDirectory, pub)
	if e != nil || in.Forward.File != core.ForwardGrant.Path {
		return zero, install.ErrInstall
	}
	grant := forward.DeploymentBinding()
	if grant.ConfigVersion != 1 || grant.DeploymentConfigSHA256 != in.Core.SHA256 || grant.InstallationID != core.InstallationID {
		return zero, install.ErrInstall
	}
	raw, e := read(in.RequestFiles, 262144)
	var request install.RequestFiles
	if e != nil || json.Unmarshal(raw, &request) != nil {
		return zero, install.ErrInstall
	}
	if request.ConfigFileSHA256 != grant.ConfigSHA256 {
		return zero, install.ErrInstall
	}
	raw, e = read(in.SourceSelection, 262144)
	var selection install.BootstrapSourceAuthoringSelection
	if e != nil || json.Unmarshal(raw, &selection) != nil || selection.Deployment != in.Core {
		return zero, install.ErrInstall
	}
	raw, e = read(selection.MaterialsTemplate, 8<<20)
	var material productionCaptureMaterials
	if e != nil || json.Unmarshal(raw, &material) != nil || material.Version != productionCaptureMaterialsVersion || material.Discovery == nil || material.Redis.GrantSHA256 != "" || material.Objects.GrantSHA256 != "" {
		return zero, install.ErrInstall
	}
	raw, e = read(in.ProviderResult, 262144)
	var provider install.OriginalRuntimeProviderIssueReceipt
	if e != nil || json.Unmarshal(raw, &provider) != nil || provider.Version != "original-runtime-provider-authorities-result.v1" || provider.State != "original_authority_and_capabilities_committed_readback_verified" {
		return zero, install.ErrInstall
	}
	raw, e = read(in.ProviderObserver, 262144)
	var observed a.VaultPermissionObserverConfig
	if e != nil || json.Unmarshal(raw, &observed) != nil || !reflect.DeepEqual(observed.Binding, provider.Binding) || hash(observed.CAPEM) != provider.Binding.Provider.CAPEMSHA256 || !k.ValidPermitDeliveryPin(provider.DeliveryPin) {
		return zero, install.ErrInstall
	}
	issuer := material.Discovery.Issuer
	if len(issuer) != ed25519.PublicKeySize || !strings.HasPrefix(material.Redis.GrantFile, filepath.Dir(core.CaptureModules.Path)+"/") || !strings.HasPrefix(material.Objects.GrantFile, filepath.Dir(core.CaptureModules.Path)+"/") {
		return zero, install.ErrInstall
	}
	notBefore, until := grant.NotBefore, grant.ExpiresAt
	if selection.NotBefore.After(notBefore) {
		notBefore = selection.NotBefore
	}
	if selection.Until.Before(until) {
		until = selection.Until
	}
	raw, e = read(install.BootstrapSourceFilePin{File: provider.FormalGrant.File, SHA256: provider.FormalGrant.SHA256}, 65536)
	var formalEnvelope struct{ Record, Signature []byte }
	var formalGrant a.ControllerVerifierGrant
	if e != nil || json.Unmarshal(raw, &formalEnvelope) != nil || json.Unmarshal(formalEnvelope.Record, &formalGrant) != nil {
		return zero, install.ErrInstall
	}
	if formalGrant.NotBefore.After(notBefore) {
		notBefore = formalGrant.NotBefore
	}
	if formalGrant.Until.Before(until) {
		until = formalGrant.Until
	}
	if !notBefore.Before(until) || time.Now().Before(notBefore) || !time.Now().Before(until) {
		return zero, install.ErrInstall
	}
	directory := filepath.Dir(core.CaptureModules.Path)
	schema, e := read(in.SchemaRegistry, 8<<20)
	if e != nil {
		return zero, e
	}
	policy := ce.RedactionPolicy{Version: "system-backup-control-redaction-registry.v1", RegistryVersion: "original-control-redaction.v1", Contract: "system-backup-plan.v12", Status: "frozen", Projections: ce.ProjectionColumns()}
	policyRaw, e := json.Marshal(policy)
	if e != nil {
		return zero, e
	}
	control := ce.CaptureInput{SchemaRegistryFile: in.SchemaRegistry.File, SchemaRegistrySHA256: in.SchemaRegistry.SHA256, RedactionRegistryFile: filepath.Join(directory, "control-redaction-registry.json"), RedactionRegistrySHA256: hash(policyRaw), CoverageWindowSeconds: 3600}
	if _, _, _, e = ce.ReadPolicies(schema, policyRaw, control); e != nil {
		return zero, e
	}
	material.InstallationID, material.ControllerOwner, material.DeploymentConfigSHA256, material.CaptureGrantSHA256 = core.InstallationID, core.ControllerOwner, in.Core.SHA256, in.Forward.SHA256
	material.ControlEvidence = &control
	material.ControlEvidenceSource = &worker.ControlEvidenceSourceMount{Endpoint: core.ControlURL, GrantFile: filepath.Join(directory, "control-source.grant.json"), ControllerGrantFile: filepath.Join(directory, "control-source.grant.json"), Issuer: issuer}
	if material.Operations == nil {
		return zero, install.ErrInstall
	}
	for _, name := range []string{ce.Operation, "capture-description"} {
		if _, exists := material.Operations[name]; exists {
			return zero, install.ErrInstall
		}
		material.Operations[name] = productionCaptureOperation{Request: worker.Request{Version: worker.Version, Operation: name, ArtifactName: name + ".encrypted", MaxArchiveBytes: 32 << 20, MaxCompressedBytes: 32 << 20}, Formal: worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, EnvelopeName: name + ".envelope", MaxFrames: 65536}}
	}
	cfg := k.Config{Endpoint: provider.Binding.Provider.Endpoint, InstallationID: core.InstallationID, KeyName: provider.Binding.Provider.KeyName, Key: provider.Binding.Key, CAPEM: observed.CAPEM, CASHA256: hash(observed.CAPEM), NotBefore: notBefore, NotAfter: until}
	if k.ValidateCaptureConfig(cfg) != nil {
		return zero, install.ErrInstall
	}
	databaseSource := worker.FormalSourceMount{GrantFile: filepath.Join(directory, "database-source.grant.json"), Issuer: issuer, CredentialFile: in.DatabaseCredential.File, CredentialSHA256: in.DatabaseCredential.SHA256}
	if _, e = read(in.DatabaseCredential, 16384); e != nil {
		return zero, e
	}
	teams := in.TeamsSource
	if teams.GrantFile == "" {
		// DATA from the real complete native original Parts registry. The
		// distinct actual Teams issuer MUST independently reobserve this scope.
		partsRaw, partsErr := read(in.PartsRegistry, 8<<20)
		var parts bootstrapSourcePartsRegistry
		if partsErr != nil || json.Unmarshal(partsRaw, &parts) != nil || parts.SchemaVersion != bootstrapSourcePartsVersion || parts.Installation != core.InstallationID || parts.Source.ServerUUID != core.SourceServerUUID || parts.Source.Database != core.SourceDatabase || parts.Source.Teams == nil {
			return zero, install.ErrInstall
		}
		teams = material.Objects
		teams.GrantFile = filepath.Join(directory, "teams-source.grant.json")
		teams.GrantSHA256 = ""
		teams.ObjectPrefixes = nil
		prefixes := map[string]worker.ObjectSourcePrefix{}
		for _, object := range parts.Source.Teams.Objects {
			if object.Validate() != nil {
				return zero, install.ErrInstall
			}
			prefix := path.Dir(object.Key)
			if prefix == "." || prefix == "/" {
				return zero, install.ErrInstall
			}
			prefix += "/"
			prefixes[object.Bucket+"\x00"+prefix] = worker.ObjectSourcePrefix{Bucket: object.Bucket, Prefix: prefix}
		}
		if len(prefixes) == 0 {
			// Empty actual original Team object inventory: retain the existing
			// native finite source boundary, never synthesize a bucket wildcard.
			teams.ObjectPrefixes = append([]worker.ObjectSourcePrefix(nil), material.Objects.ObjectPrefixes...)
		} else {
			keys := make([]string, 0, len(prefixes))
			for key := range prefixes {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				teams.ObjectPrefixes = append(teams.ObjectPrefixes, prefixes[key])
			}
		}
	}
	if teams.GrantFile == "" || !originalCaptureInputKeyEqual(teams.Issuer, issuer) || teams.Objects == nil {
		return zero, install.ErrInstall
	}
	kms := map[string]k.Config{}
	files := map[string]OriginalCaptureMappingFile{}
	add := func(workerPath, file, sha string) bool {
		if old, ok := files[workerPath]; ok {
			return old.File == file && old.SHA256 == sha
		}
		files[workerPath] = OriginalCaptureMappingFile{WorkerPath: workerPath, File: file, SHA256: sha}
		return true
	}
	for _, file := range in.TeamsFiles {
		if !add(file.WorkerPath, file.File, file.SHA256) {
			return zero, install.ErrInstall
		}
	}
	sourceFiles := func(source worker.FormalSourceMount, pending bool) bool {
		if pending {
			if !add(source.GrantFile, "", "") {
				return false
			}
		} else if !add(source.GrantFile, source.GrantFile, source.GrantSHA256) {
			return false
		}
		if !add(source.CredentialFile, source.CredentialFile, source.CredentialSHA256) {
			return false
		}
		for _, tls := range []*worker.SourceTLSMapping{source.Redis, source.Objects} {
			if tls != nil && !add(tls.CAFile, tls.CAFile, tls.CASHA256) {
				return false
			}
		}
		return true
	}
	if !sourceFiles(material.Redis, true) || !sourceFiles(material.Objects, true) || !sourceFiles(databaseSource, true) || !sourceFiles(teams, teams.GrantSHA256 == "") || !add(material.ControlEvidenceSource.GrantFile, "", "") {
		return zero, install.ErrInstall
	}
	api := material.Discovery.SourceAPI
	if !add(api.CAFile, api.CAFile, api.CASHA256) || !add(api.TokenFile, api.TokenFile, material.Discovery.SourceAPITokenSHA256) {
		return zero, install.ErrInstall
	}
	originRaw, e := json.Marshal(struct {
		Core, Forward, Provider install.BootstrapSourceFilePin
	}{in.Core, in.Forward, in.ProviderResult})
	if e != nil {
		return zero, e
	}
	originFile := filepath.Join(directory, "original-capture-input-origins.json")
	if !add(originFile, originFile, hash(originRaw)) {
		return zero, install.ErrInstall
	}
	operationFiles := func(name string) []string {
		required := []string{originFile}
		var source *worker.FormalSourceMount
		switch name {
		case "capture-database":
			source = &databaseSource
		case "capture-source-redis":
			source = &material.Redis
		case "capture-skill-objects":
			source = &material.Objects
		case "capture-team-objects":
			source = &teams
		case "capture-deployment-resources", "capture-secret-bundle":
			required = append(required, api.CAFile, api.TokenFile)
		case ce.Operation:
			required = append(required, material.ControlEvidenceSource.GrantFile)
		}
		if source != nil {
			required = append(required, source.GrantFile, source.CredentialFile)
			for _, tls := range []*worker.SourceTLSMapping{source.Redis, source.Objects} {
				if tls != nil {
					required = append(required, tls.CAFile)
				}
			}
		}
		sort.Strings(required)
		return required
	}
	for name, operation := range material.Operations {
		if len(operation.Workload.Command) != 0 {
			return zero, install.ErrInstall
		}
		operation.Formal.PermitDelivery = &provider.DeliveryPin
		if operation.Request.MaxCompressedBytes < 1 {
			return zero, install.ErrInstall
		}
		operation.Formal.MaxFrames = uint64((operation.Request.MaxCompressedBytes+w.ChunkSize-1)/w.ChunkSize + 1)
		if operation.Formal.MaxFrames < 2 || operation.Formal.MaxFrames > w.MaxStreamFrames {
			return zero, install.ErrInstall
		}
		operation.Provider = k.Access{Operation: k.Generate, Endpoint: cfg.Endpoint, KeyName: cfg.KeyName, Request: w.KeyRequest{Key: cfg.Key}}
		operation.Workload.Identity.Namespace = core.Namespace
		operation.Workload.Image = core.WorkerImage
		operation.Workload.ServiceAccount = core.Security.ServiceAccountName
		operation.Workload.StagingClaim = core.StagingClaim
		operation.Workload.DeadlineSeconds = 300
		operation.Workload.WorkerControl = &kube.WorkerControl{URL: core.ControlURL, BoundPodIdentity: true}
		if name != "capture-workspace" {
			operation.Workload.Source = corev1.Volume{}
			operation.Workload.SourceSubPath = ""
		}
		prefix := "sbk-formal-" + hash([]byte(in.Core.SHA256 + name))[:20]
		mount := kube.FormalInputMount{Volume: "formal-inputs", Kind: "Secret", Name: prefix + "-inputs", Directory: "/run/backup/materials/inputs", DataPaths: map[string]string{}}
		for n, file := range operationFiles(name) {
			key := "item-" + originalCaptureInputIndex(n)
			mount.Items = append(mount.Items, corev1.KeyToPath{Key: key, Path: key})
			mount.DataPaths[key] = file
		}
		operation.Workload.FormalMaterials = &kube.FormalJobMaterials{ProjectionProtocol: kube.OriginalFormalDataPathsV1, ConfigMap: prefix + "-mapping", Inputs: []kube.FormalInputMount{mount}}
		if kube.ValidateFormalJobMaterials(operation.Workload.FormalMaterials) != nil {
			return zero, install.ErrInstall
		}
		material.Operations[name] = operation
		kms[name] = cfg
	}
	materialRaw, e := json.Marshal(material)
	if e != nil {
		return zero, e
	}
	definition := ProductionMaterialDefinition{Version: productionMaterialDefinitionVersion, CoreFile: in.Core.File, CoreSHA256: in.Core.SHA256, ConfigFile: request.ConfigFile, ConfigSHA256: request.ConfigFileSHA256, ForwardGrantSHA256: in.Forward.SHA256, NotBefore: notBefore, Until: until, Materials: materialRaw}
	definitionRaw, e := json.Marshal(definition)
	if e != nil {
		return zero, e
	}
	definitionFile := filepath.Join(directory, "capture-source-definition.json")
	template := OriginalCaptureMappingDefinition{Version: OriginalCaptureInstallationTemplateVersion, OriginalDefinitionSHA256: hash(definitionRaw), KMS: kms, DatabaseSource: databaseSource, TeamsSource: &teams}
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		template.Files = append(template.Files, files[key])
	}
	templateRaw, e := json.Marshal(template)
	if e != nil {
		return zero, e
	}
	database := install.DatabaseSourceIssueDefinition{Version: install.DatabaseSourceIssueVersion, OriginalDefinitionSHA256: hash(definitionRaw), Account: in.DatabaseAccount, Service: in.DatabaseService, ServiceUID: in.DatabaseServiceUID, Port: in.DatabasePort, Source: databaseSource}
	databaseRaw, e := json.Marshal(database)
	if e != nil {
		return zero, e
	}
	outputs := map[string][]byte{control.RedactionRegistryFile: policyRaw, originFile: originRaw, definitionFile: definitionRaw, filepath.Join(directory, "capture-components-template.json"): templateRaw, filepath.Join(directory, "database-source-inputs.json"): databaseRaw}
	paths := make([]string, 0, len(outputs))
	for file := range outputs {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	for _, file := range paths {
		if e = writeOriginalMaterialFile(file, outputs[file]); e != nil {
			return zero, e
		}
	}

	pin := func(file string) install.BootstrapSourceFilePin {
		return install.BootstrapSourceFilePin{File: file, SHA256: hash(outputs[file])}
	}
	return OriginalCaptureInputAuthorResult{Version: "original-capture-operational-inputs-authored.v1", State: "original_data_authored_native_grants_and_mapping_not_yet_issued", SourceDefinition: pin(definitionFile), ComponentsTemplate: pin(filepath.Join(directory, "capture-components-template.json")), DatabaseIssueDefinition: pin(filepath.Join(directory, "database-source-inputs.json")), ControlInput: control}, nil
}

func originalCaptureInputKeyEqual(a, b []byte) bool { return reflect.DeepEqual(a, b) }
func originalCaptureInputIndex(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('a' + n - 10))
}
