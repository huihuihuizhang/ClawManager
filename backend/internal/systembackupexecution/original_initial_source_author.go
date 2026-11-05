package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"time"

	api "clawreef/internal/systembackupdeployment"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Ordinary operational data assembled by the original installer from real
// SQL/Kube/transport producers. No old source-selection/material file, observed
// source facts, final config hash, source scope hash, grant, or Passed flag is
// accepted in place of constructing the actual initial inputs below.
type OriginalInitialSourceAuthorInputs struct {
	Version                                                 string
	Deployment                                              DeploymentConfig
	Materials                                               json.RawMessage
	Profile                                                 api.ExecutionProfile
	Controller                                              install.BootstrapSourceController
	Connections                                             []install.BootstrapSourceConnection
	RuntimeAgent                                            *install.BootstrapSourceRuntimeAgentV2
	PartsVersion, SourceWritersVersion, RedisSourcesVersion string
	NotBefore, Until                                        time.Time
}
type OriginalInitialSourceAuthorReceipt struct {
	Version                                                          string
	Deployment, MaterialsTemplate, ExecutionProfile, SourceSelection install.BootstrapSourceFilePin
	NativeSourceQualified, GrantsIssued, BackupReady                 bool
}

func ProduceOriginalInitialSourceInputs(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, in OriginalInitialSourceAuthorInputs, directory string) (OriginalInitialSourceAuthorReceipt, error) {
	var zero OriginalInitialSourceAuthorReceipt
	if installer == nil || ctx == nil || ctx.Err() != nil || in.Version != "original-initial-source-author-inputs.v1" || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	cfg := in.Deployment
	corePath, templatePath, profilePath := filepath.Join(directory, "deployment-core.json"), filepath.Join(directory, "capture-materials-template.json"), filepath.Join(directory, "execution-profile.json")
	if cfg.ProfileFile != profilePath || cfg.CaptureModules == nil || cfg.CaptureModules.Path != filepath.Join(directory, "capture-materials.json") || cfg.PublicationSigners != nil || cfg.PublisherVerifier != nil || cfg.Validate() != nil {
		return zero, install.ErrInstall
	}
	if in.Profile.InstallationID != cfg.InstallationID {
		return zero, install.ErrInstall
	}
	if _, _, err := in.Profile.CanonicalIdentity(); err != nil {
		return zero, err
	}
	var material productionCaptureMaterials
	if _, err := jsoncanonicalizer.Transform(in.Materials); err != nil {
		return zero, install.ErrInstall
	}
	decoder := json.NewDecoder(bytes.NewReader(in.Materials))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&material) != nil || decoder.Decode(new(any)) != io.EOF || material.Discovery == nil || material.Version != productionCaptureMaterialsVersion ||
		material.DeploymentConfigSHA256 != "" || material.CaptureGrantSHA256 != "" || material.Redis.GrantSHA256 != "" || material.Objects.GrantSHA256 != "" || material.Discovery.GrantSHA256 != "" ||
		material.InstallationID != cfg.InstallationID || material.ControllerOwner != cfg.ControllerOwner {
		return zero, install.ErrInstall
	}
	// Every operation must be explicitly present in the operational template.
	// Its task identity, native observation and real permissions are still
	// constructed by the unchanged later owners, not this data author.
	for _, operation := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
		if _, ok := material.Operations[operation]; !ok {
			return zero, install.ErrInstall
		}
	}
	coreRaw, err := json.Marshal(cfg)
	if err != nil || len(coreRaw) > 262144 {
		return zero, install.ErrInstall
	}
	material.DeploymentConfigSHA256 = hash(coreRaw)
	materialRaw, err := json.Marshal(material)
	if err != nil || len(materialRaw) > 8<<20 {
		return zero, install.ErrInstall
	}
	profileRaw, _, err := in.Profile.CanonicalIdentity()
	if err != nil || len(profileRaw) > 16384 {
		return zero, install.ErrInstall
	}
	corePin := install.BootstrapSourceFilePin{File: corePath, SHA256: hash(coreRaw)}
	materialPin := install.BootstrapSourceFilePin{File: templatePath, SHA256: hash(materialRaw)}
	profilePin := install.BootstrapSourceFilePin{File: profilePath, SHA256: hash(profileRaw)}
	selection := install.BootstrapSourceAuthoringSelection{Version: install.BootstrapSourceAuthoringSelectionVersion, Deployment: corePin, MaterialsTemplate: materialPin,
		ExecutionProfile: profilePin, Controller: in.Controller, ApplicationScope: cfg.ApplicationScope, PartsVersion: in.PartsVersion, SourceWritersVersion: in.SourceWritersVersion,
		PartsFile: filepath.Join(directory, "parts-registry.json"), SourceWritersFile: filepath.Join(directory, "source-writers-registry.json"), Connections: in.Connections, RuntimeAgent: in.RuntimeAgent,
		NotBefore: in.NotBefore, Until: in.Until}
	if in.RedisSourcesVersion != "" {
		selection.RedisSourcesVersion = in.RedisSourcesVersion
		selection.RedisSourcesFile = filepath.Join(directory, "redis-sources-registry.json")
	}
	selectionRaw, err := json.Marshal(selection)
	if err == nil {
		selectionRaw, err = jsoncanonicalizer.Transform(selectionRaw)
	}
	if err != nil || len(selectionRaw) > 262144 {
		return zero, install.ErrInstall
	}
	selectionPath := filepath.Join(directory, "source-selection.json")
	// These are new DATA files only; a later authentication failure retains
	// them for exact inspection. The operator never retries an unknown send.
	for _, output := range []struct {
		path string
		raw  []byte
	}{{corePath, coreRaw}, {templatePath, materialRaw}, {profilePath, profileRaw}, {selectionPath, selectionRaw}} {
		if writeBootstrapSourceFactFile(output.path, output.raw) != nil {
			return zero, install.ErrInstall
		}
	}
	selectionPin := install.BootstrapSourceFilePin{File: selectionPath, SHA256: hash(selectionRaw)}
	authority, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionPin.File, selectionPin.SHA256)
	if err != nil {
		return zero, err
	}
	defer authority.Close()
	// The real original constructor checks the complete source tuple/core/
	// schema-census/template consistency, controller graph and original admin.
	// It issues no source grant and performs no substitution for native facts.
	if _, err = newBootstrapSourceAuthoringReader(ctx, authority); err != nil {
		return zero, err
	}
	if authority.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	return OriginalInitialSourceAuthorReceipt{Version: "original-initial-source-inputs-authored.v1", Deployment: corePin, MaterialsTemplate: materialPin, ExecutionProfile: profilePin, SourceSelection: selectionPin}, nil
}
