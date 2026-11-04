package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"

	ce "clawreef/internal/systembackupcontrolevidence"
	api "clawreef/internal/systembackupdeployment"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Original owner inputs and final deployment coordinates. No ready/Passed or
// caller policy body is accepted. This action precedes worker/metadata signing.
type FunctionalPublicationMaterialInputs struct {
	Bundle                                     install.BootstrapSourceFilePin
	ClassificationDefinition                   install.BootstrapSourceFilePin
	SourceDefinition                           install.BootstrapSourceFilePin
	ComponentsTemplate                         install.BootstrapSourceFilePin
	Selection                                  pd.BootstrapConsumptionRequest
	Request                                    install.RequestFiles
	IssuerPrivateFile, ClassificationDirectory string
	RegistryDirectory                          string
	OutputDefinitionFile, OutputComponentsFile string
}

type FunctionalPublicationMaterialReceipt struct {
	Version            string
	Classification     install.FunctionalClassificationFiles
	PublicationPolicy  install.BootstrapSourceFilePin
	SourceDefinition   install.BootstrapSourceFilePin
	ComponentsTemplate install.BootstrapSourceFilePin
}

// ProduceFunctionalPublicationMaterials authenticates and signs through the
// ORIGINAL IssueFunctionalClassification API, persists that actual signature,
// and binds its exact policy before any source metadata signature exists.
// Existing sources are never overwritten/re-signed after a task was created.
func ProduceFunctionalPublicationMaterials(ctx context.Context, owner *install.Installer, password []byte, enrollment install.EnrollmentPin, in FunctionalPublicationMaterialInputs) (FunctionalPublicationMaterialReceipt, error) {
	var zero FunctionalPublicationMaterialReceipt
	if ctx == nil || ctx.Err() != nil || owner == nil {
		return zero, install.ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, install.ErrInstall
	}
	reads := []install.BootstrapSourceFilePin{in.Bundle, in.ClassificationDefinition, in.SourceDefinition, in.ComponentsTemplate}
	raw := make([][]byte, len(reads))
	for n, p := range reads {
		var err error
		raw[n], err = install.ReadSourceMaterialFile(p.File)
		if err != nil || hash(raw[n]) != p.SHA256 {
			return zero, install.ErrInstall
		}
	}
	var definition ProductionMaterialDefinition
	var components OriginalCaptureMappingDefinition
	if decodeMetadataCanonical(raw[2], &definition) != nil || definition.Version != productionMaterialDefinitionVersion || decodeMetadataCanonical(raw[3], &components) != nil || components.Version != OriginalCaptureInstallationTemplateVersion || components.OriginalDefinitionSHA256 != in.SourceDefinition.SHA256 {
		return zero, install.ErrInstall
	}
	core, err := LoadDeploymentConfig(definition.CoreFile, definition.CoreSHA256)
	if err != nil || core.CaptureModules == nil {
		return zero, install.ErrInstall
	}
	var material productionCaptureMaterials
	if decodeMetadataCanonical(definition.Materials, &material) != nil || material.Discovery == nil || material.Discovery.PublicationPolicy != nil || material.Discovery.GrantSHA256 != "" || material.Redis.GrantSHA256 != "" || material.Objects.GrantSHA256 != "" {
		return zero, install.ErrInstall
	}
	// Actual on-disk outputs must still be absent: an already signed scope is
	// immutable, even if an operator supplied a new unsigned template afterward.
	for _, file := range []string{material.Discovery.GrantFile, material.Redis.GrantFile, material.Objects.GrantFile, core.CaptureModules.Path} {
		if file == "" {
			return zero, install.ErrInstall
		}
		if _, err := os.Lstat(file); !os.IsNotExist(err) {
			return zero, install.ErrInstall
		}
	}
	profile, err := api.LoadExecutionProfile(core.ProfileFile)
	if err != nil {
		return zero, install.ErrInstall
	}
	paths := map[string]bool{}
	for _, p := range reads {
		paths[p.File] = true
	}
	for _, file := range []string{definition.CoreFile, definition.ConfigFile, in.IssuerPrivateFile, material.Redis.GrantFile, material.Objects.GrantFile, material.Discovery.GrantFile, core.CaptureModules.Path} {
		paths[file] = true
	}
	for _, file := range []string{in.OutputDefinitionFile, in.OutputComponentsFile} {
		if !filepath.IsAbs(file) || filepath.Clean(file) != file || paths[file] {
			return zero, install.ErrInstall
		}
		paths[file] = true
		if _, err := os.Lstat(file); !os.IsNotExist(err) {
			return zero, install.ErrInstall
		}
	}
	key, err := install.ReadPrivateFile(in.IssuerPrivateFile, ed25519.PrivateKeySize)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	signed, err := owner.IssueFunctionalClassification(ctx, password, enrollment, raw[0], in.Bundle.SHA256, in.ClassificationDefinition.File, in.ClassificationDefinition.SHA256, in.Selection, in.Request, key)
	if err != nil {
		return zero, err
	}
	var classified install.FunctionalClassificationRecord
	if json.Unmarshal(signed.Record, &classified) != nil || classified.Profile != install.FunctionalNonDRProfile || classified.TaskPurpose != "functional_test" || classified.Target.InstallationID != core.InstallationID || string(classified.Selection.ConfigHash) != definition.ConfigSHA256 || classified.TargetClass != profile.TargetClass || classified.TargetFailureDomain != profile.FailureDomain || !reflect.DeepEqual(classified.TargetRisks, profile.TargetRisks) || hash(signed.PublicationPolicy) != classified.PublicationPolicySHA256 {
		return zero, install.ErrInstall
	}
	policy, policyErr := decodeOriginalPublicationPolicy(signed.PublicationPolicy, classified.PublicationPolicySHA256, core.InstallationID, definition.ConfigSHA256, ce.RegistryPin{Version: classified.FailureDomains.Version, SHA256: classified.FailureDomains.SHA256}, publicationManifestTarget{Class: profile.TargetClass, Domain: profile.FailureDomain, Risks: profile.TargetRisks})
	if policyErr != nil || policy.Policy.RecoveryEvidenceStatus != "not_provided" || policy.Policy.RecoveryEvidence != nil {
		return zero, install.ErrInstall
	}
	if !filepath.IsAbs(in.RegistryDirectory) || filepath.Clean(in.RegistryDirectory) != in.RegistryDirectory || !filepath.IsAbs(in.ClassificationDirectory) || filepath.Clean(in.ClassificationDirectory) != in.ClassificationDirectory {
		return zero, install.ErrInstall
	}
	registryFiles := sec.RegistrationFiles{RegistryDirectory: in.RegistryDirectory}
	for _, pin := range []sec.BootstrapRegistryRef{classified.FailureDomains, classified.DisasterMapping} {
		if _, e := registryFiles.RegistryBytes(pin.Kind, pin.Version, pin.SHA256); e != nil {
			return zero, install.ErrInstall
		}
	}
	if err = install.SaveFrozenFunctionalClassification(in.ClassificationDirectory, signed); err != nil {
		return zero, err
	}
	policyFile := filepath.Join(in.ClassificationDirectory, "functional-publication-policy.json")
	actual, err := install.ReadPrivateFile(policyFile, 65536)
	if err != nil || !bytes.Equal(actual, signed.PublicationPolicy) {
		return zero, install.ErrInstall
	}
	material.Discovery.PublicationPolicy = &originalPublicationPolicyReference{Protocol: originalPublicationPolicyVersion, Path: policyFile, SHA256: hash(actual)}
	definition.Materials, err = json.Marshal(material)
	if err != nil {
		return zero, install.ErrInstall
	}
	encoded, err := json.Marshal(definition)
	if err != nil {
		return zero, install.ErrInstall
	}
	// Keep the selected KMS/files/component declarations unchanged. Only the
	// source definition hash must follow this pre-signing policy binding.
	components.OriginalDefinitionSHA256 = hash(encoded)
	componentBytes, err := json.Marshal(components)
	if err != nil {
		return zero, install.ErrInstall
	}
	for n, p := range reads {
		now, e := install.ReadSourceMaterialFile(p.File)
		if e != nil || !bytes.Equal(now, raw[n]) {
			return zero, install.ErrInstall
		}
	}
	if ctx.Err() != nil || writeOriginalMaterialFile(in.OutputDefinitionFile, encoded) != nil || writeOriginalMaterialFile(in.OutputComponentsFile, componentBytes) != nil {
		return zero, install.ErrInstall
	}
	for _, p := range []install.BootstrapSourceFilePin{{File: in.OutputDefinitionFile, SHA256: hash(encoded)}, {File: in.OutputComponentsFile, SHA256: hash(componentBytes)}} {
		actual, e := install.ReadSourceMaterialFile(p.File)
		if e != nil || hash(actual) != p.SHA256 {
			return zero, install.ErrInstall
		}
	}
	return FunctionalPublicationMaterialReceipt{Version: "original-functional-publication-materials.v1", Classification: install.FunctionalClassificationFiles{RecordFile: filepath.Join(in.ClassificationDirectory, "functional-classification.record.json"), RecordSHA256: hash(signed.Record), SignatureFile: filepath.Join(in.ClassificationDirectory, "functional-classification.signature"), RegistryDirectory: in.RegistryDirectory}, PublicationPolicy: install.BootstrapSourceFilePin{File: policyFile, SHA256: hash(signed.PublicationPolicy)}, SourceDefinition: install.BootstrapSourceFilePin{File: in.OutputDefinitionFile, SHA256: hash(encoded)}, ComponentsTemplate: install.BootstrapSourceFilePin{File: in.OutputComponentsFile, SHA256: hash(componentBytes)}}, nil
}
