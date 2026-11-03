package systembackupexecution

import (
	"context"
	"encoding/json"
	"path/filepath"

	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes"
)

const OriginalCaptureInstallationTemplateVersion = "original-capture-installation-components-template.v1"

// OriginalCaptureInstallationInputs is an installation-process argument list,
// never public HTTP/task input or serialized authority. The independently
// selected template leaves ONLY the two not-yet-issued source grant file/hash
// pairs empty. Other finite files, native KMS components and database grant
// already exist and remain exact original selected inputs.
type OriginalCaptureInstallationInputs struct {
	DefinitionFile, DefinitionSHA256, IssuerPrivateFile string
	TemplateFile, TemplateSHA256                        string
	ResolvedComponentsFile, IntermediateFile            string
}

// InstallOriginalCaptureMappings calls the actual B sequence, concrete D
// materializer and B finalizer with one original bounded context. It never
// constructs a fake owner, UID, credential, permission, source observation or
// enabled-v1/task prerequisite. Errors retain all original/partial files and
// immutable objects for independent inspection; no rollback deletes them.
func InstallOriginalCaptureMappings(ctx context.Context, owner *install.Installer, client kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, input OriginalCaptureInstallationInputs) (ProductionMaterialReceipt, error) {
	var zero ProductionMaterialReceipt
	if ctx == nil || ctx.Err() != nil || owner == nil || client == nil {
		return zero, c.ErrExecutionAuthority
	}
	raw, err := install.ReadSourceMaterialFile(input.TemplateFile)
	var template OriginalCaptureMappingDefinition
	if err != nil || hash(raw) != input.TemplateSHA256 || decodeMetadataCanonical(raw, &template) != nil || template.Version != OriginalCaptureInstallationTemplateVersion || template.OriginalDefinitionSHA256 != input.DefinitionSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	// Validate every selected output coordinate before Begin publishes grants.
	definitionRaw, err := install.ReadSourceMaterialFile(input.DefinitionFile)
	var definition ProductionMaterialDefinition
	if err != nil || hash(definitionRaw) != input.DefinitionSHA256 || decodeMetadataCanonical(definitionRaw, &definition) != nil {
		return zero, c.ErrExecutionAuthority
	}
	core, err := LoadDeploymentConfig(definition.CoreFile, definition.CoreSHA256)
	if err != nil || core.CaptureModules == nil {
		return zero, c.ErrExecutionAuthority
	}
	var material productionCaptureMaterials
	if decodeMetadataCanonical(definition.Materials, &material) != nil || material.Discovery == nil {
		return zero, c.ErrExecutionAuthority
	}
	protected := map[string]bool{}
	for _, file := range []string{input.DefinitionFile, input.TemplateFile, input.IssuerPrivateFile, definition.CoreFile, definition.ConfigFile, core.ForwardGrant.Path, material.Redis.GrantFile, material.Objects.GrantFile, material.Discovery.GrantFile, core.CaptureModules.Path} {
		protected[file] = true
	}
	for _, file := range template.Files {
		if file.File != "" {
			protected[file.File] = true
		}
	}
	for _, file := range []string{input.ResolvedComponentsFile, input.IntermediateFile} {
		if !filepath.IsAbs(file) || filepath.Clean(file) != file || filepath.Dir(file) != filepath.Dir(core.CaptureModules.Path) || protected[file] {
			return zero, c.ErrExecutionAuthority
		}
		protected[file] = true
	}
	// Template placeholders must name ONLY the two original grant paths, once
	// each. Do not repair caller-provided hashes or silently add undeclared files.
	for _, original := range []string{material.Redis.GrantFile, material.Objects.GrantFile} {
		found := false
		for _, file := range template.Files {
			if file.WorkerPath == original {
				if found || file.File != "" || file.SHA256 != "" {
					return zero, c.ErrExecutionAuthority
				}
				found = true
			} else if file.File == "" || file.SHA256 == "" {
				if file.WorkerPath != material.Redis.GrantFile && file.WorkerPath != material.Objects.GrantFile {
					return zero, c.ErrExecutionAuthority
				}
			}
		}
		if !found {
			return zero, c.ErrExecutionAuthority
		}
	}
	sequence, err := BeginOriginalCaptureSequence(ctx, owner, password, enrollment, input.DefinitionFile, input.DefinitionSHA256, input.IssuerPrivateFile)
	if err != nil {
		return zero, err
	}
	redis, objects, err := sequence.WorkerSourceMounts(ctx)
	if err != nil {
		return zero, err
	}
	for index, file := range template.Files {
		for _, grant := range []struct{ file, sha string }{{redis.GrantFile, redis.GrantSHA256}, {objects.GrantFile, objects.GrantSHA256}} {
			if file.WorkerPath == grant.file {
				template.Files[index].File, template.Files[index].SHA256 = grant.file, grant.sha
			}
		}
	}
	template.Version = OriginalCaptureMappingDefinitionVersion
	resolved, err := json.Marshal(template)
	if err != nil || writeOriginalMaterialFile(input.ResolvedComponentsFile, resolved) != nil {
		return zero, c.ErrExecutionAuthority
	}
	actual, err := install.ReadSourceMaterialFile(input.ResolvedComponentsFile)
	if err != nil || hash(actual) != hash(resolved) {
		return zero, c.ErrExecutionAuthority
	}
	intermediate, err := sequence.MaterializeMappings(ctx, client, input.ResolvedComponentsFile, hash(resolved), input.IntermediateFile)
	if err != nil {
		return zero, err
	}
	// The fixed template is re-read after the last materialization GET, before
	// granting final metadata, then again after all finalizer owner tails.
	if check, err := install.ReadSourceMaterialFile(input.TemplateFile); err != nil || hash(check) != input.TemplateSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	receipt, err := sequence.Finalize(ctx, client, intermediate.File, intermediate.SHA256)
	if err != nil {
		return zero, err
	}
	if check, err := install.ReadSourceMaterialFile(input.TemplateFile); err != nil || hash(check) != input.TemplateSHA256 || ctx.Err() != nil {
		return zero, c.ErrExecutionAuthority
	}
	return receipt, nil
}
