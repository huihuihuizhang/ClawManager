package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"

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
	DatabaseIssueDefinition                             install.BootstrapSourceFilePin
	TemplateFile, TemplateSHA256                        string
	ResolvedComponentsFile, IntermediateFile            string
}

// InstallOriginalCaptureMappings calls the actual B sequence, concrete D
// materializer and B finalizer with one original bounded context. It never
// constructs a fake owner, UID, credential, permission, source observation or
// enabled-v1/task prerequisite. Errors retain all original/partial files and
// immutable objects for independent inspection; no rollback deletes them.
func InstallOriginalCaptureMappings(ctx context.Context, owner *install.Installer, client kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, input OriginalCaptureInstallationInputs, runtimeDB ...*sql.DB) (ProductionMaterialReceipt, error) {
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
	// C owns the actual same-context SQL/app/schema/config/scope read. This
	// branch is never selected by nil mounts, static [] or a caller flag.
	preflight, err := PrepareOriginalCaptureSourceSequence(ctx, owner, password, enrollment, input.DefinitionFile, input.DefinitionSHA256, input.IssuerPrivateFile, runtimeDB...)
	if err != nil {
		return zero, err
	}
	teamMode, err := preflight.resolveOriginalTeamObjectMode(ctx)
	if err != nil || validateOriginalTeamObjectSelection(teamMode, definition, template, material) != nil {
		return zero, install.ErrTeamsSourceUnavailable
	}
	selectedTeamObjectScope := teamMode == originalTeamObjectScopeSelected
	pendingTeams := selectedTeamObjectScope && template.TeamsSource.GrantSHA256 == ""
	if selectedTeamObjectScope {
		if template.TeamsSource.GrantFile == template.DatabaseSource.GrantFile || template.TeamsSource.GrantFile == input.ResolvedComponentsFile || template.TeamsSource.GrantFile == input.IntermediateFile {
			return zero, c.ErrExecutionAuthority
		}
		if pendingTeams {
			if _, e := os.Lstat(template.TeamsSource.GrantFile); !os.IsNotExist(e) {
				return zero, c.ErrExecutionAuthority
			}
		}
	}
	// Template placeholders must name ONLY the two original grant paths, once
	// each. Do not repair caller-provided hashes or silently add undeclared files.
	pendingDatabase := input.DatabaseIssueDefinition != (install.BootstrapSourceFilePin{})
	if pendingDatabase && (input.DatabaseIssueDefinition.File == "" || input.DatabaseIssueDefinition.SHA256 == "" || template.DatabaseSource.GrantSHA256 != "") {
		return zero, c.ErrExecutionAuthority
	}
	pendingGrants := []string{material.Redis.GrantFile, material.Objects.GrantFile}
	if pendingDatabase {
		pendingGrants = append(pendingGrants, template.DatabaseSource.GrantFile)
	}
	pendingControl := material.ControlEvidenceSource != nil && material.ControlEvidenceSource.GrantSHA256 == ""
	if pendingControl {
		pendingGrants = append(pendingGrants, material.ControlEvidenceSource.GrantFile)
	}
	if pendingTeams {
		pendingGrants = append(pendingGrants, template.TeamsSource.GrantFile)
	}
	pending := map[string]bool{}
	for _, file := range pendingGrants {
		if file == "" || pending[file] {
			return zero, c.ErrExecutionAuthority
		}
		pending[file] = true
	}
	for _, original := range pendingGrants {
		found := false
		for _, file := range template.Files {
			if file.WorkerPath == original {
				if found || file.File != "" || file.SHA256 != "" {
					return zero, c.ErrExecutionAuthority
				}
				found = true
			} else if file.File == "" || file.SHA256 == "" {
				if !pending[file.WorkerPath] {
					return zero, c.ErrExecutionAuthority
				}
			}
		}
		if !found {
			return zero, c.ErrExecutionAuthority
		}
	}
	// Authenticate + observe Teams BEFORE any other grant is emitted. Missing
	// inventory or denied native reads must not create a half source bundle.
	if pendingTeams {
		if err = preflight.ValidateTeamsSource(ctx); err != nil {
			return zero, err
		}
	} else if selectedTeamObjectScope {
		checked, e := preflight.QueryTeamsSourceGrant(ctx)
		if e != nil || !reflect.DeepEqual(checked.Source, *template.TeamsSource) {
			return zero, c.ErrExecutionAuthority
		}
	}
	sequence, err := BeginOriginalCaptureSequence(ctx, owner, password, enrollment, input.DefinitionFile, input.DefinitionSHA256, input.IssuerPrivateFile, runtimeDB...)
	if err != nil {
		return zero, err
	}
	var teamsResult install.TeamsSourceIssueResult
	if pendingTeams {
		teamsResult, err = sequence.IssueTeamsSourceGrant(ctx)
		if err != nil {
			return zero, err
		}
		template.TeamsSource = &teamsResult.Source
	}
	if selectedTeamObjectScope {
		// C's runtime material retains the SAME independent object mount.
		// Fill only its actually issued/query-verified grant SHA.
		if sequence.materials.TeamObjects == nil || template.TeamsSource == nil {
			return zero, install.ErrTeamsSourceUnavailable
		}
		expected := sequence.materials.TeamObjects.Source
		expected.GrantSHA256 = template.TeamsSource.GrantSHA256
		if !reflect.DeepEqual(expected, *template.TeamsSource) {
			return zero, install.ErrTeamsSourceUnavailable
		}
		sequence.materials.TeamObjects.Source = *template.TeamsSource
	}
	var controlResult install.ControlEvidenceSourceIssueResult
	if pendingControl {
		// SAME actual original SourceMaterialIssuer/context; not an external
		// signer handle, JSON approval or renewed definition/window.
		controlResult, err = sequence.IssueControlEvidenceSourceGrant(ctx)
		if err != nil {
			return zero, err
		}
	}
	var databaseResult install.DatabaseSourceIssueResult
	if pendingDatabase {
		databaseResult, err = sequence.IssueDatabaseSourceGrant(ctx, input.DatabaseIssueDefinition.File, input.DatabaseIssueDefinition.SHA256)
		if err != nil {
			return zero, err
		}
		expected := template.DatabaseSource
		expected.GrantSHA256 = databaseResult.Source.GrantSHA256
		if !reflect.DeepEqual(expected, databaseResult.Source) {
			return zero, c.ErrExecutionAuthority
		}
		template.DatabaseSource = databaseResult.Source
	}
	redis, objects, err := sequence.WorkerSourceMounts(ctx)
	if err != nil {
		return zero, err
	}
	for index, file := range template.Files {
		if pendingTeams && file.WorkerPath == teamsResult.Source.GrantFile {
			template.Files[index].File, template.Files[index].SHA256 = teamsResult.Grant.File, teamsResult.Grant.SHA256
		}
		if pendingDatabase && file.WorkerPath == databaseResult.Source.GrantFile {
			template.Files[index].File, template.Files[index].SHA256 = databaseResult.Source.GrantFile, databaseResult.Source.GrantSHA256
		}
		if pendingControl && file.WorkerPath == controlResult.Source.GrantFile {
			template.Files[index].File, template.Files[index].SHA256 = controlResult.Grant.File, controlResult.Grant.SHA256
		}
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
