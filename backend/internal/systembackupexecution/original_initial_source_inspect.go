package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// InitialSourceDefinitionInspection is syntax/shape DATA only. It neither
// authenticates an installer nor connects to SQL/Kubernetes/native sources.
type InitialSourceDefinitionInspection struct {
	Version, Stage, Field                                                                                string
	DefinitionDecoded, DeploymentValid, ProfileValid, OutputPathsMatch, MaterialsDecoded, MaterialsValid bool
	NativeAuthorCalled, BackupReady                                                                      bool
}

func InspectOriginalInitialSourceDefinition(raw []byte, directory string) InitialSourceDefinitionInspection {
	r := InitialSourceDefinitionInspection{Version: "original-initial-source-definition-inspection.v1", Stage: "definition_decode"}
	var in OriginalInitialSourceAuthorInputs
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		// Only a schema field name can leave this diagnostic, never the
		// offending value, raw decoder error or any credential body.
		const prefix = "json: unknown field "
		if strings.HasPrefix(err.Error(), prefix) {
			field := strings.Trim(strings.TrimPrefix(err.Error(), prefix), "\"")
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,100}$`).MatchString(field) {
				r.Field = field
			}
		}
		if typed, ok := err.(*json.UnmarshalTypeError); ok && regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,100}$`).MatchString(typed.Field) {
			r.Field = typed.Field
		}
		return r
	}
	if d.Decode(new(any)) != io.EOF {
		return r
	}
	r.DefinitionDecoded = true
	r.DeploymentValid = in.Deployment.Validate() == nil
	_, _, profileErr := in.Profile.CanonicalIdentity()
	r.ProfileValid = profileErr == nil && in.Profile.InstallationID == in.Deployment.InstallationID
	r.OutputPathsMatch = filepath.IsAbs(directory) && filepath.Clean(directory) == directory &&
		in.Deployment.ProfileFile == filepath.Join(directory, "execution-profile.json") &&
		in.Deployment.CaptureModules != nil && in.Deployment.CaptureModules.Path == filepath.Join(directory, "capture-materials.json")
	var material productionCaptureMaterials
	m := json.NewDecoder(bytes.NewReader(in.Materials))
	m.DisallowUnknownFields()
	materialErr := m.Decode(&material)
	if materialErr == nil && m.Decode(new(any)) == io.EOF {
		r.MaterialsDecoded = true
		r.MaterialsValid = material.Discovery != nil && material.Version == productionCaptureMaterialsVersion &&
			material.DeploymentConfigSHA256 == "" && material.CaptureGrantSHA256 == "" && material.Redis.GrantSHA256 == "" &&
			material.Objects.GrantSHA256 == "" && material.Discovery.GrantSHA256 == "" &&
			material.InstallationID == in.Deployment.InstallationID && material.ControllerOwner == in.Deployment.ControllerOwner
		for _, operation := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
			if _, ok := material.Operations[operation]; !ok {
				r.MaterialsValid = false
			}
		}
	}
	if materialErr != nil {
		r.Stage = "materials_decode"
		const prefix = "json: unknown field "
		if strings.HasPrefix(materialErr.Error(), prefix) {
			field := strings.Trim(strings.TrimPrefix(materialErr.Error(), prefix), "\"")
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,100}$`).MatchString(field) {
				r.Field = field
			}
		}
		if typed, ok := materialErr.(*json.UnmarshalTypeError); ok && regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,100}$`).MatchString(typed.Field) {
			r.Field = typed.Field
		}
		return r
	}
	r.Stage = "definition_shape_checked_no_authority"
	return r
}
