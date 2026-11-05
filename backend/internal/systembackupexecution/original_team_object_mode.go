package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"

	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Private branch result only. C's concrete
// (*OriginalCaptureSequence).resolveOriginalTeamObjectMode(ctx) must compute
// it from the SAME authenticated original context, full SQL and app/schema/
// configuration/scope observations. No API accepts a caller-supplied mode.
type originalTeamObjectMode uint8

const (
	originalTeamObjectUnknown originalTeamObjectMode = iota
	originalTeamFilesOnly
	originalTeamObjectScopeSelected
)

// Conservative DATA test: even an empty configured object-source record is
// selected/unknown, never proof that no Team object source exists.
func originalHasTeamObjectMaterial(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return true
	}
	if json.Unmarshal(raw, &fields) != nil {
		return true
	}
	for key, value := range fields {
		if strings.EqualFold(key, "TeamObjects") && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return true
		}
	}
	return false
}

// Structural check AFTER C's live mode resolution; never source authority on
// its own. In particular nil/[] cannot cause the factory to select files-only.
func validateOriginalTeamObjectSelection(mode originalTeamObjectMode, definition ProductionMaterialDefinition, template OriginalCaptureMappingDefinition, material productionCaptureMaterials) error {
	if definition.TeamsSource == nil {
		// Keep the existing original Parts/SQL selector even without an object
		// mount. Removing a grant must not also remove its comparison source.
		return install.ErrTeamsSourceUnavailable
	}
	source := definition.TeamsSource.Source
	switch mode {
	case originalTeamFilesOnly:
		if !reflect.DeepEqual(source, worker.FormalSourceMount{}) || template.TeamsSource != nil || material.TeamObjects != nil || originalHasTeamObjectMaterial(definition.Materials) {
			return install.ErrTeamsSourceUnavailable
		}
		if _, exists := material.Operations["capture-team-objects"]; exists {
			return install.ErrTeamsSourceUnavailable
		}
		if _, exists := template.KMS["capture-team-objects"]; exists {
			return install.ErrTeamsSourceUnavailable
		}
	case originalTeamObjectScopeSelected:
		if template.TeamsSource == nil || source.Objects == nil || len(source.ObjectPrefixes) == 0 || source.Redis != nil || material.TeamObjects == nil || !reflect.DeepEqual(material.TeamObjects.Source, source) {
			return install.ErrTeamsSourceUnavailable
		}
		source.GrantSHA256 = template.TeamsSource.GrantSHA256
		if !reflect.DeepEqual(source, *template.TeamsSource) {
			return install.ErrTeamsSourceUnavailable
		}
	default:
		return install.ErrTeamsSourceUnavailable
	}
	return nil
}
