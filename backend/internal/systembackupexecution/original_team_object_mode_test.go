package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	k "clawreef/internal/systembackupkms"
)

// DATA regression only. C must independently test the live resolver's SQL,
// image/schema/pin binding and complete original object-scope discrimination.
func TestOriginalTeamConditionalGateCannotDropSelectedScope(t *testing.T) {
	for _, name := range []string{"file-only", "unknown", "missing-selector", "selected-without-mount", "declared-root", "stale-grant", "template-mount", "material-object-source", "empty-material-object-source", "shadowed-material-object-source", "alias-material-object-source", "object-operation", "object-kms", "selected-valid", "selected-scope-swap"} {
		t.Run(name, func(t *testing.T) {
			d := ProductionMaterialDefinition{TeamsSource: &install.TeamsSourceIssueDefinition{}, Materials: json.RawMessage(`{}`)}
			template := OriginalCaptureMappingDefinition{KMS: map[string]k.Config{}}
			material := productionCaptureMaterials{Operations: map[string]productionCaptureOperation{}}
			mode := originalTeamFilesOnly
			selected := worker.FormalSourceMount{GrantFile: "/private/teams-grant", Objects: &worker.SourceTLSMapping{Address: "objects.invalid:443"}, ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "original", Prefix: "teams/"}}}
			switch name {
			case "unknown":
				mode = originalTeamObjectUnknown
			case "missing-selector":
				d.TeamsSource = nil
			case "selected-without-mount":
				mode = originalTeamObjectScopeSelected
			case "declared-root":
				d.TeamsSource.Source = selected
			case "stale-grant":
				d.TeamsSource.Source.GrantSHA256 = strings.Repeat("a", 64)
			case "template-mount":
				template.TeamsSource = &worker.FormalSourceMount{}
			case "material-object-source":
				d.Materials = json.RawMessage(`{"TeamObjects":{"Source":{"ObjectPrefixes":[{"Bucket":"original","Prefix":"teams/"}]}}}`)
			case "empty-material-object-source":
				d.Materials = json.RawMessage(`{"TeamObjects":{}}`)
			case "shadowed-material-object-source":
				d.Materials = json.RawMessage(`{"TeamObjects":{"Source":{}},"TeamObjects":null}`)
			case "alias-material-object-source":
				d.Materials = json.RawMessage(`{"teamobjects":{"Source":{}},"TeamObjects":null}`)
			case "object-operation":
				material.Operations["capture-team-objects"] = productionCaptureOperation{}
			case "object-kms":
				template.KMS["capture-team-objects"] = k.Config{}
			case "selected-valid", "selected-scope-swap":
				mode = originalTeamObjectScopeSelected
				d.TeamsSource.Source = selected
				material.TeamObjects = &productionTeamObjectsSource{Source: selected}
				copy := selected
				copy.GrantSHA256 = strings.Repeat("b", 64)
				if name == "selected-scope-swap" {
					copy.ObjectPrefixes = []worker.ObjectSourcePrefix{{Bucket: "original", Prefix: "other/"}}
				}
				template.TeamsSource = &copy
			}
			e := validateOriginalTeamObjectSelection(mode, d, template, material)
			if (e == nil) != (name == "file-only" || name == "selected-valid") {
				t.Fatalf("unexpected conditional selection: %v", e)
			}
		})
	}
}

func TestOriginalTeamTemplateRemovalRetainsAllMandatoryDomains(t *testing.T) {
	ops := map[string]productionCaptureOperation{}
	for _, name := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation} {
		ops[name] = productionCaptureOperation{}
	}
	// The real plan contract, rather than a count of hand-picked categories,
	// must still require all seven original mandatory operation builders.
	if _, e := newProductionCapturePlan(ops, "original"); e != nil {
		t.Fatal(e)
	}
	delete(ops, "capture-skill-objects")
	if _, e := newProductionCapturePlan(ops, "original"); e == nil {
		t.Fatal("Team omission also removed mandatory object storage")
	}
}
