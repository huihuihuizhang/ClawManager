package systembackupexecution

import (
	"encoding/json"
	"testing"

	"clawreef/internal/buildinfo"
	appdb "clawreef/internal/db"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
)

func checkOriginalPublicationSourceFacts(t *testing.T, discovery b.Discovery) {
	t.Helper()
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(discovery.Source, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.PublicationFacts == nil {
		t.Fatal("same original Prepare did not freeze publication source facts")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	facts := metadata.PublicationFacts
	if err != nil || facts.AppVersion != buildinfo.Version || facts.GitCommit != buildinfo.Commit || facts.MigrationCatalogSHA256 != catalog.Hash || facts.SchemaSHA256 != metadata.SQLSchema.SchemaSHA256 || facts.CoveredObjects != len(metadata.SQLSchema.Tables) || facts.ExcludedObjects < 1 || facts.SchemaRegistry != metadata.ControlEvidence.Expected.SchemaRegistry {
		t.Fatal("original publication source provenance did not match actual producer")
	}
}

func TestPublicationSourceFactsUseLinkedReleaseAndActualCatalog(t *testing.T) {
	_, source, _, _, _ := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("fixture metadata")
	}
	t.Setenv("CLAWMANAGER_VERSION", "display-override-is-not-evidence")
	t.Setenv("CLAWMANAGER_COMMIT", "display-override-is-not-evidence")
	facts, err := observePublicationSourceFacts(metadata.SQLSchema, domain.BusinessSchemaCensusObjects{Business: metadata.SQLSchema.Tables, Control: []string{"schema_migrations"}}, metadata.ControlEvidence.Expected.SchemaRegistry)
	catalog, catalogErr := appdb.EmbeddedMigrationCatalog()
	if err != nil || catalogErr != nil || facts.AppVersion != buildinfo.Version || facts.GitCommit != buildinfo.Commit || facts.MigrationCatalogSHA256 != catalog.Hash || facts.SchemaSHA256 != metadata.SQLSchema.SchemaSHA256 || facts.CoveredObjects != len(metadata.SQLSchema.Tables) || facts.ExcludedObjects != 1 {
		t.Fatal("source provenance changed or invented", err)
	}
}

// Pure named source DATA, not original task/capture/readback authority. The
// consumer must use the frozen bytes, never the publishing process's build.
func TestPublicationFrozenSourceFactsRejectDrift(t *testing.T) {
	for _, mode := range []string{"unchanged-dev-version", "missing", "source-hash", "schema", "registry", "covered", "bad-commit"} {
		t.Run(mode, func(t *testing.T) {
			_, source, _, _, _ := productionModuleFixture(t)
			var metadata productionCaptureMetadata
			if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
				t.Fatal("fixture metadata")
			}
			metadata.PublicationFacts = &productionPublicationSourceFacts{Version: "system-backup-original-publication-source-facts.v1", AppVersion: "dev", GitCommit: "1234567", MigrationCatalogSHA256: hash([]byte("explicit frozen catalog DATA")), SchemaSHA256: metadata.SQLSchema.SchemaSHA256, SchemaRegistry: metadata.ControlEvidence.Expected.SchemaRegistry, CoveredObjects: len(metadata.SQLSchema.Tables), ExcludedObjects: 1}
			control := metadata.ControlEvidence
			switch mode {
			case "missing":
				metadata.PublicationFacts = nil
			case "schema":
				metadata.PublicationFacts.SchemaSHA256 = hash([]byte("changed"))
			case "registry":
				metadata.PublicationFacts.SchemaRegistry.SHA256 = hash([]byte("changed"))
			case "covered":
				metadata.PublicationFacts.CoveredObjects++
			case "bad-commit":
				metadata.PublicationFacts.GitCommit = "unknown"
			}
			source.CaptureMetadata, _ = json.Marshal(metadata)
			raw, _ := json.Marshal(source)
			input := c.HistoricalCaptureInput{SourceSnapshot: raw, SourceSHA256: hash(raw)}
			if mode == "source-hash" {
				input.SourceSHA256 = hash([]byte("changed"))
			}
			facts, err := publicationSourceFacts(input, control)
			if mode == "unchanged-dev-version" {
				if err != nil || facts.AppVersion != "dev" || facts.GitCommit != "1234567" {
					t.Fatal("frozen source facts unavailable", err)
				}
			} else if err == nil {
				t.Fatal("changed source facts accepted")
			}
		})
	}
}
