package systembackupexecution

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"clawreef/internal/buildinfo"
	appdb "clawreef/internal/db"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Facts frozen by the real source producer into the SAME encrypted plan and
// capture context. No permission, readiness flag, current task state or secret
// value is added. Build provenance remains unchanged, including a dev version;
// the public contract's git commit syntax is checked by the consumer below.
type productionPublicationSourceFacts struct {
	Version                                       string `json:"schema_version"`
	AppVersion, GitCommit, MigrationCatalogSHA256 string
	SchemaSHA256                                  string
	SchemaRegistry                                ce.RegistryPin
	CoveredObjects, ExcludedObjects               int
}

func observePublicationSourceFacts(schema domain.BusinessCaptureSchema, census domain.BusinessSchemaCensusObjects, registry ce.RegistryPin) (*productionPublicationSourceFacts, error) {
	if schema.Validate() != nil || len(census.Business) != len(schema.Tables) || len(census.Control) == 0 || registry.Version == "" || !formalCandidateDigest(registry.SHA256) {
		return nil, c.ErrExecutionRecord
	}
	for i, name := range schema.Tables {
		if census.Business[i] != name {
			return nil, c.ErrExecutionRecord
		}
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || len(catalog.Filenames) == 0 || !formalCandidateDigest(catalog.Hash) {
		return nil, c.ErrExecutionRecord
	}
	// Linked release values are the same original build provenance used by the
	// app image. Environment display overrides are deliberately not evidence.
	return &productionPublicationSourceFacts{Version: "system-backup-original-publication-source-facts.v1", AppVersion: buildinfo.Version, GitCommit: buildinfo.Commit, MigrationCatalogSHA256: catalog.Hash, SchemaSHA256: schema.SchemaSHA256, SchemaRegistry: registry, CoveredObjects: len(census.Business), ExcludedObjects: len(census.Control)}, nil
}

func (facts productionPublicationSourceFacts) validate() error {
	if facts.Version != "system-backup-original-publication-source-facts.v1" || facts.AppVersion == "" || len(facts.AppVersion) > 128 || !utf8.ValidString(facts.AppVersion) || strings.ContainsAny(facts.AppVersion, "\x00\r\n") || !regexp.MustCompile(`^[a-f0-9]{7,64}$`).MatchString(facts.GitCommit) || !formalCandidateDigest(facts.MigrationCatalogSHA256) || !formalCandidateDigest(facts.SchemaSHA256) || facts.SchemaRegistry.Version == "" || !formalCandidateDigest(facts.SchemaRegistry.SHA256) || facts.CoveredObjects < 1 || facts.CoveredObjects > 1000 || facts.ExcludedObjects < 1 || facts.ExcludedObjects > 10000 {
		return c.ErrExecutionRecord
	}
	return nil
}

func publicationSourceFacts(input c.HistoricalCaptureInput, control ce.CaptureLocator) (productionPublicationSourceFacts, error) {
	var zero productionPublicationSourceFacts
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if len(input.SourceSnapshot) == 0 || hash(input.SourceSnapshot) != input.SourceSHA256 || decodeMetadataCanonical(input.SourceSnapshot, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.Version != productionCaptureMetadataVersion || metadata.PublicationFacts == nil || metadata.PublicationFacts.validate() != nil || metadata.SQLSchema.Validate() != nil || metadata.PublicationFacts.SchemaSHA256 != metadata.SQLSchema.SchemaSHA256 || metadata.PublicationFacts.CoveredObjects != len(metadata.SQLSchema.Tables) || metadata.PublicationFacts.SchemaRegistry != control.Expected.SchemaRegistry || metadata.ControlEvidence.Expected != control.Expected {
		return zero, c.ErrExecutionRecord
	}
	return *metadata.PublicationFacts, nil
}
