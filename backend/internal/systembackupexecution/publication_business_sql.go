package systembackupexecution

import (
	"encoding/json"
	"strings"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Explicit SQL units only. These are inputs to the six-domain manifest
// summaries, not complete summaries of Redis, objects, workspace or resources.
// No cell value or plaintext row hash is retained.
type publicationSQLDomainCounts struct {
	Tables, Rows, RawCellBytes int64
}

func publicationSQLBusinessCounts(capture publicationVerifiedCapture) (map[string]publicationSQLDomainCounts, error) {
	if !capture.checked() || capture.SourceFacts.validate() != nil {
		return nil, c.ErrExecutionRecord
	}
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(capture.Input.SourceSnapshot, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.PublicationFacts == nil || metadata.PublicationFacts.SchemaRegistry != capture.SourceFacts.SchemaRegistry || hash(metadata.PublicationFacts.SchemaRegistryBytes) != hash(capture.SourceFacts.SchemaRegistryBytes) {
		return nil, c.ErrExecutionRecord
	}
	var sqlPart *publicationVerifiedPart
	for index := range capture.Parts {
		if capture.Parts[index].Operation == "capture-database" {
			if sqlPart != nil {
				return nil, c.ErrExecutionRecord
			}
			sqlPart = &capture.Parts[index]
		}
	}
	if sqlPart == nil || sqlPart.RequestedPart != "mysql" {
		return nil, c.ErrExecutionRecord
	}
	return derivePublicationSQLBusinessCounts(metadata.SQLSchema, capture.SourceFacts, sqlPart.Counts)
}

// The original pinned registry supplies category ownership. In particular it
// must not be replaced by coarse capture categories or the current runtime's
// normalization-rule registry, whose categories need not be identical.
func derivePublicationSQLBusinessCounts(schema domain.BusinessCaptureSchema, facts productionPublicationSourceFacts, counts ownedPayloadCounts) (map[string]publicationSQLDomainCounts, error) {
	if schema.Validate() != nil || schema.PolicySHA256 != domain.BusinessCapturePolicySHA256() || facts.SchemaSHA256 != schema.SchemaSHA256 || len(facts.SchemaRegistryBytes) == 0 || len(facts.SchemaRegistryBytes) > 8<<20 || hash(facts.SchemaRegistryBytes) != facts.SchemaRegistry.SHA256 || counts.Version != "system-backup-inert-payload-counts.v1" || counts.Kind != "sql_raw_cell_bytes" || !counts.Complete || counts.ArchiveEntries != 0 || len(counts.SQLTables) != len(schema.Tables) || counts.Items != int64(len(schema.Tables)) || counts.ContentBytes < 0 {
		return nil, c.ErrExecutionRecord
	}
	registry, err := readPublicationFrozenRegistry(facts)
	if err != nil {
		return nil, c.ErrExecutionRecord
	}
	selected := make(map[string]bool, len(schema.Tables))
	for _, name := range schema.Tables {
		selected[name] = true
	}
	out := map[string]publicationSQLDomainCounts{"users": {}, "instances": {}, "ai_gateway": {}, "teams": {}, "resources": {}, "skill_hub": {}}
	categories := map[string]string{}
	for _, object := range registry.Objects {
		if object.Type != "table" || !selected[object.Name] {
			continue
		}
		if _, ok := out[object.Category]; !ok || object.Backup != "mysql_dump" || categories[object.Name] != "" {
			return nil, c.ErrExecutionRecord
		}
		if object.Classification == nil || (*object.Classification != "public" && *object.Classification != "internal" && *object.Classification != "confidential" && *object.Classification != "secret") || object.Restore != "normalize" {
			return nil, c.ErrExecutionRecord
		}
		categories[object.Name] = object.Category
	}
	if len(categories) != len(schema.Tables) {
		return nil, c.ErrExecutionRecord
	}
	const maxExactJSONInteger int64 = 9007199254740991
	var totalBytes int64
	for index, table := range counts.SQLTables {
		if table.Table != schema.Tables[index] || table.Rows < 0 || table.CellBytes < 0 || table.CellBytes > counts.ContentBytes-totalBytes {
			return nil, c.ErrExecutionRecord
		}
		category := categories[table.Table]
		count := out[category]
		if count.Tables >= maxExactJSONInteger || table.Rows > maxExactJSONInteger-count.Rows || table.CellBytes > maxExactJSONInteger-count.RawCellBytes {
			return nil, c.ErrExecutionRecord
		}
		count.Tables++
		count.Rows += table.Rows
		count.RawCellBytes += table.CellBytes
		out[category] = count
		totalBytes += table.CellBytes
	}
	if totalBytes != counts.ContentBytes {
		return nil, c.ErrExecutionRecord
	}
	for _, count := range out {
		if count.Tables < 1 {
			return nil, c.ErrExecutionRecord
		}
	}
	return out, nil
}

type publicationFrozenRegistry struct {
	Kind     string `json:"kind"`
	Version  string `json:"registry_version"`
	Contract string `json:"contract_version"`
	Status   string `json:"contract_status"`
	Schema   struct {
		Algorithm string         `json:"algorithm"`
		Status    string         `json:"status"`
		Hash      string         `json:"hash"`
		Evidence  ce.EvidenceRef `json:"evidence"`
	} `json:"schema_hash"`
	Summary struct {
		Objects      int `json:"object_count"`
		Recorded     int `json:"policy_recorded"`
		Pending      int `json:"policy_pending"`
		CrossPending int `json:"cross_review_pending"`
	} `json:"summary"`
	Objects []struct {
		Type           string   `json:"object_type"`
		Name           string   `json:"name"`
		Category       string   `json:"category"`
		Backup         string   `json:"backup_strategy"`
		Restore        string   `json:"restore_strategy"`
		Classification *string  `json:"data_classification"`
		Owner          string   `json:"owner"`
		Decision       string   `json:"decision_status"`
		Required       []string `json:"required_cross_reviewers"`
		Approved       []string `json:"approved_cross_reviewers"`
	} `json:"objects"`
}

// This verifies inert ownership-policy structure for manifest accounting only.
// It does not widen A's separate closed 15-table CaptureScope or authorize SQL.
func readPublicationFrozenRegistry(facts productionPublicationSourceFacts) (publicationFrozenRegistry, error) {
	var registry publicationFrozenRegistry
	if len(facts.SchemaRegistryBytes) == 0 || len(facts.SchemaRegistryBytes) > 8<<20 || hash(facts.SchemaRegistryBytes) != facts.SchemaRegistry.SHA256 || json.Unmarshal(facts.SchemaRegistryBytes, &registry) != nil || registry.Kind != "system_backup_schema_registry" || registry.Version != facts.SchemaRegistry.Version || registry.Contract != "system-backup-plan.v12" || registry.Status != "frozen" || registry.Schema.Algorithm != "sha256-information-schema-canonical-v1" || registry.Schema.Status != "observed" || !formalCandidateDigest(registry.Schema.Hash) || !formalCandidateDigest(registry.Schema.Evidence.SHA256) || !strings.HasPrefix(registry.Schema.Evidence.PublicID, "sev_") || len(registry.Schema.Evidence.PublicID) > 128 || len(registry.Objects) == 0 || len(registry.Objects) > 10000 || registry.Summary.Objects != len(registry.Objects) || registry.Summary.Recorded != len(registry.Objects) || registry.Summary.Pending != 0 || registry.Summary.CrossPending != 0 {
		return publicationFrozenRegistry{}, c.ErrExecutionRecord
	}
	seen := map[string]bool{}
	roles := map[string]bool{"A": true, "B": true, "C": true, "D": true}
	for _, object := range registry.Objects {
		id := object.Type + ":" + object.Name
		if object.Type == "" || object.Name == "" || seen[id] || object.Decision != "frozen" || !roles[object.Owner] || len(object.Required) != len(object.Approved) {
			return publicationFrozenRegistry{}, c.ErrExecutionRecord
		}
		seen[id] = true
		required := map[string]bool{}
		for _, role := range object.Required {
			if !roles[role] || role == object.Owner || required[role] {
				return publicationFrozenRegistry{}, c.ErrExecutionRecord
			}
			required[role] = true
		}
		for _, role := range object.Approved {
			if !required[role] {
				return publicationFrozenRegistry{}, c.ErrExecutionRecord
			}
			delete(required, role)
		}
		if len(required) != 0 {
			return publicationFrozenRegistry{}, c.ErrExecutionRecord
		}
	}
	return registry, nil
}
