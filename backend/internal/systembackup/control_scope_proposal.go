package systembackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
)

const ControlScopeProposalVersion = "system-backup-observed-control-policy-proposal.v1"

// ObserveControlScopeSchemas reads metadata only for the finite already
// classified control names. Generated expressions are recorded as inert
// metadata; this does not permit their export/restore or execute their SQL.
// ReadTableSchema's original business capture rejection remains unchanged.
func ObserveControlScopeSchemas(ctx context.Context, q SQLQueryer, names []string) ([]SQLTable, error) {
	if ctx == nil || ctx.Err() != nil || q == nil || len(names) < 1 || len(names) > 1000 {
		return nil, errors.New("invalid finite control observation scope")
	}
	for index, name := range names {
		policy, known := Policy(name)
		if !known || policy.Category != "system_backup" || policy.BackupStrategy != "metadata_only" || policy.RestoreStrategy != "reference_only" || index > 0 && names[index-1] >= name {
			return nil, errors.New("unreviewed or unordered control observation scope")
		}
	}
	observed := make([]SQLTable, 0, len(names))
	for _, name := range names {
		table, err := readTableSchema(ctx, q, name, true)
		if err != nil {
			return nil, err
		}
		observed = append(observed, table)
	}
	return observed, nil
}

// An offline review document, never an approval, capture scope or source grant.
// Classification comes only from the existing finite reviewed registry. Owner
// approvals and a frozen v12 registry must still arrive independently.
type ControlScopeProposal struct {
	Version                string              `json:"schema_version"`
	Status                 string              `json:"status"`
	ServerUUID             string              `json:"server_uuid"`
	Database               string              `json:"database"`
	MigrationCatalogSHA256 string              `json:"migration_catalog_sha256"`
	RegistrySHA256         string              `json:"reviewed_policy_sha256"`
	ObservedShapeSHA256    string              `json:"observed_shape_sha256"`
	Tables                 []ControlScopeTable `json:"tables"`
}

type ControlScopeTable struct {
	Policy       ObjectPolicy `json:"reviewed_policy"`
	Schema       SQLTable     `json:"observed_schema"`
	SchemaSHA256 string       `json:"observed_schema_sha256"`
	ReviewStatus string       `json:"review_status"`
}

// NewControlScopeProposal never assigns a policy to a newly discovered name.
// The supplied schema observations belong to an independently authenticated
// observer; producing this draft cannot establish their provenance by itself.
func NewControlScopeProposal(server, database, migrationSHA string, observed []SQLTable) (ControlScopeProposal, error) {
	zero := ControlScopeProposal{}
	if server == "" || !identifierPattern.MatchString(database) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(migrationSHA) || len(observed) < 1 || len(observed) > 1000 {
		return zero, errors.New("invalid original control proposal identity")
	}
	raw, err := json.Marshal(observed)
	var tables []SQLTable
	if err != nil || len(raw) > 8<<20 || json.Unmarshal(raw, &tables) != nil {
		return zero, errors.New("invalid original control schema observations")
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	p := ControlScopeProposal{Version: ControlScopeProposalVersion, Status: "draft_requires_independent_owner_review", ServerUUID: server, Database: database, MigrationCatalogSHA256: migrationSHA, RegistrySHA256: RegistryHash(), Tables: []ControlScopeTable{}}
	for index, table := range tables {
		policy, known := Policy(table.Name)
		if !known || policy.Category != "system_backup" || policy.BackupStrategy != "metadata_only" || policy.RestoreStrategy != "reference_only" || (policy.Classification != "internal" && policy.Classification != "secret") || index > 0 && tables[index-1].Name == table.Name || len(table.Columns) == 0 || len(table.PrimaryKey) == 0 {
			return zero, errors.New("unassigned, duplicate or invalid original control observation")
		}
		columns := map[string]bool{}
		for _, column := range table.Columns {
			if !identifierPattern.MatchString(column.Name) || column.Type == "" || columns[column.Name] || (column.Nullable != "YES" && column.Nullable != "NO") {
				return zero, errors.New("invalid original control column observation")
			}
			columns[column.Name] = true
		}
		keys := map[string]bool{}
		for _, key := range table.PrimaryKey {
			if !columns[key] || keys[key] {
				return zero, errors.New("invalid original control primary key observation")
			}
			keys[key] = true
		}
		shape, _ := json.Marshal(table)
		p.Tables = append(p.Tables, ControlScopeTable{Policy: policy, Schema: table, SchemaSHA256: controlProposalSHA256(shape), ReviewStatus: "owner_and_cross_review_required"})
	}
	shape, _ := json.Marshal(tables)
	p.ObservedShapeSHA256 = controlProposalSHA256(shape)
	return p, nil
}

func controlProposalSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
