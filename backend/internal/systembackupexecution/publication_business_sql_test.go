package systembackupexecution

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Named registry/schema/count DATA only. Synthetic approvals below are confined
// to this mapping test. No task, SQL, capture receipt or authority is created.
func publicationSQLCategoryData(t *testing.T) (domain.BusinessCaptureSchema, productionPublicationSourceFacts, ownedPayloadCounts) {
	t.Helper()
	raw, err := os.ReadFile("../systembackupbusinessa/testdata/schema-registry-historical-15.json")
	var document map[string]any
	if err != nil || json.Unmarshal(raw, &document) != nil {
		t.Fatal("named registry DATA unavailable", err)
	}
	document["contract_status"] = "frozen"
	observation := document["schema_hash"].(map[string]any)
	observation["status"], observation["hash"] = "observed", strings.Repeat("a", 64)
	observation["evidence"] = map[string]any{"public_id": "sev_named_category_DATA", "sha256": strings.Repeat("b", 64)}
	objects := document["objects"].([]any)
	selected := map[string]bool{}
	for _, name := range domain.BusinessCaptureTables() {
		selected[name] = true
	}
	names := map[string]bool{}
	for _, value := range objects {
		object := value.(map[string]any)
		object["decision_status"] = "frozen"
		object["approved_cross_reviewers"] = object["required_cross_reviewers"]
		if object["object_type"] == "table" {
			name := object["name"].(string)
			names[name] = true
			if selected[name] {
				policy, ok := root.Policy(name)
				if !ok {
					t.Fatal("named selected-table policy DATA unavailable", name)
				}
				if object["category"] == nil || object["category"] == "" {
					object["category"] = policy.Category
				}
				if object["data_classification"] == nil {
					object["data_classification"] = policy.Classification
				}
				object["backup_strategy"], object["restore_strategy"] = "mysql_dump", "normalize"
			}
		}
	}
	for _, name := range domain.BusinessCaptureTables() {
		if names[name] {
			continue
		}
		policy, ok := root.Policy(name)
		if !ok {
			t.Fatal("named policy DATA unavailable", name)
		}
		objects = append(objects, map[string]any{"object_type": "table", "name": name, "category": policy.Category, "data_classification": policy.Classification, "owner": "D", "decision_status": "frozen", "backup_strategy": "mysql_dump", "restore_strategy": "normalize", "required_cross_reviewers": []string{"A", "B", "C"}, "approved_cross_reviewers": []string{"A", "B", "C"}})
		names[name] = true
	}
	document["objects"] = objects
	summary := document["summary"].(map[string]any)
	summary["object_count"], summary["policy_recorded"] = len(objects), len(objects)
	summary["policy_pending"], summary["cross_review_pending"] = 0, 0
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var tables []domain.Table
	for _, name := range domain.BusinessCaptureTables() {
		if names[name] {
			tables = append(tables, domain.Table{Name: name, Engine: "InnoDB", Columns: []domain.Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}, Rows: []domain.Row{}})
		}
	}
	schema, err := domain.BusinessCaptureSchemaForTables(tables)
	if err != nil {
		t.Fatal("named complete SQL schema DATA", err)
	}
	counts := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Kind: "sql_raw_cell_bytes", Complete: true, Items: int64(len(schema.Tables)), SQLTables: []ownedSQLTableCount{}}
	for _, name := range schema.Tables {
		count := ownedSQLTableCount{Table: name}
		if name == "users" {
			count.Rows, count.CellBytes = 1, 8
		} else if name == "northbound_caller_policies" {
			count.Rows, count.CellBytes = 2, 13
		}
		counts.SQLTables = append(counts.SQLTables, count)
		counts.ContentBytes += count.CellBytes
	}
	facts := productionPublicationSourceFacts{Version: "system-backup-original-publication-source-facts.v1", AppVersion: "named-DATA", GitCommit: "1234567", MigrationCatalogSHA256: strings.Repeat("c", 64), SchemaSHA256: schema.SchemaSHA256, SchemaRegistry: ce.RegistryPin{Version: "system-backup-schema-registry.v1", SHA256: hash(raw)}, CoveredObjects: len(schema.Tables), ExcludedObjects: 1, SchemaRegistryBytes: raw}
	return schema, facts, counts
}

func TestPublicationSQLBusinessCountsUseFrozenRegistryData(t *testing.T) {
	for _, mode := range []string{"current", "missing-registry", "registry-pin", "registry-version", "registry-bytes", "policy", "missing-count", "duplicate-count", "count-kind", "incomplete", "negative-rows", "row-overflow", "byte-total"} {
		t.Run(mode, func(t *testing.T) {
			schema, facts, counts := publicationSQLCategoryData(t)
			switch mode {
			case "missing-registry":
				facts.SchemaRegistryBytes = nil
			case "registry-pin":
				facts.SchemaRegistry.SHA256 = strings.Repeat("d", 64)
			case "registry-version":
				facts.SchemaRegistry.Version += "-different"
			case "registry-bytes":
				facts.SchemaRegistryBytes[0] ^= 1
			case "policy":
				schema.PolicySHA256 = strings.Repeat("e", 64)
			case "missing-count":
				counts.SQLTables = counts.SQLTables[1:]
			case "duplicate-count":
				counts.SQLTables[1].Table = counts.SQLTables[0].Table
			case "count-kind":
				counts.Kind = "object_payload_bytes"
			case "incomplete":
				counts.Complete = false
			case "negative-rows":
				counts.SQLTables[0].Rows = -1
			case "row-overflow":
				counts.SQLTables[0].Rows = 9007199254740992
			case "byte-total":
				counts.ContentBytes++
			}
			actual, err := derivePublicationSQLBusinessCounts(schema, facts, counts)
			if mode != "current" {
				if err == nil || actual != nil {
					t.Fatal("invalid named domain-count DATA admitted", mode)
				}
				return
			}
			if err != nil || len(actual) != 6 || actual["users"].Rows != 3 || actual["users"].RawCellBytes != 21 || actual["resources"].Rows != 0 || actual["resources"].RawCellBytes != 0 {
				t.Fatal("original registry users ownership replaced by coarse/runtime mapping", err)
			}
			var tableTotal int64
			for _, count := range actual {
				tableTotal += count.Tables
			}
			if tableTotal != counts.Items {
				t.Fatal("original SQL tables omitted or counted more than once")
			}
		})
	}
}
