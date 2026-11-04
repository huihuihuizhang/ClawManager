package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// LegacySiteRowProof covers every original column of every observed source
// table, including the original 97 migration rows. The stable aggregate
// excludes only llm_models' automatic updated_at after a reviewed new-column
// backfill. The existing protocol_type remains covered. No row
// values are returned. Matching hashes do not authorize a live upgrade.
type LegacySite177RowProof struct {
	ReadMode                string                    `json:"read_mode,omitempty"`
	TargetCatalogSHA256     string                    `json:"target_catalog_sha256"`
	UpgradedSchemaSHA256    string                    `json:"upgraded_schema_sha256,omitempty"`
	UpgradedSchema          *importSchema             `json:"upgraded_schema,omitempty"`
	ExpectedLedgerRows      int                       `json:"expected_ledger_rows"`
	Phase                   string                    `json:"phase"`
	CopyServerUUID          string                    `json:"copy_server_uuid"`
	CopyDatabase            string                    `json:"copy_database"`
	SourceInventorySHA      string                    `json:"source_inventory_sha256"`
	SourceSchemaSHA         string                    `json:"source_schema_sha256"`
	OriginalLedgerSHA       string                    `json:"original_ledger_sha256"`
	Tables                  []LegacySiteRowTableProof `json:"tables"`
	PreservationSHA256      string                    `json:"preservation_sha256"`
	LLMExistingProtocolRows int64                     `json:"llm_existing_protocol_rows"`
	LLMGroupBackfillRows    int64                     `json:"llm_group_backfill_rows"`
	MigrationAuthorized     bool                      `json:"migration_authorized"`
}

// ProveLegacySiteCopyRows177 takes a repeatable-read snapshot of an isolated copy.
// The post-upgrade proof selects only the original columns, and maps the 35
// empty, preserved old control tables to their reviewed dlegacy_* names.
func ProveLegacySiteCopyRows177(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string) (LegacySite177RowProof, error) {
	return proveLegacySiteRows198(ctx, pool, inventoryRaw, phase, false)
}

// ProveLegacySiteOriginalRows198 is an explicit READ ONLY original baseline or
// post-upgrade verification entry. It neither changes the copy-only API nor
// authorizes migration, writer stop, backup consistency or recovery. The caller
// must separately hold actual original maintenance across baseline/backup/DDL.
func ProveLegacySiteOriginalRows198(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string) (LegacySite177RowProof, error) {
	return proveLegacySiteRows198(ctx, pool, inventoryRaw, phase, true)
}

func proveLegacySiteRows198(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string, original bool) (LegacySite177RowProof, error) {
	return proveLegacySiteRowsReviewed(ctx, pool, inventoryRaw, phase, original, "0031e3825416f419fb7308b6bd72c9616c6179eab376e0579f448965fbe7b4c3", 177, 198)
}

// C1 profile is separately reviewed and content-addressed. It never changes
// the old198 evidence or authorizes writing the original database.
func ProveLegacySiteRowsC1(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string, original bool) (LegacySite177RowProof, error) {
	return proveLegacySiteRowsReviewed(ctx, pool, inventoryRaw, phase, original, "1efd02dc8ee4038f53c58f17aeee39ba49ad1e6c06f56cdad3a1147d10992494", 178, 199)
}
func proveLegacySiteRowsReviewed(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string, original bool, reviewed string, fileCount, unionCount int) (LegacySite177RowProof, error) {
	var report LegacySite177RowProof
	if ctx == nil || pool == nil || ctx.Err() != nil || (phase != "before" && phase != "after") {
		return report, errors.New("legacy copy row proof unavailable")
	}
	source, err := parseLegacySiteInventory(inventoryRaw)
	if err != nil {
		return report, err
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil || catalog.Hash != reviewed || len(catalog.Filenames) != fileCount {
		return report, errors.New("legacy177 exact embedded catalog mismatch")
	}
	expected := make(map[string]bool)
	for _, name := range source.Ledger {
		expected[name] = true
	}
	for _, name := range catalog.Filenames {
		expected[name] = true
	}
	if len(expected) != unionCount {
		return report, errors.New("legacy177 reviewed ledger union changed")
	}
	report.TargetCatalogSHA256, report.ExpectedLedgerRows = catalog.Hash, len(expected)
	if phase == "before" && !original {
		if _, err = PreflightLegacySiteCopy(ctx, pool, inventoryRaw); err != nil {
			return report, err
		}
	}
	tx, err := pool.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var server, database string
	if err = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database); err != nil ||
		!legacy198ReadProofIdentity(server, database, original) {
		return report, errors.New("legacy row proof requires the observed server and an isolated copy")
	}
	if original {
		report.ReadMode = "original_database_readonly_not_migration_authority"
	}
	ledger, err := readLegacyInventoryLedger(ctx, tx)
	if err != nil {
		return report, err
	}
	if phase == "before" {
		if original {
			var journal int
			if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_import_journal'").Scan(&journal) != nil || journal != 0 {
				return report, errors.New("legacy copy already has an import journal")
			}
			if err = assertImportSourceIdle(ctx, tx, backupImportMap{}, false); err != nil {
				return report, err
			}
		}
		shape, shapeErr := readImportSchema(ctx, tx)
		if shapeErr != nil || !legacy198ReadProofSchema(importDigest(shape), original) || !sameLegacyLedger(ledger, source.Ledger) {
			return report, errors.New("legacy row proof source schema or ledger changed")
		}
	} else {
		if len(ledger) != len(expected) || len(source.Ledger) != 97 {
			return report, errors.New("legacy row proof upgraded ledger incomplete")
		}
		applied := make(map[string]bool, len(ledger))
		for _, file := range ledger {
			applied[file] = true
		}
		for file := range expected {
			if !applied[file] {
				return report, errors.New("legacy row proof original migration removed")
			}
		}
	}
	old := make([]string, 0, 35)
	for _, table := range source.Schema.Tables {
		if legacyControlTable(table.Name) {
			old = append(old, table.Name)
		}
	}
	sort.Strings(old)
	if len(old) != 35 {
		return report, errors.New("legacy row proof control set changed")
	}
	remap := make(map[string]string, 35)
	for index, name := range old {
		remap[name] = fmt.Sprintf("dlegacy_%02d_%s", index+1, name[:min(39, len(name))])
	}
	for _, table := range source.Schema.Tables {
		if !legacyControlTable(table.Name) {
			continue
		}
		name := table.Name
		if phase == "after" {
			name = remap[name]
		}
		quoted, e := importIdentifier(name)
		if e != nil {
			return report, e
		}
		var rows uint64
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoted).Scan(&rows) != nil || rows != 0 {
			return report, errors.New("legacy row proof control history not empty")
		}
	}
	migrations := make(map[string]string, len(source.Ledger))
	for _, file := range source.Ledger {
		migrations[file] = "observed-ledger"
	}
	var aggregate []importTableProof
	for _, table := range source.Schema.Tables {
		target := table.Name
		if phase == "after" && remap[target] != "" {
			target = remap[target]
		}
		stable := table
		if table.Name == "llm_models" {
			// 049 backfills a new model_group column, updating updated_at.
			// The source's existing protocol_type values must remain intact.
			stable.Columns = nil
			for _, column := range table.Columns {
				if column != "updated_at" {
					stable.Columns = append(stable.Columns, column)
				}
			}
		}
		item, e := proveLegacy177TableRows(ctx, tx, stable, target, backupImportMap{Migrations: migrations})
		if e != nil {
			return report, e
		}
		aggregate = append(aggregate, item)
		row := LegacySiteRowTableProof{Name: table.Name, Rows: item.Rows, SHA256: item.SHA256}
		if table.Name == "llm_models" {
			full, fullErr := proveLegacy177TableRows(ctx, tx, table, target, backupImportMap{Migrations: migrations})
			if fullErr != nil || full.Rows != item.Rows {
				return report, errors.New("legacy model full row proof unavailable")
			}
			row.FullSHA256 = full.SHA256
			var valid int64
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_models WHERE protocol_type IS NOT NULL AND LENGTH(TRIM(protocol_type)) > 0").Scan(&valid); e != nil || valid != item.Rows {
				return report, errors.New("legacy model existing protocol set changed")
			}
			report.LLMExistingProtocolRows = valid
			if phase == "after" {
				if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_models WHERE BINARY model_group = BINARY display_name").Scan(&valid); e != nil || valid != item.Rows {
					return report, errors.New("legacy model group backfill differs from reviewed transformation")
				}
				report.LLMGroupBackfillRows = valid
			}
		}
		report.Tables = append(report.Tables, row)
	}
	if phase == "after" {
		shape, shapeErr := readImportSchema(ctx, tx)
		if shapeErr != nil {
			return report, shapeErr
		}
		report.UpgradedSchemaSHA256 = importDigest(shape)
		report.UpgradedSchema = &shape
	}
	if err = tx.Commit(); err != nil {
		return report, err
	}
	report.Phase, report.CopyServerUUID, report.CopyDatabase = phase, server, database
	report.SourceInventorySHA, report.SourceSchemaSHA, report.OriginalLedgerSHA = legacySiteInventorySHA, legacySiteSchemaSHA, legacySiteLedgerSHA
	report.PreservationSHA256 = importDigest(aggregate)
	return report, nil
}

func legacy198ReadProofIdentity(server, database string, original bool) bool {
	if server != legacySiteServerUUID {
		return false
	}
	if original {
		return database == "clawmanager"
	}
	return regexpImportDatabase.MatchString(database)
}
func legacy198ReadProofSchema(schema string, original bool) bool {
	if original {
		return schema == legacySiteSchemaSHA
	}
	return schema == legacySiteSchemaSHA || schema == legacyDumpCopySchemaSHA
}
