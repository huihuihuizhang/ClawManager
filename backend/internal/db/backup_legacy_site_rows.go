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
type LegacySiteRowProof struct {
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

type LegacySiteRowTableProof struct {
	Name       string `json:"name"`
	Rows       int64  `json:"rows"`
	SHA256     string `json:"sha256"`
	FullSHA256 string `json:"full_sha256,omitempty"`
}

// ProveLegacySiteCopyRows takes a repeatable-read snapshot of an isolated copy.
// The post-upgrade proof selects only the original columns, and maps the 35
// empty, preserved old control tables to their reviewed dlegacy_* names.
func ProveLegacySiteCopyRows(ctx context.Context, pool *sql.DB, inventoryRaw []byte, phase string) (LegacySiteRowProof, error) {
	var report LegacySiteRowProof
	if ctx == nil || pool == nil || ctx.Err() != nil || (phase != "before" && phase != "after") {
		return report, errors.New("legacy copy row proof unavailable")
	}
	source, err := parseLegacySiteInventory(inventoryRaw)
	if err != nil {
		return report, err
	}
	if phase == "before" {
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
		server != legacySiteServerUUID || !regexpImportDatabase.MatchString(database) {
		return report, errors.New("legacy row proof requires the observed server and an isolated copy")
	}
	ledger, err := readLegacyInventoryLedger(ctx, tx)
	if err != nil {
		return report, err
	}
	if phase == "before" {
		shape, shapeErr := readImportSchema(ctx, tx)
		if shapeErr != nil || (importDigest(shape) != legacySiteSchemaSHA && importDigest(shape) != legacyDumpCopySchemaSHA) || !sameLegacyLedger(ledger, source.Ledger) {
			return report, errors.New("legacy row proof source schema or ledger changed")
		}
	} else {
		if len(ledger) != 189 || len(source.Ledger) != 97 {
			return report, errors.New("legacy row proof upgraded ledger incomplete")
		}
		applied := make(map[string]bool, len(ledger))
		for _, file := range ledger {
			applied[file] = true
		}
		for _, file := range source.Ledger {
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
		item, e := proveImportTable(ctx, tx, stable, target, backupImportMap{Migrations: migrations})
		if e != nil {
			return report, e
		}
		aggregate = append(aggregate, item)
		row := LegacySiteRowTableProof{Name: table.Name, Rows: item.Rows, SHA256: item.SHA256}
		if table.Name == "llm_models" {
			full, fullErr := proveImportTable(ctx, tx, table, target, backupImportMap{Migrations: migrations})
			if fullErr != nil || full.Rows != item.Rows {
				return report, errors.New("legacy model full row proof unavailable")
			}
			row.FullSHA256 = full.SHA256
			var valid int64
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_models WHERE protocol_type IS NOT NULL AND LENGTH(TRIM(protocol_type)) > 0").Scan(&valid); e != nil || valid != item.Rows || valid != 2 {
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
	if err = tx.Commit(); err != nil {
		return report, err
	}
	report.Phase, report.CopyServerUUID, report.CopyDatabase = phase, server, database
	report.SourceInventorySHA, report.SourceSchemaSHA, report.OriginalLedgerSHA = legacySiteInventorySHA, legacySiteSchemaSHA, legacySiteLedgerSHA
	report.PreservationSHA256 = importDigest(aggregate)
	return report, nil
}

func legacyControlTable(name string) bool {
	for _, prefix := range []string{"system_backup", "system_maintenance", "system_restore", "system_artifact"} {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
