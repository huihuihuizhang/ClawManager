package domain

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
)

// Metadata is returned as one bounded four-column row, instead of thousands of network
// authority round trips for individual information_schema cells. All original
// before/after-query and before/after-Next guards still run. Business DATA rows
// retain their original per-row guards, RR transaction and lossless Cell path.
// No source grant, key window, catalog field or full-schema census is relaxed.
const sourceCatalogTables = `SELECT JSON_ARRAYAGG(JSON_OBJECT('table',TABLE_NAME,'engine',COALESCE(ENGINE,''))) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'`
const sourceCatalogColumns = `SELECT JSON_ARRAYAGG(JSON_OBJECT('table',TABLE_NAME,'position',ORDINAL_POSITION,'name',COLUMN_NAME,'type',COLUMN_TYPE,'nullable',IS_NULLABLE,'default',COLUMN_DEFAULT,'extra',EXTRA)) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()`
const sourceCatalogKeys = `SELECT JSON_ARRAYAGG(JSON_OBJECT('table',TABLE_NAME,'name',COLUMN_NAME,'constraint',CONSTRAINT_NAME,'position',ORDINAL_POSITION,'reference_table',REFERENCED_TABLE_NAME,'reference_column',REFERENCED_COLUMN_NAME,'sort',source_order)) FROM (SELECT TABLE_NAME,COLUMN_NAME,CONSTRAINT_NAME,ORDINAL_POSITION,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,ROW_NUMBER() OVER (PARTITION BY TABLE_NAME ORDER BY CONSTRAINT_NAME,ORDINAL_POSITION) AS source_order FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND (CONSTRAINT_NAME='PRIMARY' OR REFERENCED_TABLE_NAME IS NOT NULL)) AS original_keys`
const sourceCatalogUnique = `SELECT JSON_ARRAYAGG(JSON_OBJECT('table',TABLE_NAME,'index',INDEX_NAME,'name',COLUMN_NAME,'position',SEQ_IN_INDEX,'prefix',SUB_PART,'sort',source_order)) FROM (SELECT TABLE_NAME,INDEX_NAME,COLUMN_NAME,SEQ_IN_INDEX,SUB_PART,ROW_NUMBER() OVER (PARTITION BY TABLE_NAME ORDER BY INDEX_NAME,SEQ_IN_INDEX) AS source_order FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('workbuddy_linux_identities','workbuddy_linux_identity_allocator','llm_models','gateway_keys','gateway_key_budget_reservations','gateway_key_budget_ledger','gateway_image_artifacts','gateway_image_jobs','llm_model_user_grants','routing_classifier_settings','northbound_admin_settings','northbound_caller_policies','northbound_owner_records','northbound_settings_audit','northbound_operations') AND NON_UNIQUE=0 AND INDEX_NAME<>'PRIMARY') AS original_unique`

const sourceCatalogBatch = "SELECT (" + sourceCatalogTables + ") AS source_tables,(" + sourceCatalogColumns + ") AS source_columns,(" + sourceCatalogKeys + ") AS source_keys,(" + sourceCatalogUnique + ") AS source_unique"

type sourceCatalogItem struct {
	Table           string  `json:"table"`
	Engine          string  `json:"engine"`
	Position        int     `json:"position"`
	Order           int     `json:"sort"`
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	Nullable        string  `json:"nullable"`
	Default         *string `json:"default"`
	Extra           string  `json:"extra"`
	Constraint      string  `json:"constraint"`
	ReferenceTable  *string `json:"reference_table"`
	ReferenceColumn *string `json:"reference_column"`
	Index           string  `json:"index"`
	Prefix          *int    `json:"prefix"`
}

func readSourceCatalogBatch(ctx context.Context, q queryer, check func() error) ([4][]sourceCatalogItem, error) {
	var zero [4][]sourceCatalogItem
	rows, err := (sourceGuardedQuery{q, check}).QueryContext(ctx, sourceCatalogBatch)
	if err != nil {
		return zero, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || !slices.Equal(columns, []string{"source_tables", "source_columns", "source_keys", "source_unique"}) {
		return zero, ErrSchema
	}
	next, err := sourceRowsNext(ctx, rows, check)
	if err != nil {
		return zero, err
	}
	if !next {
		return zero, ErrSchema
	}
	var raw [4][]byte
	defer func() {
		for _, v := range raw {
			clear(v)
		}
	}()
	if rows.Scan(&raw[0], &raw[1], &raw[2], &raw[3]) != nil {
		return zero, ErrCapacity
	}
	next, err = sourceRowsNext(ctx, rows, check)
	if err != nil {
		return zero, err
	}
	if next || rows.Err() != nil {
		return zero, ErrDatabase
	}
	var groups [4][]sourceCatalogItem
	size := 0
	for i, v := range raw {
		size += len(v)
		if size > 8<<20 {
			return zero, ErrCapacity
		}
		if len(v) == 0 {
			continue
		} // SQL NULL for an empty aggregate
		if json.Unmarshal(v, &groups[i]) != nil || len(groups[i]) > 40000 {
			return zero, ErrSchema
		}
	}
	return groups, nil
}

func catalogBusinessGuarded(ctx context.Context, q queryer, check func() error) ([]Table, error) {
	groups, err := readSourceCatalogBatch(ctx, q, check)
	if err != nil {
		return nil, err
	}
	tableItems := groups[0]
	if len(tableItems) < 1 || len(tableItems) > 1000 {
		return nil, ErrSchema
	}
	sort.Slice(tableItems, func(i, j int) bool { return tableItems[i].Table < tableItems[j].Table })
	tables := make([]Table, len(tableItems))
	byName := map[string]int{}
	for index, item := range tableItems {
		if !identifier.MatchString(item.Table) || index > 0 && tableItems[index-1].Table == item.Table {
			return nil, ErrSchema
		}
		byName[item.Table] = index
		tables[index] = Table{Name: item.Table, Engine: item.Engine}
	}
	for group, statement := range []string{sourceCatalogColumns, sourceCatalogKeys, sourceCatalogUnique} {
		items := groups[group+1]
		sort.Slice(items, func(i, j int) bool {
			a, b := items[i], items[j]
			if a.Table != b.Table {
				return a.Table < b.Table
			}
			if a.Order != b.Order {
				return a.Order < b.Order
			}
			if a.Constraint != b.Constraint {
				return a.Constraint < b.Constraint
			}
			if a.Index != b.Index {
				return a.Index < b.Index
			}
			return a.Position < b.Position
		})
		for _, item := range items {
			index, ok := byName[item.Table]
			if !ok || !identifier.MatchString(item.Name) || item.Position < 1 {
				return nil, ErrSchema
			}
			table := &tables[index]
			switch statement {
			case sourceCatalogColumns:
				if item.Position != len(table.Columns)+1 || len(table.Columns) >= 4096 || item.Nullable != "YES" && item.Nullable != "NO" {
					return nil, ErrSchema
				}
				table.Columns = append(table.Columns, Column{Name: item.Name, Type: item.Type, Nullable: item.Nullable == "YES", Default: item.Default, Extra: item.Extra})
			case sourceCatalogKeys:
				if item.Constraint == "PRIMARY" {
					if item.Position != len(table.PrimaryKey)+1 {
						return nil, ErrSchema
					}
					table.PrimaryKey = append(table.PrimaryKey, item.Name)
				} else {
					if item.ReferenceTable == nil || item.ReferenceColumn == nil || !identifier.MatchString(*item.ReferenceTable) || !identifier.MatchString(*item.ReferenceColumn) {
						return nil, ErrSchema
					}
					table.ForeignKeys = append(table.ForeignKeys, ForeignKey{Column: item.Name, Table: *item.ReferenceTable, Reference: *item.ReferenceColumn})
				}
			case sourceCatalogUnique:
				if item.Prefix != nil || !identifier.MatchString(item.Index) || item.Index == "PRIMARY" || !requiresUniqueCatalog(item.Table) {
					return nil, ErrSchema
				}
				if len(table.UniqueKeys) == 0 || table.UniqueKeys[len(table.UniqueKeys)-1].Name != item.Index {
					table.UniqueKeys = append(table.UniqueKeys, UniqueKey{Name: item.Index})
				}
				key := &table.UniqueKeys[len(table.UniqueKeys)-1]
				if item.Position != len(key.Columns)+1 {
					return nil, ErrSchema
				}
				key.Columns = append(key.Columns, item.Name)
			}
		}
	}
	if sourceReadGuard(ctx, check) != nil {
		return nil, ErrIsolation
	}
	return tables, nil
}
