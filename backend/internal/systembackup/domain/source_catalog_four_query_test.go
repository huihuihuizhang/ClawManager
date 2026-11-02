package domain

// Frozen pre-batch four-query reader, retained only as an independent test oracle.
import (
	"context"
	"encoding/json"
	"sort"
)

func readSourceCatalogAggregateOracle(ctx context.Context, q queryer, statement string, check func() error) ([]sourceCatalogItem, int, error) {
	rows, err := (sourceGuardedQuery{q, check}).QueryContext(ctx, statement)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	next, err := sourceRowsNext(ctx, rows, check)
	if err != nil {
		return nil, 0, err
	}
	if !next {
		return nil, 0, ErrSchema
	}
	var raw []byte
	if rows.Scan(&raw) != nil || len(raw) > 8<<20 {
		return nil, 0, ErrCapacity
	}
	defer clear(raw)
	next, err = sourceRowsNext(ctx, rows, check)
	if err != nil {
		return nil, 0, err
	}
	if next || rows.Err() != nil {
		return nil, 0, ErrDatabase
	}
	if len(raw) == 0 {
		return nil, 0, nil
	} // SQL NULL for an empty aggregate
	var items []sourceCatalogItem
	if json.Unmarshal(raw, &items) != nil || len(items) > 40000 {
		return nil, 0, ErrSchema
	}
	return items, len(raw), nil
}

func catalogBusinessFourQueriesOracle(ctx context.Context, q queryer, check func() error) ([]Table, error) {
	tableItems, size, err := readSourceCatalogAggregateOracle(ctx, q, sourceCatalogTables, check)
	if err != nil {
		return nil, err
	}
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
	for _, statement := range []string{sourceCatalogColumns, sourceCatalogKeys, sourceCatalogUnique} {
		items, bytes, err := readSourceCatalogAggregateOracle(ctx, q, statement, check)
		size += bytes
		if err != nil {
			return nil, err
		}
		if size > 8<<20 {
			return nil, ErrCapacity
		}
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
