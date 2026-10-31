package domain

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
)

func memoryCatalogAggregate(tables []Table, statement string) (driver.Rows, error) {
	var items []sourceCatalogItem
	for _, table := range tables {
		switch statement {
		case sourceCatalogTables:
			items = append(items, sourceCatalogItem{Table: table.Name, Engine: table.Engine})
		case sourceCatalogColumns:
			for index, column := range table.Columns {
				nullable := "NO"
				if column.Nullable {
					nullable = "YES"
				}
				items = append(items, sourceCatalogItem{Table: table.Name, Position: index + 1, Name: column.Name, Type: column.Type, Nullable: nullable, Default: column.Default, Extra: column.Extra})
			}
		case sourceCatalogKeys:
			for index, name := range table.PrimaryKey {
				items = append(items, sourceCatalogItem{Table: table.Name, Name: name, Constraint: "PRIMARY", Position: index + 1})
			}
			for index, key := range table.ForeignKeys {
				refTable, refColumn := key.Table, key.Reference
				items = append(items, sourceCatalogItem{Table: table.Name, Name: key.Column, Constraint: "fk", Position: index + 1, ReferenceTable: &refTable, ReferenceColumn: &refColumn})
			}
		case sourceCatalogUnique:
			if table.Name != "workbuddy_linux_identities" && table.Name != "workbuddy_linux_identity_allocator" {
				continue
			}
			for _, key := range table.UniqueKeys {
				for index, name := range key.Columns {
					items = append(items, sourceCatalogItem{Table: table.Name, Name: name, Index: key.Name, Position: index + 1})
				}
			}
		}
	}
	if statement == sourceCatalogKeys || statement == sourceCatalogUnique {
		counts := map[string]int{}
		for i := range items {
			counts[items[i].Table]++
			items[i].Order = counts[items[i].Table]
		}
	}
	// Deliberately reverse SQL aggregate order: only explicit ordinals and
	// key names may determine the reconstructed original metadata order.
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	return rows([]string{"catalog"}, []driver.Value{raw}), nil
}

func TestBusinessAggregateCatalogPreservesCompleteOriginalShapeAndGuards(t *testing.T) {
	source, _, _ := fixture()
	tables := copyTables(source.Tables)
	defaultValue := "literal 'quoted' default"
	tables = append(tables, Table{Name: "workbuddy_linux_identities", Engine: "InnoDB", Columns: []Column{{Name: "id", Type: "bigint unsigned", Extra: "auto_increment"}, {Name: "uid", Type: "int unsigned", Nullable: true, Default: &defaultValue}}, PrimaryKey: []string{"id"}, UniqueKeys: []UniqueKey{{Name: "uid_unique", Columns: []string{"uid", "id"}}}})
	for i := range tables {
		tables[i].Rows = nil
	}
	state := &memoryDB{tables: tables}
	db := database(state)
	defer db.Close()
	want, err := Catalog(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Name < want[j].Name })
	calls := 0
	got, err := catalogBusinessGuarded(context.Background(), db, func() error { calls++; return nil })
	if err != nil || !reflect.DeepEqual(got, want) || calls > 30 || state.writes != 0 {
		t.Fatal("complete original catalog differed", err, calls)
	}
	for revoke := 1; revoke <= calls; revoke++ {
		seen := 0
		got, err := catalogBusinessGuarded(context.Background(), db, func() error {
			seen++
			if seen >= revoke {
				return errors.New("original authority withdrawn")
			}
			return nil
		})
		if err == nil || got != nil {
			t.Fatalf("revocation at original read boundary %d returned metadata", revoke)
		}
	}
}

func TestBusinessAggregateCaptureKeepsDataRowAndFinalRevocationGuards(t *testing.T) {
	source, _, _ := fixture()
	state := &memoryDB{tables: copyTables(source.Tables)}
	db := database(state)
	defer db.Close()
	calls := 0
	got, err := captureWithCatalog(context.Background(), db, Limits{MaxRows: 100, MaxBytes: 1 << 20}, nil, catalogBusinessGuarded, func() error { calls++; return nil })
	if err != nil || len(got.Tables) == 0 || calls <= 30 {
		t.Fatal("full original RR/data capture", err, calls)
	}
	for _, revoke := range []int{30, calls - 2, calls - 1, calls} {
		seen := 0
		result, err := captureWithCatalog(context.Background(), db, Limits{MaxRows: 100, MaxBytes: 1 << 20}, nil, catalogBusinessGuarded, func() error {
			seen++
			if seen >= revoke {
				return errors.New("authority withdrawn during data read")
			}
			return nil
		})
		if err == nil || len(result.Tables) != 0 {
			t.Fatalf("data/final read revocation %d exposed a partial snapshot", revoke)
		}
	}
}
