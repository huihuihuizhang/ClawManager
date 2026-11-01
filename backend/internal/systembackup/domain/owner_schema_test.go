package domain

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOwnerUniqueIndexesSurviveBothCatalogPathsAndBindAdapter(t *testing.T) {
	for _, name := range []string{"gateway_keys", "gateway_key_budget_reservations", "gateway_key_budget_ledger", "gateway_image_artifacts", "gateway_image_jobs", "llm_model_user_grants", "routing_classifier_settings", "northbound_admin_settings", "northbound_caller_policies", "northbound_owner_records", "northbound_settings_audit", "northbound_operations"} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(sourceCatalogUnique, "'"+name+"'") {
				t.Fatal("aggregate query omits owner table")
			}
			shape := Table{Name: name, Engine: "InnoDB", Columns: []Column{{Name: "id", Type: "bigint"}, {Name: "scope_id", Type: "bigint"}, {Name: "key_id", Type: "varchar(64)"}}, PrimaryKey: []string{"id"}, UniqueKeys: []UniqueKey{{Name: "scoped_key", Columns: []string{"scope_id", "key_id"}}}}
			state := &memoryDB{tables: []Table{shape}}
			db := database(state)
			defer db.Close()
			normal, err := Catalog(context.Background(), db)
			if err != nil || len(normal) != 1 || !reflect.DeepEqual(normal[0].UniqueKeys, shape.UniqueKeys) {
				t.Fatal("target catalog lost unique columns/order", err)
			}
			aggregate, err := catalogBusinessGuarded(context.Background(), db, func() error { return nil })
			if err != nil || !reflect.DeepEqual(aggregate, normal) {
				t.Fatal("source catalog lost unique metadata", err)
			}
			adapter := TableAdapter{SchemaSHA256: SchemaDigest(shape), Columns: map[string]string{"id": "preserve", "scope_id": "preserve", "key_id": "preserve"}}
			if adapter.validate(normal[0]) != nil {
				t.Fatal("identical schema differs")
			}
			for _, changed := range [][]UniqueKey{nil, {{Name: "scoped_key", Columns: []string{"key_id", "scope_id"}}}, {{Name: "renamed", Columns: []string{"scope_id", "key_id"}}}, {{Name: "scoped_key", Columns: []string{"scope_id"}}}} {
				other := shape
				other.UniqueKeys = changed
				if adapter.validate(other) == nil {
					t.Fatal("unique constraint drift bypassed exact adapter")
				}
			}
			if state.writes != 0 {
				t.Fatal("metadata inspection wrote business data")
			}
		})
	}
}
