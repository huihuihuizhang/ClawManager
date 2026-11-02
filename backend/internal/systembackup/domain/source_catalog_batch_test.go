package domain

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validBatchValues() []driver.Value {
	return []driver.Value{
		[]byte(`[{"table":"users","engine":"InnoDB"}]`),
		[]byte(`[{"table":"users","position":1,"name":"id","type":"bigint unsigned","nullable":"NO","default":null,"extra":"auto_increment"}]`),
		[]byte(`[{"table":"users","name":"id","constraint":"PRIMARY","position":1}]`),
		nil, // real SQL NULL for no secondary unique keys
	}
}

func TestBusinessCatalogBatchMalformedAndBudget(t *testing.T) {
	for _, mode := range []string{"query-error", "next-error", "scan-error", "missing-row", "extra-row", "missing-column", "wrong-column", "json-tables", "json-columns", "json-keys", "json-unique", "array-items", "array-bytes", "total-bytes"} {
		t.Run(mode, func(t *testing.T) {
			state := &memoryDB{}
			state.sourceQuery = func(q string) (driver.Rows, bool, error) {
				if q != sourceCatalogBatch {
					return nil, false, nil
				}
				columns := []string{"source_tables", "source_columns", "source_keys", "source_unique"}
				values := validBatchValues()
				switch mode {
				case "query-error":
					return nil, true, errors.New("query failed")
				case "next-error":
					return catalogBatchErrorRows{}, true, nil
				case "scan-error":
					values[0] = struct{}{}
				case "missing-row":
					return rows(columns), true, nil
				case "extra-row":
					return rows(columns, values, values), true, nil
				case "missing-column":
					return rows(columns[:3], values[:3]), true, nil
				case "wrong-column":
					columns[3] = "untrusted"
				case "json-tables":
					values[0] = []byte("{")
				case "json-columns":
					values[1] = []byte("{")
				case "json-keys":
					values[2] = []byte("{")
				case "json-unique":
					values[3] = []byte("{")
				case "array-items":
					values[2] = []byte("[" + strings.TrimSuffix(strings.Repeat("{},", 40001), ",") + "]")
				case "array-bytes":
					values[0] = []byte(strings.Repeat(" ", (8<<20)+1))
				case "total-bytes":
					for i := range values {
						if values[i] == nil {
							values[i] = []byte("null")
						}
						values[i] = append(append([]byte(nil), values[i].([]byte)...), []byte(strings.Repeat(" ", 2<<20))...)
					}
				}
				return rows(columns, values), true, nil
			}
			db := database(state)
			defer db.Close()
			got, err := catalogBusinessGuarded(context.Background(), db, nil)
			if err == nil || got != nil {
				t.Fatal("malformed or oversized catalog accepted", mode)
			}
			if (mode == "array-bytes" || mode == "total-bytes" || mode == "scan-error") && !errors.Is(err, ErrCapacity) {
				t.Fatal("capacity error category changed", mode, err)
			}
			if mode == "array-items" && !errors.Is(err, ErrSchema) {
				t.Fatal("item count error category changed", err)
			}
		})
	}
}

type catalogBatchErrorRows struct{}

func (catalogBatchErrorRows) Columns() []string {
	return []string{"source_tables", "source_columns", "source_keys", "source_unique"}
}
func (catalogBatchErrorRows) Close() error              { return nil }
func (catalogBatchErrorRows) Next([]driver.Value) error { return errors.New("batch read failed") }

func TestBusinessCatalogBatchCancelDeadlineAndSQLNull(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline", "null-aggregates"} {
		t.Run(mode, func(t *testing.T) {
			state := &memoryDB{}
			state.sourceQuery = func(string) (driver.Rows, bool, error) {
				return rows([]string{"source_tables", "source_columns", "source_keys", "source_unique"}, validBatchValues()), true, nil
			}
			db := database(state)
			defer db.Close()
			ctx := context.Background()
			if mode == "canceled" {
				bounded, cancel := context.WithCancel(ctx)
				cancel()
				ctx = bounded
			}
			if mode == "deadline" {
				bounded, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				ctx = bounded
			}
			got, err := catalogBusinessGuarded(ctx, db, nil)
			if mode != "null-aggregates" {
				if err == nil || got != nil || len(state.queries) != 0 {
					t.Fatal("inactive authority read catalog", mode)
				}
			} else if err != nil || len(got) != 1 || got[0].Columns[0].Default != nil || len(got[0].UniqueKeys) != 0 {
				t.Fatal("SQL NULL metadata changed", err)
			}
		})
	}
}

func TestBusinessCatalogBatchFourQuerySnapshotOracle(t *testing.T) {
	seed, _, _ := fixture()
	state := countFixture(seed.Tables)
	db := database(state)
	defer db.Close()
	limits := Limits{MaxRows: 100, MaxBytes: 1 << 20}
	want, err := captureWithCatalogMode(context.Background(), db, limits, nil, catalogBusinessFourQueriesOracle, true)
	if err != nil {
		t.Fatal("four-query oracle", err)
	}
	state.queries = nil
	got, err := captureWithCatalogMode(context.Background(), db, limits, nil, catalogBusinessGuarded, true)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("full original snapshot changed", err)
	}
	queries := 0
	for _, q := range state.queries {
		if q == sourceCatalogBatch {
			queries++
		}
	}
	if queries != 2 {
		t.Fatal("COUNT must retain both full metadata reads", queries)
	}
}
