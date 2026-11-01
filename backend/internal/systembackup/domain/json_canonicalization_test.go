package domain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestJSONCastFailureAndCancellationPrecedeAllBusinessWrites(t *testing.T) {
	for _, mode := range []string{"failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			source, _, policy := operationRestoreFixture()
			for i := range source.Tables {
				if source.Tables[i].Name != "northbound_operations" {
					continue
				}
				for j := range source.Tables[i].Columns {
					if source.Tables[i].Columns[j].Name == "request_payload" {
						source.Tables[i].Columns[j].Type = "json"
					}
				}
				a := policy.Dependencies["northbound_operations"]
				a.SchemaSHA256 = SchemaDigest(source.Tables[i])
				policy.Dependencies["northbound_operations"] = a
			}
			state := isolatedTarget(copyTables(source.Tables))
			state.rollbackDone = make(chan struct{})
			db := database(state)
			defer db.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state.castJSON = func(c context.Context, _ string) (string, error) {
				if state.writes != 0 {
					t.Error("business write preceded CAST")
				}
				if mode == "cancel" {
					cancel()
					return "", c.Err()
				}
				return "", errors.New("injected native CAST failure")
			}
			beforeTarget, _ := Digest(Snapshot{Version: Version, Tables: copyTables(state.tables)})
			beforeSource, _ := Digest(source)
			evidenceCalls := 0
			target := DrillTarget{Database: state.name, ServerUUID: state.uuid, CheckIsolation: func(c context.Context) error { return c.Err() }}
			_, err := RestoreDrillWithEvidence(ctx, db, target, source, policy, func(context.Context, RestorePlan) error { evidenceCalls++; return nil })
			select {
			case <-state.rollbackDone:
			case <-time.After(5 * time.Second):
				t.Fatal("transaction rollback did not finish")
			}
			afterTarget, _ := Digest(Snapshot{Version: Version, Tables: copyTables(state.tables)})
			afterSource, _ := Digest(source)
			if err == nil || state.castQueries != 1 || state.writes != 0 || state.commits != 0 || evidenceCalls != 0 || beforeTarget != afterTarget || beforeSource != afterSource {
				t.Fatal("CAST failure/cancellation failed to stop before all writes", err, state.castQueries, state.writes, evidenceCalls)
			}
		})
	}
}

// Called only by the opt-in disposable MySQL test. Rendering itself is tested
// against the real engine, not reimplemented in the in-memory SQL fixture.
func testNativeJSONCanonicalization(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	values := []Cell{{Null: true}, Text("null"), Text("{ }"), Text("[ ]"), Text(`{ "n": 9007199254740993, "max": 9223372036854775807, "u": 18446744073709551615 }`)}
	source := Snapshot{Version: Version, Tables: []Table{{Name: "native_json_boundary_fixture", Columns: []Column{{Name: "document", Type: "json", Nullable: true}, {Name: "text_document", Type: "text", Nullable: true}}}}}
	for _, value := range values {
		source.Tables[0].Rows = append(source.Tables[0].Rows, Row{"document": value, "text_document": value})
	}
	before, _ := Digest(source)
	plan := RestorePlan{Data: Snapshot{Version: Version, Tables: copyTables(source.Tables)}}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := canonicalizeTargetJSON(ctx, tx, &plan); err != nil {
		t.Fatal("native CAST", err)
	}
	rows := plan.Data.Tables[0].Rows
	if !rows[0]["document"].Null || len(rows[0]["document"].Bytes) != 0 || rows[1]["document"].Null || rows[1]["document"].String() != "null" || rows[2]["document"].String() != "{}" || rows[3]["document"].String() != "[]" {
		t.Fatal("SQL NULL, JSON null, empty object or array conflated")
	}
	decoder := json.NewDecoder(strings.NewReader(rows[4]["document"].String()))
	decoder.UseNumber()
	var numbers map[string]json.Number
	if decoder.Decode(&numbers) != nil || numbers["n"].String() != "9007199254740993" || numbers["max"].String() != "9223372036854775807" || numbers["u"].String() != "18446744073709551615" {
		t.Fatal("JSON integer precision lost")
	}
	for i, row := range rows {
		if !reflect.DeepEqual(row["text_document"], values[i]) {
			t.Fatal("TEXT column changed")
		}
	}
	after, _ := Digest(source)
	if before != after || source.Tables[0].Rows[2]["document"].String() != "{ }" {
		t.Fatal("source snapshot mutated")
	}
	for _, mode := range []string{"invalid-json", "canceled-context"} {
		bad := RestorePlan{Data: Snapshot{Tables: []Table{{Columns: []Column{{Name: "document", Type: "json"}}, Rows: []Row{{"document": Text("{")}}}}}}
		callCtx := ctx
		if mode == "canceled-context" {
			var cancel context.CancelFunc
			callCtx, cancel = context.WithCancel(ctx)
			cancel()
			bad.Data.Tables[0].Rows[0]["document"] = Text("{}")
		}
		if canonicalizeTargetJSON(callCtx, tx, &bad) == nil {
			t.Fatal("native CAST accepted", mode)
		}
	}
}
