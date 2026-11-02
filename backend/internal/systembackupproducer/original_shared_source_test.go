package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Component SQL protocol coverage: actual closed codec and parameterized
// database/sql dispatch, not native privilege, gap-lock or deployment proof.
func TestOriginalSharedSourceClosedRecords(t *testing.T) {
	for _, fixture := range fixtures(t).Records {
		for _, exists := range []bool{false, true} {
			t.Run(fixture.Definition+map[bool]string{false: "/absent", true: "/present"}[exists], func(t *testing.T) {
				runner, state, _ := setupTx(t)
				record := recordFixture(t, fixture.Definition)
				scope := reflect.ValueOf(record).Elem().FieldByName("Scope").Interface().(Scope)
				queries := 0
				state.queryRecord = func(query string, args []driver.NamedValue) (driver.Rows, error) {
					queries++
					if !strings.HasSuffix(query, " FOR SHARE") {
						t.Fatal("original reader needs only SELECT sharing locks", query)
					}
					assertRecordQuery(t, strings.TrimSuffix(query, " FOR SHARE")+" FOR UPDATE", args, record)
					definition, _ := storageFor(record)
					if !strings.HasPrefix(query, "SELECT "+strings.Join(recordColumns(definition), ", ")+" FROM ") {
						t.Fatal("partial projection")
					}
					return rowsForRecord(t, record, exists), nil
				}
				out := destination(fixture.Definition)
				found, err := ReadOriginalSharedRecord(context.Background(), runner.db, scope, keyForRecord(record), out)
				if err != nil || found != exists || queries != 1 || exists && !reflect.DeepEqual(out, record) {
					t.Fatal("closed source read", found, err, queries)
				}
				if state.commits != 0 || state.rollbacks != 0 {
					t.Fatal("data-only reader owned a transaction")
				}
			})
		}
	}
}

func TestOriginalSharedSourceRejectsCorruptionAndIncompleteEOF(t *testing.T) {
	for _, mode := range []string{"bytes", "digest", "scope_projection", "wrong_key", "duplicate", "columns", "iteration", "close", "query"} {
		t.Run(mode, func(t *testing.T) {
			runner, state, _ := setupTx(t)
			record := recordFixture(t, "GrantRecord")
			scope := record.(*GrantRecord).Scope
			state.queryRecord = func(_ string, _ []driver.NamedValue) (driver.Rows, error) {
				if mode == "query" {
					return nil, errors.New("controlled read failure")
				}
				rows := rowsForRecord(t, record, true)
				column := func(name string, value driver.Value) {
					t.Helper()
					for n, key := range rows.names {
						if key == name {
							rows.data[0][n] = value
							return
						}
					}
					t.Fatal("missing exact projection", name)
				}
				switch mode {
				case "bytes":
					column("record_bytes", []byte("{}"))
				case "digest":
					column("record_sha256", make([]byte, 32))
				case "scope_projection":
					column("scope_key", strings.Repeat("f", 64))
				case "duplicate":
					rows.data = append(rows.data, rows.data[0])
				case "columns":
					rows.names = append([]string(nil), rows.names...)
					rows.names[0] = "unexpected"
				case "iteration":
					rows.nextError = errors.New("controlled EOF failure")
				case "close":
					rows.closeError = errors.New("controlled close failure")
				}
				return rows, nil
			}
			key := keyForRecord(record)
			if mode == "wrong_key" {
				key.ID = "another-original-grant"
			}
			out := &GrantRecord{}
			if found, err := ReadOriginalSharedRecord(context.Background(), runner.db, scope, key, out); err == nil || found || !reflect.DeepEqual(out, &GrantRecord{}) {
				t.Fatal("corrupt original source accepted or destination changed", found, err)
			}
		})
	}
}
