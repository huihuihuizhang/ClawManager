package domain_test

import (
	"bytes"
	"database/sql"
	"testing"

	"clawreef/internal/systembackup/domain"
)

// The existing small history table fixtures receive the real migration 052
// nullable BIGINT column/index. This tests nonempty SQL custody, not a complete
// production history schema or fullC authentication.
func seedNativeGatewayAttributionHistory(t *testing.T, f *gatewayNative, db *sql.DB) {
	t.Helper()
	for _, name := range []string{"model_invocations", "audit_events", "cost_records"} {
		f.exec(db, "INSERT INTO `"+name+"`(id,gateway_key_id) VALUES (31,9223372036854775807),(32,NULL),(33,777),(34,9223372036854775806)")
	}
	f.exec(db, "UPDATE model_invocations SET status='completed'")
	f.exec(db, "UPDATE model_invocations SET prompt_tokens=1,completion_tokens=2,total_tokens=3,created_at='2024-01-02 03:04:05' WHERE id=34")
	f.exec(db, "UPDATE cost_records SET currency='USD',estimated_cost=0.00000001 WHERE id=34")
	t.Log("actual source history seeded: each of model_invocations/audit_events/cost_records has max signed BIGINT, SQL NULL, deleted key 777 and retained key attribution; real migration052 adds no FK")
}

func validateNativeGatewayAttributionHistory(t *testing.T, original, actual domain.Snapshot) {
	t.Helper()
	for _, snapshot := range []domain.Snapshot{original, actual} {
		for _, row := range nativeGatewayTable(snapshot, "gateway_keys").Rows {
			if id := row["id"].String(); id == "777" || id == "9223372036854775807" {
				t.Fatal("native orphan history accidentally has a current key")
			}
		}
	}
	for _, name := range []string{"model_invocations", "audit_events", "cost_records"} {
		expected, got := nativeGatewayTable(original, name), nativeGatewayTable(actual, name)
		if len(expected.Rows) != 4 || len(got.Rows) != len(expected.Rows) || len(expected.ForeignKeys) != 0 || len(got.ForeignKeys) != 0 || domain.SchemaDigest(expected) != domain.SchemaDigest(got) {
			t.Fatal("nonempty native attribution shape/row count changed", name)
		}
		found := false
		for _, column := range got.Columns {
			if column.Name == "gateway_key_id" {
				found = column.Type == "bigint" && column.Nullable
			}
		}
		if !found {
			t.Fatal("actual migration052 attribution type/NULL changed", name)
		}
		byID := map[string]domain.Row{}
		for _, row := range got.Rows {
			if byID[row["id"].String()] != nil {
				t.Fatal("duplicate native history row", name)
			}
			byID[row["id"].String()] = row
		}
		for _, row := range expected.Rows {
			other := byID[row["id"].String()]
			if len(other) != len(row) {
				t.Fatal("native history row lost", name)
			}
			for column, value := range row {
				cell, ok := other[column]
				if !ok || cell.Null != value.Null || !bytes.Equal(cell.Bytes, value.Bytes) {
					t.Fatal("native history raw cell changed", name, column)
				}
			}
		}
		for id, want := range map[string]domain.Cell{"31": domain.Text("9223372036854775807"), "32": {Null: true}, "33": domain.Text("777"), "34": domain.Text("9223372036854775806")} {
			cell := byID[id]["gateway_key_id"]
			if cell.Null != want.Null || !bytes.Equal(cell.Bytes, want.Bytes) {
				t.Fatal("native deleted/NULL/max attribution changed or linked", name, id)
			}
		}
		t.Logf("actual independent SELECT-only history readback %s: 4 nonempty rows; max signed BIGINT/NULL/deleted key/retained key and every raw cell preserved; no FK added PASS", name)
	}
}

func validateNativeGatewayHistoryRollback(t *testing.T, f *gatewayNative, reader *sql.DB, mode string) {
	t.Helper()
	for _, name := range []string{"model_invocations", "audit_events", "cost_records"} {
		var count int
		if reader.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM `"+name+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("nonempty native history did not roll back", name, mode)
		}
	}
	t.Logf("actual public native case=%s: all three history tables rolled back to zero rows PASS", mode)
}
