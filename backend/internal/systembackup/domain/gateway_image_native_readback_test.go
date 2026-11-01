package domain_test

import (
	"bytes"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
)

func validateNativeImageRawCells(t *testing.T, original, actual domain.Snapshot) {
	t.Helper()
	for _, name := range []string{"gateway_keys", "gateway_key_budget_reservations", "gateway_key_budget_ledger", "gateway_image_artifacts", "gateway_image_jobs"} {
		expected, got := nativeGatewayTable(original, name), nativeGatewayTable(actual, name)
		if domain.SchemaDigest(expected) != domain.SchemaDigest(got) || len(expected.Rows) != len(got.Rows) {
			t.Fatal("native image owner schema/row loss", name)
		}
		key := func(row domain.Row) string {
			var values []string
			for _, column := range expected.PrimaryKey {
				values = append(values, row[column].String())
			}
			return strings.Join(values, "\x00")
		}
		byID := map[string]domain.Row{}
		for _, row := range got.Rows {
			if byID[key(row)] != nil {
				t.Fatal("native owner duplicate PK", name)
			}
			byID[key(row)] = row
		}
		for _, row := range expected.Rows {
			other := byID[key(row)]
			if len(other) != len(row) {
				t.Fatal("native image owner raw row lost", name)
			}
			for column, want := range row {
				if name == "gateway_keys" && row["status"].String() != "revoked" && (column == "status" || column == "revoked_at" || column == "revoked_by_user_id" || column == "revocation_reason" || column == "updated_at") {
					continue
				}
				if name == "gateway_image_artifacts" && column == "ready" {
					if other[column].String() != "0" {
						t.Fatal("native artifact remains ready")
					}
					continue
				}
				if name == "gateway_image_jobs" {
					if column == "state" && (want.String() == "running" || want.String() == "preparing") {
						expectedState := "unknown"
						if want.String() == "preparing" {
							expectedState = "failed"
						}
						if other[column].String() != expectedState {
							t.Fatal("native interrupted image state")
						}
						continue
					}
					if column == "settled" || column == "analytics_recorded" {
						if other[column].String() != "1" {
							t.Fatal("native replay flag remains active")
						}
						continue
					}
					if column == "updated_at" && (row["state"].String() == "running" || row["state"].String() == "preparing" || row["settled"].String() != "1" || row["analytics_recorded"].String() != "1") {
						continue
					}
				}
				cell, ok := other[column]
				if !ok || cell.Null != want.Null || !bytes.Equal(cell.Bytes, want.Bytes) {
					t.Fatal("native owner raw cell changed", name, column)
				}
			}
		}
	}
	t.Log("independent native raw-cell comparison: all five owner tables, binary32 key including NUL/0xff, HMAC, DECIMAL/NULL, retained image_pending, GC artifact-ID tombstone and cascaded old key/reservation/instance IDs preserved; only named quarantine markers changed PASS")
}
