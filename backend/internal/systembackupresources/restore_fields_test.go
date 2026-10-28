package systembackupresources

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fieldString(value string) *string { return &value }

func fieldFixture() []restoreFieldTable {
	var tables []restoreFieldTable
	for name, columns := range restoreFieldColumns() {
		row := restoreFieldRow{}
		for _, column := range columns {
			row[column] = fieldString("source-secret:" + column)
		}
		row["id"] = fieldString("1")
		tables = append(tables, restoreFieldTable{name, columns, []restoreFieldRow{row}})
	}
	return tables
}

func fieldTable(tables []restoreFieldTable, name string) *restoreFieldTable {
	for i := range tables {
		if tables[i].Name == name {
			return &tables[i]
		}
	}
	panic("fixture table missing")
}

var fieldTestBudget = restoreFieldBudget{Rows: 100, Bytes: 100000}

func TestRestoreFieldsEveryColumn(t *testing.T) {
	for name, columns := range restoreFieldColumns() {
		for _, column := range columns {
			t.Run(name+"/"+column, func(t *testing.T) {
				expected, observed := fieldFixture(), fieldFixture()
				if err := compareRestoreFields(context.Background(), expected, observed, fieldTestBudget); err != nil {
					t.Fatal(err)
				}
				fieldTable(observed, name).Rows[0][column] = fieldString("changed-secret")
				err := compareRestoreFields(context.Background(), expected, observed, fieldTestBudget)
				if err == nil || strings.Contains(err.Error(), "secret") {
					t.Fatalf("missing or unsafe rejection: %v", err)
				}
			})
		}
	}
}

func TestRestoreFieldsStructure(t *testing.T) {
	cases := map[string]func([]restoreFieldTable) []restoreFieldTable{
		"missing_table":      func(x []restoreFieldTable) []restoreFieldTable { return x[1:] },
		"extra_table":        func(x []restoreFieldTable) []restoreFieldTable { return append(x, x[0]) },
		"duplicate_table":    func(x []restoreFieldTable) []restoreFieldTable { x[0] = x[1]; return x },
		"unknown_table":      func(x []restoreFieldTable) []restoreFieldTable { x[0].Name = "users"; return x },
		"missing_column":     func(x []restoreFieldTable) []restoreFieldTable { x[0].Columns = x[0].Columns[1:]; return x },
		"duplicate_column":   func(x []restoreFieldTable) []restoreFieldTable { x[0].Columns[0] = x[0].Columns[1]; return x },
		"unknown_column":     func(x []restoreFieldTable) []restoreFieldTable { x[0].Columns[0] = "unknown"; return x },
		"missing_row_column": func(x []restoreFieldTable) []restoreFieldTable { delete(x[0].Rows[0], "created_at"); return x },
		"extra_row_column":   func(x []restoreFieldTable) []restoreFieldTable { x[0].Rows[0]["unknown"] = nil; return x },
		"missing_row":        func(x []restoreFieldTable) []restoreFieldTable { x[0].Rows = nil; return x },
		"extra_row": func(x []restoreFieldTable) []restoreFieldTable {
			row := restoreFieldRow{}
			for k, v := range x[0].Rows[0] {
				row[k] = v
			}
			row["id"] = fieldString("2")
			x[0].Rows = append(x[0].Rows, row)
			return x
		},
		"duplicate_id": func(x []restoreFieldTable) []restoreFieldTable { x[0].Rows = append(x[0].Rows, x[0].Rows[0]); return x },
	}
	for name, mutate := range cases {
		for _, side := range []string{"expected", "observed"} {
			t.Run(name+"/"+side, func(t *testing.T) {
				a, b := fieldFixture(), fieldFixture()
				if side == "expected" {
					a = mutate(a)
				} else {
					b = mutate(b)
				}
				if err := compareRestoreFields(context.Background(), a, b, fieldTestBudget); err == nil {
					t.Fatal("accepted malformed row set")
				}
			})
		}
	}
}

func TestRestoreFieldsNullAndLosslessValues(t *testing.T) {
	for _, pair := range [][2]*string{
		{nil, fieldString("")}, {fieldString(""), nil},
		{fieldString("2.00"), fieldString("2.01")},
		{fieldString("9007199254740992"), fieldString("9007199254740993")},
		{fieldString("2026-10-23 00:00:00.000001"), fieldString("2026-10-23 00:00:00.000002")},
		{fieldString(`null`), nil}, {fieldString(`"[REDACTED]"`), fieldString(`{"Config":"secret"}`)},
	} {
		a, b := fieldFixture(), fieldFixture()
		fieldTable(a, "audit_logs").Rows[0]["details"] = pair[0]
		fieldTable(b, "audit_logs").Rows[0]["details"] = pair[1]
		if compareRestoreFields(context.Background(), a, b, fieldTestBudget) == nil {
			t.Fatal("lossy comparison accepted")
		}
	}
	a, b := fieldFixture(), fieldFixture()
	fieldTable(a, "audit_logs").Rows[0]["details"] = nil
	fieldTable(b, "audit_logs").Rows[0]["details"] = nil
	if err := compareRestoreFields(context.Background(), a, b, fieldTestBudget); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreFieldsIDsBudgetsAndEmptyTables(t *testing.T) {
	for _, id := range []string{"", "0", "-1", "01", "+1", "1.0", "2147483648", "9223372036854775808"} {
		a := fieldFixture()
		fieldTable(a, "audit_logs").Rows[0]["id"] = fieldString(id)
		if compareRestoreFields(context.Background(), a, a, fieldTestBudget) == nil {
			t.Fatalf("accepted id %q", id)
		}
	}
	a := fieldFixture()
	fieldTable(a, "northbound_settings_audit").Rows[0]["id"] = fieldString("9223372036854775807")
	if err := compareRestoreFields(context.Background(), a, a, fieldTestBudget); err != nil {
		t.Fatal(err)
	}
	for _, budget := range []restoreFieldBudget{{0, 1}, {1, 0}, {-1, 100}, {8, 100000}, {100, 1}} {
		if compareRestoreFields(context.Background(), a, a, budget) == nil {
			t.Fatal("accepted exhausted budget")
		}
	}
	for i := range a {
		a[i].Rows = nil
	}
	if err := compareRestoreFields(context.Background(), a, a, fieldTestBudget); err != nil {
		t.Fatal(err)
	}
	a[0].Columns = nil
	if compareRestoreFields(context.Background(), a, a, fieldTestBudget) == nil {
		t.Fatal("empty table bypassed columns")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(compareRestoreFields(ctx, nil, nil, fieldTestBudget), context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestRestoreFieldsRowAndColumnOrder(t *testing.T) {
	a, b := fieldFixture(), fieldFixture()
	for _, set := range [][]restoreFieldTable{a, b} {
		for i := range set {
			row := restoreFieldRow{}
			for k, v := range set[i].Rows[0] {
				row[k] = v
			}
			row["id"] = fieldString("2")
			set[i].Rows = append(set[i].Rows, row)
		}
	}
	for i := range b {
		b[i].Rows[0], b[i].Rows[1] = b[i].Rows[1], b[i].Rows[0]
		for l, r := 0, len(b[i].Columns)-1; l < r; l, r = l+1, r-1 {
			b[i].Columns[l], b[i].Columns[r] = b[i].Columns[r], b[i].Columns[l]
		}
	}
	if err := compareRestoreFields(context.Background(), a, b, fieldTestBudget); err != nil {
		t.Fatal(err)
	}
}
