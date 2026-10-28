package systembackupresources

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func restoreFiveFixture() restoreFiveInput {
	i := restoreFiveInput{auditNormalizeFixture(), egressNormalizeFixture(), imageNormalizeFixture(), northboundNormalizeFixture(), fieldTestBudget}
	// These two migration columns are TIMESTAMP(0), unlike northbound's
	// DATETIME(6). Keep fixture bytes representable by the actual SQL types.
	i.Egress.Source.Rows[0]["updated_at"] = fieldString("2026-10-22 01:02:03")
	i.Images.Source.Rows[0]["updated_at"] = fieldString("2026-10-22 01:02:03")
	return i
}

func restoreFiveReadbackShape(tables []restoreFieldTable) []restoreFieldTable {
	shape := cloneRestoreFieldTables(tables)
	for name, columns := range restoreFieldColumns() {
		if strings.HasPrefix(name, "security_scan_") {
			shape = append(shape, restoreFieldTable{Name: name, Columns: columns})
		}
	}
	return shape
}

func TestRestoreFiveCompositionThroughReadback(t *testing.T) {
	i := restoreFiveFixture()
	got, err := normalizeRestoreFive(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tables) != 5 || len(got.AuditHistory) != 2 || *got.SourceAuditMaxID != 1 || *got.SourceNorthboundVersion != 77 || *got.ObservedNorthboundVersion != 5 {
		t.Fatal("five-table history/shape differs")
	}
	expected := restoreFiveReadbackShape(got.Tables)
	db, state := readbackDB(t)
	state.field.tables = cloneRestoreFieldTables(expected)
	if err := verifyRestoreReadback(context.Background(), db, frozenRegistryBytes(t), expected, i.Budget, readbackProofs()); err != nil {
		t.Fatal(err)
	}
	if state.begins != 1 || state.field.base.commits != 1 {
		t.Fatal("composition did not finish one transaction")
	}
	for _, table := range got.Tables {
		for _, row := range table.Rows {
			for _, value := range row {
				if value != nil && strings.Contains(*value, "private-secret") {
					t.Fatal("source secret survived composition")
				}
			}
			for _, flag := range []string{"enabled", "is_enabled", "api_enabled"} {
				if value, ok := row[flag]; ok && (value == nil || *value != "0") {
					t.Fatal("candidate enabled a service")
				}
			}
		}
	}
	// Exercise each candidate's actual output in the SQL-reader/comparator seam,
	// including BIGINT audit identity, mapped FK, version, decimal and JSON text.
	for _, table := range got.Tables {
		for column := range table.Rows[0] {
			if column == "id" {
				continue
			}
			t.Run(table.Name+"/"+column, func(t *testing.T) {
				changed := cloneRestoreFieldTables(expected)
				for j := range changed {
					if changed[j].Name == table.Name {
						changed[j].Rows[0][column] = fieldString("unexpected-target")
					}
				}
				localDB, localState := readbackDB(t)
				localState.field.tables = changed
				if err := verifyRestoreReadback(context.Background(), localDB, frozenRegistryBytes(t), expected, i.Budget, readbackProofs()); err == nil || localState.field.base.commits != 0 {
					t.Fatal("changed candidate field accepted")
				}
			})
		}
	}
}

func TestRestoreFiveCombinedBudgetAndAtomicFailure(t *testing.T) {
	for _, mode := range []string{"source_rows", "source_bytes", "output_bytes", "late_northbound", "wrong_table", "split_user_mapping", "split_instance_mapping", "merged_user_mapping", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			i := restoreFiveFixture()
			ctx := context.Background()
			switch mode {
			case "source_rows":
				i.Budget.Rows = 4
			case "source_bytes":
				i.Budget.Bytes = 10
			case "output_bytes":
				// Each table alone fits, but their combined retained output does not.
				i.Images.Targets[0].DisplayName = strings.Repeat("x", 255)
				var n int64
				for _, table := range []restoreFieldTable{i.Audit.Audit, i.Audit.Northbound, i.Egress.Source, i.Images.Source, i.Northbound.Source} {
					for _, row := range table.Rows {
						for _, v := range row {
							if v != nil {
								n += int64(len(*v))
							}
						}
					}
				}
				i.Budget.Bytes = n
			case "late_northbound":
				i.Northbound.Policy = nil
			case "wrong_table":
				i.Egress.Source.Name = "security_scan_configs"
			case "split_user_mapping":
				i.Northbound.Bindings[0].Target = 18
			case "split_instance_mapping":
				i.Egress.Bindings[1].Target = 28
			case "merged_user_mapping":
				i.Northbound.Bindings = []restoreIDBinding{{restoreUserID, 8, 17}}
				i.Northbound.Source.Rows[0]["updated_by"] = fieldString("8")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := normalizeRestoreFive(ctx, i)
			if err == nil || !reflect.DeepEqual(got, restoreFiveCandidate{}) {
				t.Fatal("failed composition emitted a partial candidate")
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation")
			}
		})
	}
}
