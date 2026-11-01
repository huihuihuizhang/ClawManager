package systembackup

import (
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/team"
)

func TestImageRestorePreservesUncertainOutcomeAndAccountingHistory(t *testing.T) {
	for _, state := range []string{"preparing", "running", "completed", "failed", "unknown"} {
		t.Run(state, func(t *testing.T) {
			before := team.Row{
				"request_id": team.Value("image-request"), "state": team.Value(state),
				"reservation_id": team.Value("reservation"), "estimate": team.Value("8.12345678"),
				"charge": team.Value("0.12345678"), "settled": team.Value("0"), "analytics_recorded": team.Value("0"),
				"result_metadata": team.Value(`{"artifacts":["image-history"]}`), "error_code": team.Value("provider_timeout"),
				"analytics_context": team.Value(`{"historical":true}`), "analytics_outcome": team.Null(),
			}
			table := SQLTable{Name: "gateway_image_jobs"}
			for name := range before {
				table.Columns = append(table.Columns, SQLColumn{Name: name, Nullable: "YES"})
			}
			change, err := NormalizeDataRow(table, before, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
			if err != nil || !change.Quarantined || !reflect.DeepEqual(change.Before, before) {
				t.Fatal("original accounting evidence lost", err)
			}
			wantState := state
			if state == "preparing" || state == "running" {
				wantState = "failed"
			}
			for name, value := range before {
				want := value
				switch name {
				case "state":
					want = team.Value(wantState)
				case "settled", "analytics_recorded":
					want = team.Value("1")
				}
				if !reflect.DeepEqual(change.After[name], want) {
					t.Fatalf("history changed: %s", name)
				}
			}
			// Target replay suppression is not proof that the original financial
			// event settled. Before retains both false flags, including SQL NULL.
			change.After["charge"].Data[0] = '9'
			if string(before["charge"].Data) != "0.12345678" || string(change.Before["charge"].Data) != "0.12345678" {
				t.Fatal("target aliases source history")
			}
		})
	}
	for _, state := range []team.Cell{team.Null(), team.Value("new_unsupported_state")} {
		if _, err := NormalizeDataRow(SQLTable{Name: "gateway_image_jobs", Columns: []SQLColumn{{Name: "state"}}}, team.Row{"state": state}, time.Now().UTC()); err == nil {
			t.Fatal("unsupported state acquired restore semantics")
		}
	}
}
