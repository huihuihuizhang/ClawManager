package domain

import (
	"context"
	"testing"
)

func TestSourceAwarePreflightRejectsIncompatibleRestoreWithoutWrites(t *testing.T) {
	for _, name := range []string{"valid", "missing-table", "changed-column", "missing-placement", "wrong-owner", "workbuddy-without-adapter", "nonempty-target"} {
		t.Run(name, func(t *testing.T) {
			s, catalog, p := fixture()
			state := isolatedTarget(catalog)
			switch name {
			case "missing-table":
				state.tables = append(state.tables[:2], state.tables[3:]...)
			case "changed-column":
				state.tables[2].Columns = append([]Column(nil), state.tables[2].Columns...)
				state.tables[2].Columns[0].Type = "unsupported"
			case "missing-placement":
				p.Placements = nil
			case "wrong-owner":
				s.Tables[2].Rows[0]["user_id"] = Text("999")
			case "workbuddy-without-adapter":
				s.Tables[2].Rows[0]["type"] = Text("workbuddy")
			case "nonempty-target":
				state.tables[2].Rows = s.Tables[2].Rows
			}
			db := database(state)
			defer db.Close()
			before, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			sourceBefore, _ := Digest(s)
			e := PreflightRestoreDrill(context.Background(), db, targetProof(), s, p)
			if (e == nil) != (name == "valid") {
				t.Fatalf("unexpected preflight: %v", e)
			}
			after, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			sourceAfter, _ := Digest(s)
			if before != after || sourceBefore != sourceAfter || state.writes != 0 || state.commits != 0 || state.readOnlyBegins == 0 {
				t.Fatal("preflight mutated source/target or used a writable transaction")
			}
		})
	}
}
