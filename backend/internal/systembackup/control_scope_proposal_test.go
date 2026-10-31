package systembackup

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestControlScopeProposalUsesFiniteOriginalClassificationsAndCannotApprove(t *testing.T) {
	observed := []SQLTable{{Name: "system_backup_gate", Columns: []SQLColumn{{Name: "scope", Type: "varchar(64)", Nullable: "NO"}}, PrimaryKey: []string{"scope"}}, {Name: "gateway_runtime_tasks", Columns: []SQLColumn{{Name: "id", Type: "bigint", Nullable: "NO"}}, PrimaryKey: []string{"id"}}}
	p, err := NewControlScopeProposal("original-server", "original_source", strings.Repeat("a", 64), observed)
	if err != nil || p.Status != "draft_requires_independent_owner_review" || p.Tables[0].Policy.Classification != "secret" || p.Tables[1].Policy.Classification != "internal" || p.Tables[0].ReviewStatus != "owner_and_cross_review_required" {
		t.Fatal("original reviewed classifications or draft boundary lost", err)
	}
	reordered := []SQLTable{observed[1], observed[0]}
	other, err := NewControlScopeProposal("original-server", "original_source", strings.Repeat("a", 64), reordered)
	if err != nil || !reflect.DeepEqual(p, other) {
		t.Fatal("proposal depends on input ordering", err)
	}
	observed[0].Columns[0].Type = "varchar(32)"
	changed, err := NewControlScopeProposal("original-server", "original_source", strings.Repeat("a", 64), observed)
	if err != nil || changed.ObservedShapeSHA256 == p.ObservedShapeSHA256 || p.Tables[1].Schema.Columns[0].Type != "varchar(64)" {
		t.Fatal("actual column drift not recorded or draft aliased caller state", err)
	}
	for _, mode := range []string{"unknown", "business", "duplicate", "missing-shape", "bad-key"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(reordered)
			var selected []SQLTable
			json.Unmarshal(raw, &selected)
			switch mode {
			case "unknown":
				selected[0].Name = "system_backup_v2_unreviewed_future_table"
			case "business":
				selected[0].Name = "users"
			case "duplicate":
				selected[1] = selected[0]
			case "missing-shape":
				selected[0].Columns = nil
			case "bad-key":
				selected[0].PrimaryKey = []string{"unknown"}
			}
			if proposal, err := NewControlScopeProposal("original-server", "original_source", strings.Repeat("a", 64), selected); err == nil || proposal.Version != "" {
				t.Fatal("unreviewed or invalid object acquired a control classification", mode)
			}
		})
	}
}
