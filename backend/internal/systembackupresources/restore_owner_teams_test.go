package systembackupresources

import (
	"context"
	"reflect"
	"testing"
)

func TestNorthboundOwnerTeamCreationUserRequiresExplicitMapping(t *testing.T) {
	for _, enabled := range []string{"0", "1"} {
		for _, user := range []string{"0", "7"} {
			i := northboundNormalizeFixture()
			i.Source.Rows[0]["owner_teams_enabled"] = fieldString(enabled)
			i.Source.Rows[0]["owner_team_creation_user_id"] = fieldString(user)
			before := cloneRestoreFieldTables([]restoreFieldTable{i.Source})
			got, err := normalizeRestoreNorthbound(context.Background(), i)
			if err != nil {
				t.Fatal(err)
			}
			want := "0"
			if user == "7" {
				want = "17"
			}
			if *got.Table.Rows[0]["owner_teams_enabled"] != "0" || *got.Table.Rows[0]["owner_team_creation_user_id"] != want || !reflect.DeepEqual(before[0], i.Source) {
				t.Fatal("owner team identity lost or source history changed")
			}
		}
	}
	for _, bad := range []*string{nil, fieldString("-1"), fieldString("07"), fieldString("8"), fieldString("2147483648")} {
		i := northboundNormalizeFixture()
		i.Source.Rows[0]["owner_team_creation_user_id"] = bad
		if got, err := normalizeRestoreNorthbound(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) {
			t.Fatal("invalid/unmapped creation identity accepted")
		}
	}
	for _, bad := range []*string{nil, fieldString("2"), fieldString("true")} {
		i := northboundNormalizeFixture()
		i.Source.Rows[0]["owner_teams_enabled"] = bad
		if got, err := normalizeRestoreNorthbound(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) {
			t.Fatal("invalid owner switch accepted")
		}
	}
}

func TestCurrentNorthboundRestoreRejectsMissingOwnerTeamColumns(t *testing.T) {
	i := northboundNormalizeFixture()
	i.Source.Columns = i.Source.Columns[:33]
	delete(i.Source.Rows[0], "owner_teams_enabled")
	delete(i.Source.Rows[0], "owner_team_creation_user_id")
	if _, err := normalizeRestoreNorthbound(context.Background(), i); err == nil {
		t.Fatal("older schema received invented owner defaults")
	}
}
