package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/team"
)

func TestPublicTeamsReaderSharesAuthorityTransactionAndFreezesInventory(t *testing.T) {
	f, _, _ := setup(t)
	sf := &sourceFixture{}
	cfg := linuxFixture(t, f, sf).cfg
	var original *sql.Tx
	checks := 0
	cfg.VerifySource = func(_ context.Context, tx *sql.Tx) error {
		checks++
		if original == nil {
			original = tx
		} else if original != tx {
			t.Fatal("authority crossed snapshots")
		}
		return nil
	}
	mapped := &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{{ID: 20, UserID: 4, ResourceScope: "cm", Status: "running", RedisScopeID: "redis_a", Members: []team.SourceMember{{ID: 21, InstanceID: 7}}}}, Redis: []team.RedisScope{{ID: "redis_a", ServerID: strings.Repeat("a", 40), TeamIDs: []int{20}}}}
	cfg.ReadTeams = func(_ context.Context, tx *sql.Tx, source SourceInventory) (*team.Inventory, error) {
		if tx != original || len(source.Instances) != 1 || source.Teams != nil {
			t.Fatal("C did not use original observed SQL inventory")
		}
		source.Users[0] = 999
		return mapped, nil
	}
	profile, err := NewLinuxProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	x, err := profile.Discover(context.Background(), f.in)
	if err != nil || checks != 2 || sf.writes != 0 || sf.rollbacks != 1 {
		t.Fatal(err, checks, sf)
	}
	var frozen SourceInventory
	if json.Unmarshal(x.Source, &frozen) != nil || frozen.Teams == nil || frozen.Users[0] == 999 {
		t.Fatal("C inventory omitted or callback mutated source")
	}
	copy := cloneSourceInventory(frozen)
	copy.Teams.Teams[0].Members[0].InstanceID = 999
	if frozen.Teams.Teams[0].Members[0].InstanceID != 7 {
		t.Fatal("frozen team aliases mutable callback")
	}
	legacy, _ := json.Marshal(SourceInventory{Users: []int{1}})
	if strings.Contains(string(legacy), "Teams") {
		t.Fatal("old source plan encoding changed")
	}
}
