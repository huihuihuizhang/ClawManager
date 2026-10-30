package team

import (
	"strings"
	"testing"
)

func inventoryFixture() Inventory {
	return Inventory{Version: InventoryVersion, SchemaSHA256: SchemaSHA256(), Teams: []SourceTeam{{ID: 20, UserID: 4, ResourceScope: "northbound", Owner: "owner-a", Status: "running", SharedMountID: "team_20", RedisScopeID: "redis_a", Members: []SourceMember{{ID: 21, InstanceID: 8}}}}, Mounts: []SharedMount{{ID: "team_20", TeamID: 20, Namespace: "source", PVC: "team-shared", UID: "original-volume-uid", Root: "/teams/20"}}, Redis: []RedisScope{{ID: "redis_a", ServerID: strings.Repeat("a", 40), Database: 0, TeamIDs: []int{20}}}, Objects: []ObjectRef{{TeamID: 20, Bucket: "source", Key: "artifacts/result", Version: "original-version", SHA256: strings.Repeat("b", 64), Size: 3}}}
}
func TestTeamsInventoryRejectsPartialOrForeignScope(t *testing.T) {
	for _, mode := range []string{"valid", "missing-mount", "foreign-member", "missing-redis", "foreign-key-scope", "missing-object-version", "deleted-team", "unmapped-owner", "duplicate-member"} {
		t.Run(mode, func(t *testing.T) {
			i := inventoryFixture()
			switch mode {
			case "missing-mount":
				i.Mounts = nil
			case "foreign-member":
				i.Teams[0].Members[0].InstanceID = 9
			case "missing-redis":
				i.Redis = nil
			case "foreign-key-scope":
				i.Redis[0].TeamIDs = []int{99}
			case "missing-object-version":
				i.Objects[0].Version = ""
			case "deleted-team":
				i.Teams[0].Status = "deleted"
			case "unmapped-owner":
				i.Teams[0].Owner = ""
			case "duplicate-member":
				i.Teams[0].Members = append(i.Teams[0].Members, i.Teams[0].Members[0])
			}
			err := i.Validate(map[int]bool{4: true}, map[int]int{8: 4, 9: 5})
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}
func TestTeamsInventoryCloneDoesNotAliasFrozenPlan(t *testing.T) {
	i := inventoryFixture()
	clone := CloneInventory(&i)
	hash := i.SHA256()
	clone.Redis[0].TeamIDs[0] = 99
	clone.Teams[0].Members[0].InstanceID = 99
	if i.SHA256() != hash {
		t.Fatal("frozen plan mutated")
	}
}
