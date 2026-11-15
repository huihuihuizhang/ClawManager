package team

import (
	"context"
	"strings"
	"testing"
)

func TestAutomaticTeamStoragePreservesOriginalRedisSourceID(t *testing.T) {
	facts := SourceFacts{Version: SourceFactsVersion, SchemaSHA256: SchemaSHA256(), Teams: []TeamSQLFacts{{ID: 1, UserID: 1, ResourceScope: "cm", Status: "running", Namespace: "tenant-1", PVC: "team-pvc", Root: "/team"}}, Members: []MemberSQLFacts{{ID: 1, TeamID: 1, UserID: 1, InstanceID: 7}}}
	users, owners := map[int]bool{1: true}, map[int]int{7: 1}
	for _, id := range []string{"redis_original", "redis-2de66a07-3305-4a01-9a8d-94abbc9d4bfa"} {
		storage := AutomaticStorageMapping{RedisID: id, RedisServerID: strings.Repeat("a", 40), Claims: []SharedClaimIdentity{{Namespace: "tenant-1", PVC: "team-pvc", UID: "actual-pvc-uid"}}, Objects: []ObjectRef{}}
		got, err := BindAutomaticStorage(context.Background(), facts, storage, users, owners)
		if err != nil || got.Redis[0].ID != id || got.Teams[0].RedisScopeID != id || !facts.MatchesInventory(*got) || got.Validate(users, owners) != nil {
			t.Fatal("original Redis identity or SQL relationship changed", err)
		}
		for _, invalid := range []string{"", "../redis", "redis/source", "redis\nsource", strings.Repeat("a", 97)} {
			storage.RedisID = invalid
			if _, err := BindAutomaticStorage(context.Background(), facts, storage, users, owners); err == nil {
				t.Fatalf("invalid Redis ID accepted: %q", invalid)
			}
		}
		storage.RedisID = id
		storage.RedisServerID = "wrong-server"
		if _, err := BindAutomaticStorage(context.Background(), facts, storage, users, owners); err == nil {
			t.Fatal("invalid server accepted")
		}
	}
}
