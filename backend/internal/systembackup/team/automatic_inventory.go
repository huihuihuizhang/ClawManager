package team

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
)

// AutomaticStorageMapping contains source identities observed outside SQL.
// It contains no pre-approved Team/member IDs or replacement SQL relationships.
// Callers must obtain claims and object versions from their original scoped
// Kubernetes/provider discovery; this DTO alone grants no source permission.
type AutomaticStorageMapping struct {
	RedisID, RedisServerID string
	RedisDatabase          int
	Claims                 []SharedClaimIdentity
	Objects                []ObjectRef
	Writers                []WriterBinding
}

type SharedClaimIdentity struct{ Namespace, PVC, UID string }

// ReadAutomaticInventory discovers every current Team from the caller's SAME
// authenticated read-only RR transaction, then binds its actual SQL facts to
// the independently observed finite storage mapping. There
// is no Kube/provider I/O, new transaction, caller-supplied Team list or commit.
func ReadAutomaticInventory(ctx context.Context, tx *sql.Tx, storage AutomaticStorageMapping, users map[int]bool, instanceOwners map[int]int) (*Inventory, error) {
	facts, err := ReadSourceFacts(ctx, tx, users, instanceOwners)
	if err != nil {
		return nil, err
	}
	return BindAutomaticStorage(ctx, *facts, storage, users, instanceOwners)
}

// BindAutomaticStorage is pure. SQL facts remain distinct from physical
// identities so callers can perform remote discovery only AFTER ending RR.
func BindAutomaticStorage(ctx context.Context, facts SourceFacts, storage AutomaticStorageMapping, users map[int]bool, instanceOwners map[int]int) (*Inventory, error) {
	if ctx == nil || ctx.Err() != nil || facts.Validate(users, instanceOwners) != nil || !inventoryID.MatchString(storage.RedisID) || !redisServer.MatchString(storage.RedisServerID) || storage.RedisDatabase < 0 || storage.RedisDatabase > 15 || len(storage.Claims) > 10000 || len(storage.Objects) > 100000 || len(storage.Writers) > 10000 {
		return nil, ErrInventory
	}
	// Detach the independently observed mapping as well as nested writer units.
	raw, err := json.Marshal(storage)
	var frozen AutomaticStorageMapping
	if err != nil || len(raw) > 16<<20 || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrInventory
	}
	claims := map[string]SharedClaimIdentity{}
	for _, claim := range frozen.Claims {
		key := claim.Namespace + "\x00" + claim.PVC
		if claim.Namespace == "" || claim.PVC == "" || claim.UID == "" || claims[key].UID != "" {
			return nil, ErrInventory
		}
		claims[key] = claim
	}
	mapped := Inventory{Version: InventoryVersion, SchemaSHA256: SchemaSHA256(), Teams: []SourceTeam{}, Mounts: []SharedMount{}, Redis: []RedisScope{}, Objects: frozen.Objects, Writers: frozen.Writers}
	redis := RedisScope{ID: frozen.RedisID, ServerID: frozen.RedisServerID, Database: frozen.RedisDatabase, TeamIDs: []int{}}
	usedClaims := map[string]bool{}
	teamIndex := map[int]int{}
	for _, value := range facts.Teams {
		if ctx.Err() != nil {
			return nil, ErrInventory
		}
		team := SourceTeam{ID: value.ID, UserID: value.UserID, ResourceScope: value.ResourceScope, Owner: value.Owner, Status: value.Status, RedisScopeID: redis.ID, Members: []SourceMember{}}
		if value.PVC != "" {
			key := value.Namespace + "\x00" + value.PVC
			claim, ok := claims[key]
			if !ok || usedClaims[key] {
				return nil, ErrInventory
			}
			usedClaims[key] = true
			team.SharedMountID = "team_" + strconv.Itoa(team.ID) + "_shared"
			mapped.Mounts = append(mapped.Mounts, SharedMount{ID: team.SharedMountID, TeamID: team.ID, Namespace: value.Namespace, PVC: value.PVC, UID: claim.UID, Root: value.Root})
		}
		teamIndex[team.ID] = len(mapped.Teams)
		mapped.Teams = append(mapped.Teams, team)
		redis.TeamIDs = append(redis.TeamIDs, team.ID)
	}
	if ctx.Err() != nil || len(usedClaims) != len(claims) {
		return nil, ErrInventory
	}
	for _, value := range facts.Members {
		index := teamIndex[value.TeamID]
		mapped.Teams[index].Members = append(mapped.Teams[index].Members, SourceMember{ID: value.ID, InstanceID: value.InstanceID})
	}
	if len(redis.TeamIDs) > 0 {
		mapped.Redis = append(mapped.Redis, redis)
	}
	// Provider LIST order must not change the frozen source hash.
	sort.Slice(mapped.Objects, func(i, j int) bool {
		a, b := mapped.Objects[i], mapped.Objects[j]
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		return a.Key < b.Key
	})
	if mapped.Validate(users, instanceOwners) != nil || ctx.Err() != nil {
		return nil, ErrInventory
	}
	return &mapped, nil
}
