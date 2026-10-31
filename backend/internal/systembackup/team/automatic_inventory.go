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
// authenticated read-only RR transaction, then uses ReadInventory for the
// original schema, owner, member and finite-storage consistency checks. There
// is no Kube/provider I/O, new transaction, caller-supplied Team list or commit.
func ReadAutomaticInventory(ctx context.Context, tx *sql.Tx, storage AutomaticStorageMapping, users map[int]bool, instanceOwners map[int]int) (*Inventory, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !inventoryID.MatchString(storage.RedisID) || !redisServer.MatchString(storage.RedisServerID) || storage.RedisDatabase < 0 || storage.RedisDatabase > 15 || len(storage.Claims) > 10000 || len(storage.Objects) > 100000 || len(storage.Writers) > 10000 {
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
	// Validate finite column widths before reading any original Team values.
	if CheckSQLSchema(ctx, tx) != nil {
		return nil, ErrInventory
	}
	mapped := Inventory{Version: InventoryVersion, SchemaSHA256: SchemaSHA256(), Teams: []SourceTeam{}, Mounts: []SharedMount{}, Redis: []RedisScope{}, Objects: frozen.Objects, Writers: frozen.Writers}
	redis := RedisScope{ID: frozen.RedisID, ServerID: frozen.RedisServerID, Database: frozen.RedisDatabase, TeamIDs: []int{}}
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id,resource_scope,COALESCE(owner,''),status,COALESCE(shared_pvc_name,''),COALESCE(shared_pvc_namespace,''),COALESCE(shared_mount_path,'') FROM teams WHERE status<>'deleted' ORDER BY id")
	if err != nil {
		return nil, ErrInventory
	}
	usedClaims := map[string]bool{}
	for rows.Next() {
		var team SourceTeam
		var pvc, namespace, root string
		if ctx.Err() != nil || rows.Scan(&team.ID, &team.UserID, &team.ResourceScope, &team.Owner, &team.Status, &pvc, &namespace, &root) != nil || len(mapped.Teams) >= 10000 {
			rows.Close()
			return nil, ErrInventory
		}
		team.RedisScopeID = redis.ID
		if pvc != "" {
			key := namespace + "\x00" + pvc
			claim, ok := claims[key]
			if !ok || usedClaims[key] {
				rows.Close()
				return nil, ErrInventory
			}
			usedClaims[key] = true
			team.SharedMountID = "team_" + strconv.Itoa(team.ID) + "_shared"
			mapped.Mounts = append(mapped.Mounts, SharedMount{ID: team.SharedMountID, TeamID: team.ID, Namespace: namespace, PVC: pvc, UID: claim.UID, Root: root})
		}
		mapped.Teams = append(mapped.Teams, team)
		redis.TeamIDs = append(redis.TeamIDs, team.ID)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil || len(usedClaims) != len(claims) {
		return nil, ErrInventory
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
	return ReadInventory(ctx, tx, mapped, users, instanceOwners)
}
