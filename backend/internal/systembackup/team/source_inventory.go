package team

import (
	"context"
	"database/sql"
)

// ReadInventory uses the caller's authenticated repeatable-read transaction.
// mapped is D's frozen provider/mount mapping; SQL facts cannot be replaced by
// its claims. No Redis, filesystem or Kubernetes IO occurs inside this reader.
func ReadInventory(ctx context.Context, tx *sql.Tx, mapped Inventory, users map[int]bool, instanceOwners map[int]int) (*Inventory, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return nil, ErrInventory
	}
	out := CloneInventory(&mapped)
	if out == nil {
		return nil, ErrInventory
	}
	out.Version = InventoryVersion
	if CheckSQLSchema(ctx, tx) != nil {
		return nil, ErrInventory
	}
	out.SchemaSHA256 = SchemaSHA256()
	out.Teams = []SourceTeam{}
	byID := map[int]SourceTeam{}
	for _, t := range mapped.Teams {
		if byID[t.ID].ID != 0 {
			return nil, ErrInventory
		}
		byID[t.ID] = t
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id,resource_scope,COALESCE(owner,''),status,COALESCE(shared_pvc_name,''),COALESCE(shared_pvc_namespace,''),COALESCE(shared_mount_path,'') FROM teams WHERE status<>'deleted' ORDER BY id")
	if err != nil {
		return nil, ErrInventory
	}
	index := map[int]int{}
	for rows.Next() {
		var t SourceTeam
		var pvc, namespace, root string
		if rows.Scan(&t.ID, &t.UserID, &t.ResourceScope, &t.Owner, &t.Status, &pvc, &namespace, &root) != nil || len(out.Teams) >= 10000 {
			rows.Close()
			return nil, ErrInventory
		}
		m, ok := byID[t.ID]
		if !ok {
			rows.Close()
			return nil, ErrInventory
		}
		t.SharedMountID, t.RedisScopeID = m.SharedMountID, m.RedisScopeID
		t.Members = []SourceMember{}
		if pvc != "" {
			found := false
			for _, mount := range out.Mounts {
				if mount.TeamID == t.ID && mount.ID == t.SharedMountID && mount.PVC == pvc && mount.Namespace == namespace && mount.Root == root {
					found = true
				}
			}
			if !found {
				rows.Close()
				return nil, ErrInventory
			}
		} else if t.SharedMountID != "" {
			rows.Close()
			return nil, ErrInventory
		}
		index[t.ID] = len(out.Teams)
		out.Teams = append(out.Teams, t)
	}
	if rows.Err() != nil || rows.Close() != nil || len(out.Teams) != len(byID) {
		return nil, ErrInventory
	}
	rows, err = tx.QueryContext(ctx, "SELECT m.id,m.team_id,m.user_id,COALESCE(m.instance_id,0) FROM team_members m JOIN teams t ON t.id=m.team_id WHERE t.status<>'deleted' AND m.status<>'deleted' ORDER BY m.team_id,m.id")
	if err != nil {
		return nil, ErrInventory
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var m SourceMember
		var tid, uid int
		if rows.Scan(&m.ID, &tid, &uid, &m.InstanceID) != nil {
			return nil, ErrInventory
		}
		n, ok := index[tid]
		if !ok || uid != out.Teams[n].UserID {
			return nil, ErrInventory
		}
		count++
		if count > 100000 {
			return nil, ErrInventory
		}
		out.Teams[n].Members = append(out.Teams[n].Members, m)
	}
	if rows.Err() != nil || out.Validate(users, instanceOwners) != nil {
		return nil, ErrInventory
	}
	// Mapped member lists are not a substitute for observed SQL relationships.
	return out, nil
}
