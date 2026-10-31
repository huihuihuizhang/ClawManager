package team

import (
	"context"
	"database/sql"
)

const SourceFactsVersion = "teams-original-sql-facts.v1"

// SourceFacts are ONLY original SQL relationships. No PVC UID, provider
// identity, stop proof or source permission is invented while the RR is open.
// D can bind independently observed storage after closing that transaction.
type SourceFacts struct {
	Version, SchemaSHA256 string
	Teams                 []TeamSQLFacts
	Members               []MemberSQLFacts
}

type TeamSQLFacts struct {
	ID, UserID                   int
	ResourceScope, Owner, Status string
	PVC, Namespace, Root         string
}

type MemberSQLFacts struct{ ID, TeamID, UserID, InstanceID int }

func CloneSourceFacts(f *SourceFacts) *SourceFacts {
	if f == nil {
		return nil
	}
	copy := *f
	copy.Teams = append([]TeamSQLFacts{}, f.Teams...)
	copy.Members = append([]MemberSQLFacts{}, f.Members...)
	return &copy
}

// MatchesInventory prevents a post-SQL storage resolver from replacing the
// original Team/member relationships when adding real PVC/provider identities.
func (f SourceFacts) MatchesInventory(inventory Inventory) bool {
	if len(f.Teams) != len(inventory.Teams) {
		return false
	}
	mounts := map[string]SharedMount{}
	for _, mount := range inventory.Mounts {
		mounts[mount.ID] = mount
	}
	members := map[int]MemberSQLFacts{}
	for _, member := range f.Members {
		members[member.ID] = member
	}
	count := 0
	for n, original := range f.Teams {
		actual := inventory.Teams[n]
		if original.ID != actual.ID || original.UserID != actual.UserID || original.ResourceScope != actual.ResourceScope || original.Owner != actual.Owner || original.Status != actual.Status || (original.PVC == "") != (actual.SharedMountID == "") {
			return false
		}
		if original.PVC != "" {
			mount, exists := mounts[actual.SharedMountID]
			if !exists || mount.TeamID != original.ID || mount.PVC != original.PVC || mount.Namespace != original.Namespace || mount.Root != original.Root {
				return false
			}
		}
		for _, member := range actual.Members {
			value, exists := members[member.ID]
			if !exists || value.TeamID != original.ID || value.UserID != original.UserID || value.InstanceID != member.InstanceID {
				return false
			}
			delete(members, member.ID)
			count++
		}
	}
	return count == len(f.Members) && len(members) == 0
}

func ReadSourceFacts(ctx context.Context, tx *sql.Tx, users map[int]bool, owners map[int]int) (*SourceFacts, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || CheckSQLSchema(ctx, tx) != nil {
		return nil, ErrInventory
	}
	out := &SourceFacts{Version: SourceFactsVersion, SchemaSHA256: SchemaSHA256(), Teams: []TeamSQLFacts{}, Members: []MemberSQLFacts{}}
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id,resource_scope,COALESCE(owner,''),status,COALESCE(shared_pvc_name,''),COALESCE(shared_pvc_namespace,''),COALESCE(shared_mount_path,'') FROM teams WHERE status<>'deleted' ORDER BY id")
	if err != nil {
		return nil, ErrInventory
	}
	for rows.Next() {
		var value TeamSQLFacts
		if ctx.Err() != nil || len(out.Teams) >= 10000 || rows.Scan(&value.ID, &value.UserID, &value.ResourceScope, &value.Owner, &value.Status, &value.PVC, &value.Namespace, &value.Root) != nil {
			rows.Close()
			return nil, ErrInventory
		}
		out.Teams = append(out.Teams, value)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrInventory
	}
	rows, err = tx.QueryContext(ctx, "SELECT m.id,m.team_id,m.user_id,COALESCE(m.instance_id,0) FROM team_members m JOIN teams t ON t.id=m.team_id WHERE t.status<>'deleted' AND m.status<>'deleted' ORDER BY m.team_id,m.id")
	if err != nil {
		return nil, ErrInventory
	}
	for rows.Next() {
		var value MemberSQLFacts
		if ctx.Err() != nil || len(out.Members) >= 100000 || rows.Scan(&value.ID, &value.TeamID, &value.UserID, &value.InstanceID) != nil {
			rows.Close()
			return nil, ErrInventory
		}
		out.Members = append(out.Members, value)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil || out.Validate(users, owners) != nil {
		return nil, ErrInventory
	}
	return out, nil
}

func (f SourceFacts) Validate(users map[int]bool, owners map[int]int) error {
	if f.Version != SourceFactsVersion || f.SchemaSHA256 != SchemaSHA256() || len(f.Teams) > 10000 || len(f.Members) > 100000 {
		return ErrInventory
	}
	teams, claims := map[int]TeamSQLFacts{}, map[string]bool{}
	previous := 0
	for _, value := range f.Teams {
		if value.ID <= previous || !users[value.UserID] || (value.ResourceScope != "cm" && value.ResourceScope != "northbound") || (value.ResourceScope == "cm" && value.Owner != "") || (value.ResourceScope == "northbound" && value.Owner == "") || (value.Status != "running" && value.Status != "creating" && value.Status != "deleting" && value.Status != "failed") || (value.PVC != "" && value.Namespace == "") {
			return ErrInventory
		}
		if value.PVC != "" {
			key := value.Namespace + "\x00" + value.PVC
			if claims[key] {
				return ErrInventory
			}
			claims[key] = true
		}
		teams[value.ID], previous = value, value.ID
	}
	seen := map[int]bool{}
	previousTeam, previousMember := 0, 0
	for _, value := range f.Members {
		owner, exists := teams[value.TeamID]
		if !exists || value.ID <= 0 || seen[value.ID] || value.UserID != owner.UserID || value.InstanceID < 0 || (value.InstanceID != 0 && owners[value.InstanceID] != value.UserID) || value.TeamID < previousTeam || (value.TeamID == previousTeam && value.ID <= previousMember) {
			return ErrInventory
		}
		seen[value.ID] = true
		previousTeam, previousMember = value.TeamID, value.ID
	}
	return nil
}
