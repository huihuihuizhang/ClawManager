package domain

import (
	"strconv"

	"clawreef/internal/systembackup/team"
)

// VerifyTeamCapture is part of the shared SQL worker, before sealing ANY
// result. It checks the already-captured rows, not another SQL transaction.
// Deleted history can remain archived; only live Team coverage is required.
func VerifyTeamCapture(snapshot Snapshot, inventory team.Inventory) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, table := range snapshot.Tables {
		for _, row := range table.Rows {
			id, _ := strconv.Atoi(row["id"].String())
			if table.Name == "users" {
				users[id] = true
			}
			if table.Name == "instances" {
				owner, _ := strconv.Atoi(row["user_id"].String())
				owners[id] = owner
			}
		}
	}
	if inventory.Validate(users, owners) != nil {
		return ErrSchema
	}
	required := map[string]bool{}
	for _, name := range team.SQLTableNames() {
		required[name] = false
	}
	byTeam := map[int]team.SourceTeam{}
	mounts := map[string]team.SharedMount{}
	for _, mount := range inventory.Mounts {
		mounts[mount.ID] = mount
	}
	for _, t := range inventory.Teams {
		byTeam[t.ID] = t
	}
	teamCount := 0
	operations := map[string]bool{}
	for _, t := range snapshot.Tables {
		if t.Name == "northbound_operations" {
			for _, row := range t.Rows {
				operations[row["operation_id"].String()] = true
			}
		}
	}
	members := map[int]map[int]int{}
	for _, t := range snapshot.Tables {
		if _, ok := required[t.Name]; !ok {
			continue
		}
		if required[t.Name] {
			return ErrSchema
		}
		required[t.Name] = true
		columns := make([][4]string, 0, len(t.Columns))
		for _, c := range t.Columns {
			nullable := "NO"
			if c.Nullable {
				nullable = "YES"
			}
			columns = append(columns, [4]string{c.Name, c.Type, nullable, c.Extra})
		}
		if team.ValidateCapturedTable(t.Name, columns, t.PrimaryKey) != nil {
			return ErrSchema
		}
		for _, r := range t.Rows {
			if t.Name == "owner_team_provision_steps" && !operations[r["operation_id"].String()] {
				return ErrData
			}
			if t.Name == "teams" && r["status"].String() != "deleted" {
				id, _ := strconv.Atoi(r["id"].String())
				expected, ok := byTeam[id]
				uid, _ := strconv.Atoi(r["user_id"].String())
				if !ok || uid != expected.UserID || r["status"].String() != expected.Status || r["resource_scope"].String() != expected.ResourceScope || r["owner"].String() != expected.Owner {
					return ErrData
				}
				if expected.SharedMountID == "" {
					if r["shared_pvc_name"].String() != "" {
						return ErrData
					}
				} else {
					mount := mounts[expected.SharedMountID]
					if r["shared_pvc_name"].String() != mount.PVC || r["shared_pvc_namespace"].String() != mount.Namespace || r["shared_mount_path"].String() != mount.Root {
						return ErrData
					}
				}
				teamCount++
			}
			if t.Name == "team_members" && r["status"].String() != "deleted" {
				tid, _ := strconv.Atoi(r["team_id"].String())
				if _, ok := byTeam[tid]; !ok {
					continue
				}
				mid, _ := strconv.Atoi(r["id"].String())
				instance, _ := strconv.Atoi(r["instance_id"].String())
				if members[tid] == nil {
					members[tid] = map[int]int{}
				}
				if _, exists := members[tid][mid]; exists {
					return ErrData
				}
				members[tid][mid] = instance
			}
		}
	}
	for _, present := range required {
		if !present {
			return ErrSchema
		}
	}
	if teamCount != len(inventory.Teams) {
		return ErrData
	}
	for _, t := range inventory.Teams {
		if len(members[t.ID]) != len(t.Members) {
			return ErrData
		}
		for _, m := range t.Members {
			actual, ok := members[t.ID][m.ID]
			if !ok || actual != m.InstanceID {
				return ErrData
			}
		}
	}
	return validateDependencyLinks(snapshot)
}
