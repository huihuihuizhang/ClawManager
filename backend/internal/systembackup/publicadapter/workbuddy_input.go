package publicadapter

import (
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	d "clawreef/internal/systembackupdispatch"
)

// WithWorkBuddyIdentities is a PURE assembly step, not snapshot authentication.
// D must provide its original authenticated SQL snapshot and prove it belongs
// to this installation/database/task/attempt/capture context before calling.
// Snapshot has no such authority fields; matching rows cannot prove provenance.
// No query, UID allocation, filesystem marker read, permission or key issuance
// occurs here. Caller must not mutate snapshot concurrently during this call.
func WithWorkBuddyIdentities(cfg UsersInstancesModuleConfig, snapshot domain.Snapshot) (UsersInstancesModuleConfig, error) {
	var zero UsersInstancesModuleConfig
	copy, err := cloneUsersInstancesConfig(cfg)
	if err != nil {
		return zero, err
	}
	var ids []string
	for _, i := range copy.Source.Instances {
		if isWorkBuddySource(i) {
			ids = append(ids, strconv.Itoa(i.ID))
		}
	}
	if len(ids) != 0 {
		identities, err := domain.WorkBuddyUIDForInstances(snapshot, ids)
		if err != nil || !snapshotMatchesInventory(snapshot, copy.Source) {
			return zero, d.ErrNotReady
		}
		byID := map[int]domain.WorkBuddyUIDIdentity{}
		for _, identity := range identities {
			byID[identity.InstanceID] = identity
		}
		for n := range copy.Workspaces {
			mount := &copy.Workspaces[n]
			identity, ok := byID[mount.InstanceID]
			if !ok {
				continue
			}
			old := mount.Request.Invocation.Request.WorkBuddyIdentity
			if old != nil && *old != identity {
				return zero, d.ErrNotReady
			}
			// Fresh storage for every mount; neither input nor sibling aliases it.
			mount.Request.Invocation.Request.WorkBuddyIdentity = &identity
		}
	}
	if _, err := newUsersInstancesModule(copy); err != nil {
		return zero, err
	}
	return copy, nil
}

func isWorkBuddySource(i InstanceIdentity) bool {
	return RequiresWorkBuddyUIDIdentity(i)
}

// RequiresWorkBuddyUIDIdentity follows the original Linux Lite gateway SQL
// identity contract. Pro workspaces never borrow Lite allocator identities.
func RequiresWorkBuddyUIDIdentity(i InstanceIdentity) bool {
	runtime, err := scope.PlanRuntime(scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS})
	return err == nil && runtime.Type == "workbuddy" && runtime.Mode == "lite" && strings.EqualFold(strings.TrimSpace(i.Backend), "gateway") && strings.EqualFold(strings.TrimSpace(i.Variant), "linux")
}

func snapshotMatchesInventory(snapshot domain.Snapshot, source SourceInventory) bool {
	users, instances := map[string]bool{}, map[string]domain.Row{}
	for _, table := range snapshot.Tables {
		for _, row := range table.Rows {
			switch table.Name {
			case "users":
				users[row["id"].String()] = true
			case "instances":
				instances[row["id"].String()] = row
			}
		}
	}
	if len(users) != len(source.Users) || len(instances) != len(source.Instances) {
		return false
	}
	for _, id := range source.Users {
		if !users[strconv.Itoa(id)] {
			return false
		}
	}
	for _, i := range source.Instances {
		row, ok := instances[strconv.Itoa(i.ID)]
		if !ok {
			return false
		}
		want := map[string]string{"user_id": strconv.Itoa(i.UserID), "runtime_generation": strconv.Itoa(i.Generation), "instance_mode": i.Mode, "type": i.Type, "runtime_type": i.Backend, "runtime_variant": i.Variant, "os_type": i.OS, "status": i.Status, "pod_name": i.Pod, "pod_namespace": i.Namespace, "workspace_path": i.Workspace}
		for field, value := range want {
			cell, exists := row[field]
			// These three fields use COALESCE in the original SQL projection.
			coalesced := field == "pod_name" || field == "pod_namespace" || field == "runtime_variant" || field == "workspace_path"
			if !exists || (cell.Null && !coalesced) || cell.String() != value {
				return false
			}
		}
	}
	return true
}
