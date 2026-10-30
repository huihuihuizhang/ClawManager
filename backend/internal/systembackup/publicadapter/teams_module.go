package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

type TeamsModuleConfig struct {
	Revision         string
	Source           SourceInventory
	SharedWorkspaces map[string]CapturePartRequest // mount ID, never member instance mounts
	Redis            map[string]CapturePartRequest // original server/database scope ID
	Objects          *CapturePartRequest
}

// NewTeamsModule contributes C's data plane to B's existing module catalog.
// SQL is a dependency on ONE atomic B export, not a second Team transaction.
// There is no private controller, discovery IO or source permission fallback.
func NewTeamsModule(cfg TeamsModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(cfg)
	if err != nil || len(raw) > 16<<20 {
		return zero, d.ErrNotReady
	}
	var frozen TeamsModuleConfig
	if json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	cfg = frozen
	i := cfg.Source.Teams
	if !utf8.ValidString(cfg.Revision) || strings.ContainsAny(cfg.Revision, "\x00\r\n") {
		return zero, d.ErrNotReady
	}
	if i == nil || len(i.Teams) == 0 || cfg.Source.Database == "" || cfg.Source.ServerUUID == "" || cfg.Revision == "" || len(cfg.Revision) > 128 {
		return zero, d.ErrNotReady
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range cfg.Source.Users {
		if id <= 0 || users[id] {
			return zero, d.ErrNotReady
		}
		users[id] = true
	}
	for _, instance := range cfg.Source.Instances {
		if owners[instance.ID] != 0 {
			return zero, d.ErrNotReady
		}
		owners[instance.ID] = instance.UserID
	}
	if i.Validate(users, owners) != nil || len(cfg.SharedWorkspaces) != len(i.Mounts) || len(cfg.Redis) != len(i.Redis) || (len(i.Objects) == 0) != (cfg.Objects == nil) {
		return zero, d.ErrNotReady
	}
	parts := []CaptureModulePart{}
	requests := map[string]CapturePartRequest{}
	add := func(part, storage, op string, r CapturePartRequest) bool {
		if !unit.MatchString(part) || r.Part != part || r.Category != "teams" || r.Invocation.Request.Operation != op || requests[part].Part != "" {
			return false
		}
		requests[part] = r
		parts = append(parts, CaptureModulePart{Part: part, Category: "teams", RequestedPart: storage, Operation: op})
		return true
	}
	for _, mount := range i.Mounts {
		r, ok := cfg.SharedWorkspaces[mount.ID]
		if !ok || r.Workload.Source.PersistentVolumeClaim == nil || r.Workload.Source.PersistentVolumeClaim.ClaimName != mount.PVC || r.Workload.Identity.Namespace != mount.Namespace || r.Invocation.WorkspacePath != "/workspace" || r.Invocation.Request.RuntimePolicy != nil || r.Invocation.Request.Teams != nil || !add("team_"+strconv.Itoa(mount.TeamID)+"_workspace", "workspace", "capture-workspace", r) {
			return zero, d.ErrNotReady
		}
	}
	for _, scope := range i.Redis {
		r, ok := cfg.Redis[scope.ID]
		s := r.Invocation.Request.Teams
		if !ok || s == nil || s.InventorySHA256 != i.SHA256() || s.Redis == nil || !reflect.DeepEqual(*s.Redis, scope) || !add("teams_redis_"+scope.ID, "redis", "capture-team-redis", r) {
			return zero, d.ErrNotReady
		}
	}
	if cfg.Objects != nil {
		r := *cfg.Objects
		s := r.Invocation.Request.Teams
		if s == nil || s.InventorySHA256 != i.SHA256() || !reflect.DeepEqual(s.Objects, i.Objects) || !add("teams_objects", "object_storage", "capture-team-objects", r) {
			return zero, d.ErrNotReady
		}
	}
	sourceRaw, _ := json.Marshal(cfg.Source)
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: "teams", Owner: "C", Revision: cfg.Revision, Parts: parts, Requires: []CaptureModuleDependency{{Part: UsersInstancesDatabasePart, Owner: "B", RequestedPart: "mysql", Operation: "capture-database"}}, Required: true}}
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		actual, _ := json.Marshal(input.Source)
		if string(actual) != string(sourceRaw) || input.Source.Teams == nil || len(input.Parts) != len(parts) {
			return nil, d.ErrNotReady
		}
		out := []CapturePartRequest{}
		seen := map[string]bool{}
		for _, selected := range input.Parts {
			r, ok := requests[selected.Part]
			if !ok || seen[selected.Part] || selected.Category != "teams" || selected.Operation != r.Invocation.Request.Operation {
				return nil, d.ErrNotReady
			}
			seen[selected.Part] = true
			b := r.Invocation.Request.Binding
			if b.BackupID != input.Input.Authority.TaskPublicID || b.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || b.Path != selected.Part || b.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) {
				return nil, d.ErrNotReady
			}
			var copy CapturePartRequest
			raw, _ := json.Marshal(r)
			if json.Unmarshal(raw, &copy) != nil {
				return nil, d.ErrNotReady
			}
			copy.Invocation.Request.Binding.PartIndex = selected.PartIndex
			// The provider's context must already be the original catalog index;
			// C cannot rebind a permit to another part while assigning indices.
			if copy.Invocation.ProviderKey != nil && copy.Invocation.ProviderKey.Request.Context.PartIndex != strconv.FormatUint(uint64(selected.PartIndex), 10) {
				return nil, d.ErrNotReady
			}
			out = append(out, copy)
		}
		return out, nil
	}
	return registration, nil
}

// TeamsInventoryReader is installed on the same LinuxProfile discovery path as
// B's users/instances reader. It preserves VerifySource, writers and recovery.
func WithTeamsInventory(source LinuxProfileConfig, mapped team.Inventory) LinuxProfileConfig {
	frozen := team.CloneInventory(&mapped)
	source.ReadTeams = func(ctx context.Context, tx *sql.Tx, inv SourceInventory) (*team.Inventory, error) {
		if frozen == nil {
			return nil, d.ErrNotReady
		}
		users, owners := map[int]bool{}, map[int]int{}
		for _, id := range inv.Users {
			users[id] = true
		}
		for _, instance := range inv.Instances {
			owners[instance.ID] = instance.UserID
		}
		return team.ReadInventory(ctx, tx, *frozen, users, owners)
	}
	return source
}
