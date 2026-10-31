package publicadapter

import (
	"encoding/json"
	"path"
	"slices"
	"strconv"
	"time"

	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
)

const UsersInstancesDatabasePart = "users_instances_database"

// InstanceWorkspaceCapture is a reviewed mount mapping supplied by D, not a
// path inferred from a user's files. "workspace" is the required primary mount;
// other persistent mounts must also be enumerated by the original inventory
// validator. This constructor cannot attest mount/writer coverage itself.
type InstanceWorkspaceCapture struct {
	InstanceID int
	MountID    string
	Request    CapturePartRequest
}

type UsersInstancesModuleConfig struct {
	Revision   string
	Source     SourceInventory
	Database   CapturePartRequest
	Workspaces []InstanceWorkspaceCapture
}

func instanceMountPart(id int, mount string) string {
	return "instance_" + strconv.Itoa(id) + "_" + mount
}

// NewUsersInstancesModule registers the existing ATOMIC users+instances SQL
// exporter and every admitted instance mount using the existing worker only.
// Inputs are task-scoped public templates (no credentials). Construction and
// Build perform no IO, key issuance, claim, source discovery or Job dispatch.
// Compose this registration with C modules using NewCaptureModules, then pass
// that catalog through PublicCaptureConfig.Modules. It does not open admission.
func NewUsersInstancesModule(cfg UsersInstancesModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	var err error
	cfg, err = cloneUsersInstancesConfig(cfg)
	if err != nil {
		return zero, err
	}
	return newUsersInstancesModule(cfg)
}

func cloneUsersInstancesConfig(cfg UsersInstancesModuleConfig) (UsersInstancesModuleConfig, error) {
	// Freeze all nested invocation/policy/Kubernetes slices, not just the header.
	raw, err := json.Marshal(cfg)
	var frozen UsersInstancesModuleConfig
	if err != nil || len(raw) > 16<<20 || json.Unmarshal(raw, &frozen) != nil {
		return UsersInstancesModuleConfig{}, d.ErrNotReady
	}
	return frozen, nil
}

func newUsersInstancesModule(cfg UsersInstancesModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	if cfg.Source.Database == "" || cfg.Source.ServerUUID == "" || len(cfg.Source.Users) == 0 || len(cfg.Source.Users) > 100000 || len(cfg.Source.Instances) > 9998 {
		return zero, d.ErrNotReady
	}
	users, instances := map[int]bool{}, map[int]InstanceIdentity{}
	for _, id := range cfg.Source.Users {
		if id <= 0 || users[id] {
			return zero, d.ErrNotReady
		}
		users[id] = true
	}
	for _, i := range cfg.Source.Instances {
		if i.ID <= 0 || !users[i.UserID] || i.Generation <= 0 || instances[i.ID].ID != 0 || (i.Status != "running" && i.Status != "stopped") || !path.IsAbs(i.Workspace) || path.Clean(i.Workspace) != i.Workspace || i.Workspace == "/" {
			return zero, d.ErrNotReady
		}
		if _, err := scope.PlanRuntime(scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS}); err != nil {
			return zero, d.ErrNotReady
		}
		instances[i.ID] = i
	}
	db := cfg.Database.Invocation.Request.Database
	if db != nil {
		db.TeamsInventory = team.CloneInventory(cfg.Source.Teams)
		db.SkillsInventory = sh.CloneCaptureInventory(cfg.Source.Skills)
	}
	if db == nil || db.Name != cfg.Source.Database || db.ServerUUID != cfg.Source.ServerUUID || cfg.Database.Invocation.Request.Operation != "capture-database" {
		return zero, d.ErrNotReady
	}
	requests := map[string]CapturePartRequest{UsersInstancesDatabasePart: cfg.Database}
	parts := []CaptureModulePart{{UsersInstancesDatabasePart, "users_instances", "mysql", "capture-database"}}
	primary := map[int]bool{}
	for _, mount := range cfg.Workspaces {
		i, ok := instances[mount.InstanceID]
		part := instanceMountPart(mount.InstanceID, mount.MountID)
		if !ok || !unit.MatchString(mount.MountID) || !unit.MatchString(part) || requests[part].Part != "" {
			return zero, d.ErrNotReady
		}
		r := mount.Request
		policy := r.Invocation.Request.RuntimePolicy
		if policy == nil || policy.Validate() != nil || r.Invocation.Request.Operation != "capture-workspace" {
			return zero, d.ErrNotReady
		}
		actual, e := scope.PlanRuntime(policy.Runtime)
		expected, _ := scope.PlanRuntime(scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS})
		if e != nil || actual.Type != expected.Type || actual.Mode != expected.Mode {
			return zero, d.ErrNotReady
		}
		if actual.Type == "workbuddy" {
			identity := r.Invocation.Request.WorkBuddyIdentity
			if identity == nil || identity.UserID != i.UserID || identity.InstanceID != i.ID {
				return zero, d.ErrNotReady
			}
		}
		if r.Part != part || r.Category != "instances" {
			return zero, d.ErrNotReady
		}
		if mount.MountID == "workspace" {
			primary[i.ID] = true
		}
		requests[part] = r
		parts = append(parts, CaptureModulePart{part, "instances", "workspace", "capture-workspace"})
	}
	if len(primary) != len(instances) || len(parts) > 10000 || cfg.Database.Part != UsersInstancesDatabasePart || cfg.Database.Category != "users_instances" {
		return zero, d.ErrNotReady
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: "users_instances", Owner: "B", Revision: cfg.Revision, Parts: parts}}
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		if input.Source.Database != cfg.Source.Database || input.Source.ServerUUID != cfg.Source.ServerUUID || !slices.Equal(input.Source.Users, cfg.Source.Users) || !slices.Equal(input.Source.Instances, cfg.Source.Instances) || len(input.Parts) == 0 {
			return nil, d.ErrNotReady
		}
		out := make([]CapturePartRequest, 0, len(input.Parts))
		seen := map[string]bool{}
		for _, selected := range input.Parts {
			r, ok := requests[selected.Part]
			if !ok || seen[selected.Part] || r.Category != selected.Category || r.Invocation.Request.Operation != selected.Operation {
				return nil, d.ErrNotReady
			}
			seen[selected.Part] = true
			// The original task, capture point, deadline, key reference and path
			// must already match. Only the catalog's global part index is assigned.
			binding := r.Invocation.Request.Binding
			if binding.BackupID != input.Input.Authority.TaskPublicID || binding.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || binding.Path != selected.Part || binding.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) {
				return nil, d.ErrNotReady
			}
			var detached CapturePartRequest
			encoded, e := json.Marshal(r)
			if e != nil || json.Unmarshal(encoded, &detached) != nil {
				return nil, d.ErrNotReady
			}
			detached.Invocation.Request.Binding.PartIndex = selected.PartIndex
			out = append(out, detached)
		}
		return out, nil
	}
	// Use the same catalog validation now, not a second descriptor policy.
	if _, err := NewCaptureModules([]CaptureModuleRegistration{registration}, func(d.Input, SourceInventory, time.Time, string) (ModuleCaptureContext, error) {
		return ModuleCaptureContext{}, d.ErrNotReady
	}); err != nil {
		return zero, err
	}
	return registration, nil
}
