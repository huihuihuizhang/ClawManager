package publicadapter

import (
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
)

func usersInstancesModuleFixture(t *testing.T) (*fixture, UsersInstancesModuleConfig) {
	t.Helper()
	f := moduleTestInput(t)
	f.in.Backup.RequestedParts = []string{"mysql", "workspace"}
	source := SourceInventory{Database: "source", ServerUUID: "source-uuid", Users: []int{1, 2}, Instances: []InstanceIdentity{
		{ID: 7, UserID: 1, Generation: 3, Type: "openclaw", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux", Status: "running", Workspace: "/workspaces/1/7"},
		{ID: 9, UserID: 2, Generation: 4, Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux", Status: "stopped", Workspace: "/workspaces/2/9"},
	}}
	point, _ := moduleTestContext(f.in, source, f.x.HoldUntil, "")
	build := func(part, category, storage, operation string) CapturePartRequest {
		requests, err := moduleTestRequests(t, f, CaptureModuleInput{Input: f.in, Source: source, Context: point, Parts: []CaptureModuleSelection{{CaptureModulePart: CaptureModulePart{part, category, storage, operation}}}})
		if err != nil {
			t.Fatal(err)
		}
		return requests[0]
	}
	cfg := UsersInstancesModuleConfig{Revision: "fixture-r1", Source: source, Database: build(UsersInstancesDatabasePart, "users_instances", "mysql", "capture-database")}
	for _, i := range source.Instances {
		r := build(instanceMountPart(i.ID, "workspace"), "instances", "workspace", "capture-workspace")
		r.Invocation.Request.RuntimePolicy = &worker.RuntimePolicy{Version: "fixture-r1", Image: "agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Runtime: scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS}, Files: []worker.FileRule{{Path: "config.json", Fields: []domain.JSONRule{{Path: []string{"enabled"}, Action: "preserve"}}}}}
		cfg.Workspaces = append(cfg.Workspaces, InstanceWorkspaceCapture{InstanceID: i.ID, MountID: "workspace", Request: r})
	}
	return f, cfg
}

func TestUsersInstancesConcreteRegistrationUsesAtomicDatabaseAndAllMounts(t *testing.T) {
	f, cfg := usersInstancesModuleFixture(t)
	source := cloneSourceInventory(cfg.Source)
	r, err := NewUsersInstancesModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Registration must freeze nested configuration, including policy bytes.
	cfg.Source.Users[0] = 99
	cfg.Workspaces[0].Request.Invocation.Request.RuntimePolicy.Files[0].Path = "forged"
	cfg.Database.Invocation.Request.Database.Name = "foreign"
	c := moduleTestRegistration(t, f, "a_teams", "C", "teams_workspace")
	m, err := NewCaptureModules([]CaptureModuleRegistration{r, c}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		parts, err := m.BuildParts(f.in, source, f.x.HoldUntil)
		if err != nil || len(parts) != 4 {
			t.Fatal("real Job materialization", err)
		}
		databases := 0
		for index, p := range parts {
			var inv worker.Invocation
			if json.Unmarshal(p.InvocationJSON, &inv) != nil || inv.Request.Binding.PartIndex != uint32(index) {
				t.Fatal("global index lost")
			}
			if inv.Request.Operation == "capture-database" {
				databases++
			}
			if inv.Request.RuntimePolicy != nil && inv.Request.RuntimePolicy.Files[0].Path != "config.json" {
				t.Fatal("caller changed frozen policy")
			}
		}
		if databases != 1 || f.ensures != 0 || len(f.events) != 0 {
			t.Fatal("duplicated SQL export or dispatch during construction")
		}
	}
}

func TestUsersInstancesDataOnlyMountUsesExistingCaptureWithoutReplacingPrimary(t *testing.T) {
	f, cfg := usersInstancesModuleFixture(t)
	var extra InstanceWorkspaceCapture
	raw, _ := json.Marshal(cfg.Workspaces[0])
	if json.Unmarshal(raw, &extra) != nil {
		t.Fatal("fixture clone")
	}
	extra.MountID, extra.DataOnly = "data", true
	extra.Request.Part = "instance_7_data"
	extra.Request.JobUnitKey = extra.Request.Part
	extra.Request.Workload.Identity.Name = "capture-instance-7-data"
	extra.Request.Workload.WorkerControl.InvocationConfigMap = "invoke-instance-7-data"
	extra.Request.Invocation.Request.Binding.Path = extra.Request.Part
	extra.Request.Invocation.Request.RuntimePolicy = nil
	extra.Request.Invocation.Request.ArtifactName = "instance-data.enc"
	extra.Request.Workload.SourceSubPath = "users/1/instances/7/data"
	if extra.Request.Invocation.ProviderKey != nil {
		extra.Request.Invocation.ProviderKey.Request.Context.Part = extra.Request.Part
	}
	if extra.Request.Invocation.FormalCapture != nil {
		extra.Request.Invocation.FormalCapture.EnvelopeName = "instance-data.envelope"
	}
	cfg.Workspaces = append(cfg.Workspaces, extra)
	registration, err := NewUsersInstancesModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewCaptureModules([]CaptureModuleRegistration{registration}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := m.BuildParts(f.in, cfg.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 4 {
		t.Fatal("extra mount not materialized", err)
	}
	var got worker.Invocation
	found := false
	for _, part := range parts {
		if part.Part == "instance_7_data" {
			found = true
			if json.Unmarshal(part.InvocationJSON, &got) != nil || got.Request.RuntimePolicy != nil || got.Request.WorkBuddyIdentity != nil || got.Request.Operation != "capture-workspace" {
				t.Fatal("extra mount changed protocol or runtime policy")
			}
		}
	}
	if !found {
		t.Fatal("extra mount missing")
	}
	for _, fault := range []string{"primary", "policy", "whole-root"} {
		_, invalid := usersInstancesModuleFixture(t)
		var bad InstanceWorkspaceCapture
		raw, _ := json.Marshal(extra)
		if json.Unmarshal(raw, &bad) != nil {
			t.Fatal("fixture clone")
		}
		switch fault {
		case "primary":
			bad.MountID = "workspace"
		case "policy":
			bad.Request.Invocation.Request.RuntimePolicy = invalid.Workspaces[0].Request.Invocation.Request.RuntimePolicy
		case "whole-root":
			bad.Request.Workload.SourceSubPath = "."
		}
		invalid.Workspaces = append(invalid.Workspaces, bad)
		if _, err := NewUsersInstancesModule(invalid); err == nil {
			t.Fatal("data-only bypass accepted", fault)
		}
	}
}

func TestUsersInstancesRegistrationRejectsMissingAndForeignMappings(t *testing.T) {
	for _, which := range []string{"missing-mount", "extra-instance", "duplicate-mount", "wrong-part", "unknown-owner", "duplicate-user", "windows", "missing-policy", "foreign-policy", "foreign-database", "bad-revision", "transitional-state", "unsafe-workspace"} {
		t.Run(which, func(t *testing.T) {
			_, cfg := usersInstancesModuleFixture(t)
			switch which {
			case "transitional-state":
				cfg.Source.Instances[0].Status = "creating"
			case "unsafe-workspace":
				cfg.Source.Instances[0].Workspace = "/"
			case "missing-mount":
				cfg.Workspaces = cfg.Workspaces[:1]
			case "extra-instance":
				cfg.Workspaces[0].InstanceID = 111
			case "duplicate-mount":
				cfg.Workspaces = append(cfg.Workspaces, cfg.Workspaces[0])
			case "wrong-part":
				cfg.Workspaces[0].Request.Part = "foreign"
			case "unknown-owner":
				cfg.Source.Instances[0].UserID = 99
			case "duplicate-user":
				cfg.Source.Users[1] = 1
			case "windows":
				cfg.Source.Instances[0].OS = "windows"
			case "missing-policy":
				cfg.Workspaces[0].Request.Invocation.Request.RuntimePolicy = nil
			case "foreign-policy":
				cfg.Workspaces[0].Request.Invocation.Request.RuntimePolicy.Runtime.Type = "hermes"
			case "foreign-database":
				cfg.Database.Invocation.Request.Database.ServerUUID = "foreign"
			case "bad-revision":
				cfg.Revision = ""
			}
			if _, err := NewUsersInstancesModule(cfg); err == nil {
				t.Fatal("unsafe mapping accepted")
			}
		})
	}
}

func TestUsersInstancesBuildRejectsDriftAndStaleTaskTemplatesAtomically(t *testing.T) {
	for _, which := range []string{"owner", "generation", "workspace", "task", "attempt", "capture-point", "deadline", "invalid-job", "duplicate-output"} {
		t.Run(which, func(t *testing.T) {
			f, cfg := usersInstancesModuleFixture(t)
			source := cloneSourceInventory(cfg.Source)
			switch which {
			case "owner":
				source.Instances[0].UserID = 2
			case "generation":
				source.Instances[0].Generation++
			case "workspace":
				source.Instances[0].Workspace = "/foreign"
			case "task":
				cfg.Database.Invocation.Request.Binding.BackupID = "foreign"
			case "attempt":
				cfg.Database.Invocation.Request.Binding.Attempt = "99"
			case "capture-point":
				cfg.Database.Invocation.Request.Binding.CaptureContextHash = ""
			case "deadline":
				cfg.Database.Invocation.Request.Deadline = cfg.Database.Invocation.Request.Deadline.Add(-1)
			case "invalid-job":
				cfg.Database.Workload.WorkerControl.BoundPodIdentity = false
			case "duplicate-output":
				cfg.Database.Invocation.Request.ArtifactName = cfg.Workspaces[0].Request.Invocation.Request.ArtifactName
			}
			r, err := NewUsersInstancesModule(cfg)
			if err != nil {
				t.Fatal(err)
			}
			m, err := NewCaptureModules([]CaptureModuleRegistration{r}, moduleTestContext)
			if err != nil {
				t.Fatal(err)
			}
			if parts, err := m.BuildParts(f.in, source, f.x.HoldUntil); err == nil || parts != nil || f.ensures != 0 {
				t.Fatal("partial or stale capture escaped", err)
			}
		})
	}
}

func TestUsersInstancesZeroInstancesStillExportsUsersOnce(t *testing.T) {
	f, cfg := usersInstancesModuleFixture(t)
	cfg.Source.Instances = nil
	cfg.Workspaces = nil
	f.in.Backup.RequestedParts = []string{"mysql"}
	r, err := NewUsersInstancesModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewCaptureModules([]CaptureModuleRegistration{r}, moduleTestContext)
	parts, err := m.BuildParts(f.in, cfg.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 1 || parts[0].Part != UsersInstancesDatabasePart {
		t.Fatal(err)
	}
}

func TestUsersInstancesWorkBuddyRequiresMatchingAuthenticatedStorageIdentity(t *testing.T) {
	for _, mode := range []string{"missing", "foreign-user", "foreign-instance", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, cfg := usersInstancesModuleFixture(t)
			cfg.Source.Instances[0].Type = "workbuddy"
			cfg.Workspaces[0].Request.Invocation.Request.RuntimePolicy.Runtime.Type = "workbuddy"
			identity := &domain.WorkBuddyUIDIdentity{Schema: 1, InstanceID: 7, UserID: 1, UID: 20001, GID: 20001}
			switch mode {
			case "missing":
				identity = nil
			case "foreign-user":
				identity.UserID = 2
			case "foreign-instance":
				identity.InstanceID = 9
			}
			cfg.Workspaces[0].Request.Invocation.Request.WorkBuddyIdentity = identity
			r, err := NewUsersInstancesModule(cfg)
			if mode != "valid" {
				if err == nil {
					t.Fatal("foreign WorkBuddy identity accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			m, _ := NewCaptureModules([]CaptureModuleRegistration{r}, moduleTestContext)
			if parts, err := m.BuildParts(f.in, cfg.Source, f.x.HoldUntil); err != nil || len(parts) != 3 {
				t.Fatal(err)
			}
		})
	}
}

func TestUsersInstancesRegistersAdditionalAdmittedPersistentMount(t *testing.T) {
	f, cfg := usersInstancesModuleFixture(t)
	var mount InstanceWorkspaceCapture
	raw, _ := json.Marshal(cfg.Workspaces[0])
	if json.Unmarshal(raw, &mount) != nil {
		t.Fatal("fixture")
	}
	mount.MountID = "documents"
	part := instanceMountPart(mount.InstanceID, mount.MountID)
	mount.Request.Part, mount.Request.JobUnitKey = part, part
	mount.Request.Invocation.Request.Binding.Path = part
	mount.Request.Invocation.Request.ArtifactName = part + ".enc"
	mount.Request.Workload.Identity.Name = "capture-instance-7-documents"
	mount.Request.Workload.WorkerControl.InvocationConfigMap = "invoke-instance-7-documents"
	mount.Request.Workload.Source.PersistentVolumeClaim.ClaimName = "admitted-documents-pvc"
	cfg.Workspaces = append(cfg.Workspaces, mount)
	r, err := NewUsersInstancesModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewCaptureModules([]CaptureModuleRegistration{r}, moduleTestContext)
	parts, err := m.BuildParts(f.in, cfg.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 4 {
		t.Fatal("additional mount omitted", err)
	}
}
