package publicadapter

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

func teamsModuleFixture(t *testing.T) (*fixture, UsersInstancesModuleConfig, TeamsModuleConfig) {
	t.Helper()
	f, b := usersInstancesModuleFixture(t)
	b.Source.Teams = &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{{ID: 20, UserID: 1, ResourceScope: "northbound", Owner: "owner-a", Status: "running", SharedMountID: "team_20", RedisScopeID: "a", Members: []team.SourceMember{{ID: 21, InstanceID: 7}}}}, Mounts: []team.SharedMount{{ID: "team_20", TeamID: 20, Namespace: "cm-drill-b", PVC: "source-pvc", UID: "original-claim-uid", Root: "/teams/20"}}, Redis: []team.RedisScope{{ID: "a", ServerID: strings.Repeat("a", 40), TeamIDs: []int{20}}}, Objects: []team.ObjectRef{{TeamID: 20, Bucket: "source-bucket", Key: "results/report", Version: "original-version", SHA256: strings.Repeat("b", 64), Size: 3}}}
	f.in.Backup.RequestedParts = []string{"mysql", "redis", "object_storage", "workspace"}
	point, _ := moduleTestContext(f.in, b.Source, f.x.HoldUntil, "")
	build := func(part, storage, op string, index uint32) CapturePartRequest {
		r, err := moduleTestRequests(t, f, CaptureModuleInput{Input: f.in, Source: b.Source, Context: point, Parts: []CaptureModuleSelection{{CaptureModulePart: CaptureModulePart{part, "teams", "workspace", "capture-workspace"}, PartIndex: index}}})
		if err != nil {
			t.Fatal(err)
		}
		req := r[0]
		if op != "capture-workspace" {
			req.Invocation.Request.Operation = op
			req.Invocation.Request.MaxFiles, req.Invocation.Request.MaxFileBytes = 0, 0
			req.Invocation.WorkspacePath = ""
			req.Workload.Source = corev1.Volume{}
			spec := &worker.TeamCaptureSpec{InventorySHA256: b.Source.Teams.SHA256(), MaxItems: 100}
			if storage == "redis" {
				scope := b.Source.Teams.Redis[0]
				spec.Redis = &scope
			} else {
				spec.Objects = append([]team.ObjectRef(nil), b.Source.Teams.Objects...)
			}
			req.Invocation.Request.Teams = spec
			binding := req.Invocation.Request.Binding
			req.Invocation.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://bao.example.invalid:8200", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: f.in.Authority.InstallationID, BackupPublicID: binding.BackupID, AttemptNo: binding.Attempt, Phase: "capture", Part: part, PartIndex: strconv.FormatUint(uint64(index), 10), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}}}
			req.Invocation.FormalCapture = &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: part + ".envelope", MaxFrames: 8}
		}
		return req
	}
	objects := build("teams_objects", "object_storage", "capture-team-objects", 1)
	c := TeamsModuleConfig{Revision: "current-teams-v1", Source: cloneSourceInventory(b.Source), SharedWorkspaces: map[string]CapturePartRequest{"team_20": build("team_20_workspace", "workspace", "capture-workspace", 0)}, Redis: map[string]CapturePartRequest{"a": build("teams_redis_a", "redis", "capture-team-redis", 2)}, Objects: &objects}
	return f, b, c
}

func TestTeamsModuleSharesOnePublicSQLAndCapturesAllOriginalParts(t *testing.T) {
	f, b, c := teamsModuleFixture(t)
	br, err := NewUsersInstancesModule(b)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := NewTeamsModule(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewCaptureModules([]CaptureModuleRegistration{cr}, moduleTestContext); err == nil {
		t.Fatal("Teams accepted without atomic SQL dependency")
	}
	m, err := NewCaptureModules([]CaptureModuleRegistration{br, cr}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned templates cannot alter the registered source scope.
	c.Source.Teams.Redis[0].TeamIDs[0] = 99
	c.Objects.Invocation.Request.Teams.Objects[0].Version = "replacement"
	parts, err := m.BuildParts(f.in, b.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 6 {
		t.Fatal("complete public assembly failed", len(parts), err)
	}
	db, teams, workspaces := 0, 0, 0
	for index, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil || inv.Request.Binding.PartIndex != uint32(index) || inv.Request.Binding.CaptureContextHash != strings.Repeat("c", 64) {
			t.Fatal("capture context/index drift")
		}
		if inv.Request.Operation == "capture-database" {
			db++
			if inv.Request.Database.TeamsInventory == nil || inv.Request.Database.TeamsInventory.SHA256() != b.Source.Teams.SHA256() {
				t.Fatal("shared SQL lost C coverage contract")
			}
		}
		if part.Category == "teams" {
			teams++
		}
		if inv.Request.Operation == "capture-workspace" {
			workspaces++
		}
	}
	if db != 1 || teams != 3 || workspaces != 3 || f.ensures != 0 {
		t.Fatal("duplicate SQL/member mount or premature dispatch")
	}
	f.in.Backup.RequestedParts = []string{"mysql", "workspace", "object_storage"}
	if _, err = m.BuildParts(f.in, b.Source, f.x.HoldUntil); err == nil {
		t.Fatal("missing Redis reported as complete Teams capture")
	}
}

func TestEmptyTeamsStillRegisterSQLTemplateAndHistoryCoverage(t *testing.T) {
	f, b, _ := teamsModuleFixture(t)
	b.Source.Teams.Teams, b.Source.Teams.Mounts, b.Source.Teams.Redis, b.Source.Teams.Objects = nil, nil, nil, nil
	f.in.Backup.RequestedParts = []string{"mysql", "workspace"}
	cr, err := NewTeamsModule(TeamsModuleConfig{Revision: "empty-teams-v1", Source: b.Source})
	if err != nil {
		t.Fatal("no active Teams must not discard template/history SQL coverage", err)
	}
	br, err := NewUsersInstancesModule(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewCaptureModules([]CaptureModuleRegistration{br, cr}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := m.BuildParts(f.in, b.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 3 {
		t.Fatal(parts, err)
	}
	database := 0
	for _, part := range parts {
		var inv worker.Invocation
		json.Unmarshal(part.InvocationJSON, &inv)
		if inv.Request.Operation == "capture-database" {
			database++
			if inv.Request.Database.TeamsInventory == nil {
				t.Fatal("empty C scope lost from atomic SQL")
			}
		}
	}
	if database != 1 {
		t.Fatal("duplicate shared SQL")
	}
}

func TestTeamsModuleRejectsIncompleteAndCrossOwnerBindings(t *testing.T) {
	for _, mode := range []string{"missing-workspace", "foreign-pvc", "missing-redis", "foreign-redis", "wrong-object-version", "foreign-member", "source-drift", "rebound-provider-index"} {
		t.Run(mode, func(t *testing.T) {
			f, b, c := teamsModuleFixture(t)
			switch mode {
			case "missing-workspace":
				c.SharedWorkspaces = nil
			case "foreign-pvc":
				r := c.SharedWorkspaces["team_20"]
				r.Workload.Source.PersistentVolumeClaim.ClaimName = "foreign"
				c.SharedWorkspaces["team_20"] = r
			case "missing-redis":
				c.Redis = nil
			case "foreign-redis":
				r := c.Redis["a"]
				r.Invocation.Request.Teams.Redis.TeamIDs[0] = 99
				c.Redis["a"] = r
			case "wrong-object-version":
				c.Objects.Invocation.Request.Teams.Objects[0].Version = "latest"
			case "foreign-member":
				c.Source.Teams.Teams[0].Members[0].InstanceID = 9
			case "rebound-provider-index":
				r := c.Redis["a"]
				r.Invocation.ProviderKey.Request.Context.PartIndex = "99"
				c.Redis["a"] = r
			}
			cr, err := NewTeamsModule(c)
			if mode != "source-drift" && mode != "rebound-provider-index" {
				if err == nil {
					t.Fatal("invalid Team mapping registered")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			br, err := NewUsersInstancesModule(b)
			if err != nil {
				t.Fatal(err)
			}
			m, err := NewCaptureModules([]CaptureModuleRegistration{br, cr}, moduleTestContext)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "source-drift" {
				b.Source.Teams.Teams[0].Owner = "changed-owner"
			}
			if _, err = m.BuildParts(f.in, b.Source, f.x.HoldUntil); err == nil || f.ensures != 0 {
				t.Fatal("drift/rebound request accepted or dispatched")
			}
		})
	}
}
