package publicadapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	corev1 "k8s.io/api/core/v1"
)

func sourceRedisSharedModuleFixture(t *testing.T, empty bool) (*fixture, UsersInstancesModuleConfig, TeamsModuleConfig, SourceRedisModuleConfig) {
	t.Helper()
	f, users, teams := teamsModuleFixture(t)
	r := teams.Redis["a"]
	if empty {
		users.Source.Teams = &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{}, Mounts: []team.SharedMount{}, Redis: []team.RedisScope{}, Objects: []team.ObjectRef{}}
		teams.SharedWorkspaces = map[string]CapturePartRequest{}
	} else {
		users.Source.Teams.Objects = nil
	}
	f.in.Backup.RequestedParts = []string{"mysql", "redis", "workspace"}
	r.Part, r.Category, r.JobUnitKey = SourceRedisPart, "source", SourceRedisPart
	r.Invocation.Request.Operation = "capture-source-redis"
	r.Invocation.Request.Teams = nil
	r.Invocation.Request.SourceRedis = &c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "a", Version: "original-v1", SHA256: strings.Repeat("b", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: f.in.Backup.TaskPurpose, DB: 0, Prefixes: []string{"claw:team:"}, MaxItems: 100, MaxBytes: r.Invocation.Request.MaxArchiveBytes, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40)}
	r.Invocation.Request.Binding.Path = SourceRedisPart
	r.Invocation.Request.Binding.PartIndex = 0
	r.Invocation.Request.ArtifactName = "source-redis.enc"
	r.Invocation.FormalCapture.EnvelopeName = "source-redis.envelope"
	r.Invocation.ProviderKey.Request.Context.Part = SourceRedisPart
	r.Invocation.ProviderKey.Request.Context.PartIndex = "0"
	r.Invocation.FormalCapture.SourceConfigSHA256 = f.in.Authority.ConfigSHA256
	r.Invocation.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}
	r.Workload.Identity.Name = "capture-source-redis"
	r.Workload.WorkerControl.InvocationConfigMap = "source-redis-invocation"
	r.Workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "source-redis-formal", Inputs: []kube.FormalInputMount{{Volume: "formal-redis-source", Kind: "Secret", Name: "original-redis-source", Directory: "/run/backup/materials/redis-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}
	teams.Source = cloneSourceInventory(users.Source)
	teams.Redis = nil
	teams.Objects = nil
	teams.SharedRedisPart = SourceRedisPart
	teams.SharedRedis = r.Invocation.Request.SourceRedis
	return f, users, teams, SourceRedisModuleConfig{Revision: "original-redis-v1", Source: cloneSourceInventory(users.Source), Request: r}
}

func TestActualSharedRedisModuleHasOneCollectorWithEmptyOrNonemptyTeams(t *testing.T) {
	for _, empty := range []bool{true, false} {
		name := "nonempty-teams"
		if empty {
			name = "nonempty-instances-empty-teams"
		}
		t.Run(name, func(t *testing.T) {
			f, users, teams, redis := sourceRedisSharedModuleFixture(t, empty)
			ur, err := NewUsersInstancesModule(users)
			if err != nil {
				t.Fatal(err)
			}
			tr, err := NewTeamsModule(teams)
			if err != nil {
				t.Fatal(err)
			}
			rr, err := NewSourceRedisModule(redis)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := NewCaptureModules([]CaptureModuleRegistration{ur, tr, rr}, moduleTestContext)
			if err != nil {
				t.Fatal(err)
			}
			parts, err := catalog.BuildParts(f.in, users.Source, f.x.HoldUntil)
			if err != nil {
				t.Fatal(err)
			}
			redisJobs, sqlJobs, instanceJobs := 0, 0, 0
			for _, part := range parts {
				var inv worker.Invocation
				if json.Unmarshal(part.InvocationJSON, &inv) != nil {
					t.Fatal("actual invocation decode")
				}
				if inv.Request.Operation == "capture-database" {
					sqlJobs++
				}
				if inv.Request.RuntimePolicy != nil {
					instanceJobs++
				}
				if inv.Request.Operation == "capture-team-redis" {
					t.Fatal("Teams duplicated the shared source capture")
				}
				if inv.Request.Operation == "capture-source-redis" {
					redisJobs++
					if !worker.ValidateRecordedInvocation(inv) || inv.Request.SourceRedis == nil || inv.Request.Teams != nil || inv.WorkspacePath != "" {
						t.Fatal("synthetic Team or functional source fallback")
					}
					var job struct {
						Spec struct{ Template struct{ Spec corev1.PodSpec } }
					}
					if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
						t.Fatal("actual Redis job decode")
					}
					container := job.Spec.Template.Spec.Containers[0]
					if !strings.Contains(strings.Join(container.Command, " "), "--formal-config /run/backup/formal/materials.json") {
						t.Fatal("source Redis lost formal CLI route")
					}
					found := false
					for _, mount := range container.VolumeMounts {
						if mount.MountPath == "/run/backup/materials/redis-source" && mount.ReadOnly {
							found = true
						}
						if mount.MountPath == "/workspace" {
							t.Fatal("source Redis gained a source filesystem")
						}
					}
					if !found {
						t.Fatal("source Redis lost readonly independent credential mount")
					}
				}
			}
			if redisJobs != 1 || sqlJobs != 1 || instanceJobs != len(users.Source.Instances) || f.ensures != 0 || len(f.events) != 0 {
				t.Fatal("shared original module assembly omitted/duplicated data planes", redisJobs, sqlJobs, instanceJobs)
			}
			if empty && !tr.Descriptor.DependencyOnly {
				t.Fatal("empty Teams manufactured a Job")
			}
		})
	}
	for _, mode := range []string{"missing-shared-part", "wrong-owner", "wrong-source", "wrong-run-id", "wrong-database", "incomplete-prefix", "excluded-team-data"} {
		t.Run(mode, func(t *testing.T) {
			_, users, teams, redis := sourceRedisSharedModuleFixture(t, false)
			policy := redis.Request.Invocation.Request.SourceRedis
			switch mode {
			case "wrong-source":
				policy.Policy.Source.ID = "foreign"
			case "wrong-run-id":
				policy.ServerID = strings.Repeat("d", 40)
			case "wrong-database":
				policy.Policy.DB = 5
			case "incomplete-prefix":
				policy.Policy.Prefixes = []string{"claw:team:20:events:"}
			case "excluded-team-data":
				policy.ExcludePrefixes = []string{"claw:team:20:history:"}
			}
			teams.SharedRedis = policy
			tr, err := NewTeamsModule(teams)
			if mode != "missing-shared-part" && mode != "wrong-owner" {
				if err == nil {
					t.Fatal("incomplete shared Redis scope admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ur, err := NewUsersInstancesModule(users)
			if err != nil {
				t.Fatal(err)
			}
			registrations := []CaptureModuleRegistration{ur, tr}
			if mode == "wrong-owner" {
				rr, err := NewSourceRedisModule(redis)
				if err != nil {
					t.Fatal(err)
				}
				rr.Descriptor.Owner = "C"
				registrations = append(registrations, rr)
			}
			if _, err := NewCaptureModules(registrations, moduleTestContext); err == nil {
				t.Fatal("missing/foreign shared Redis dependency admitted")
			}
		})
	}
}
