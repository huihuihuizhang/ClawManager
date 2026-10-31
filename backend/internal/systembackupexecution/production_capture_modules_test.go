package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	sh "clawreef/internal/systembackupskillhub"
	w "clawreef/internal/systembackupwire"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// Pure factory inputs are explicit fixtures, not observed source metadata or
// credentials. Every original constructor and actual Job factory is exercised.
func productionModuleFixture(t *testing.T) (d.Input, b.SourceInventory, time.Time, []b.FrozenWriter, map[string]productionCaptureOperation) {
	t.Helper()
	a, _, _ := resultEvidenceFixture()
	a.ConfigVersion = 1
	a.ClaimOwner = "fixture-controller"
	a.ClaimRowVersion = 19
	a.RequestID = "original-request"
	a.DeadlineAt = time.Now().UTC().Add(3 * time.Minute)
	config := json.RawMessage(`{"original":"pure assembly fixture"}`)
	a.ConfigSHA256 = hash(config)
	in := d.Input{Authority: a, ConfigSnapshot: config, ProfileID: "linux-fixture", ProfileRevision: "r1", Backup: &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "acceptance", RequestedParts: []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}}}
	hold := a.DeadlineAt.Add(-time.Second)
	users := []int{1, 2}
	instances := []b.InstanceIdentity{{ID: 7, UserID: 1, Generation: 3, Type: "openclaw", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux", Status: "running", Namespace: "cm-fixture", Workspace: "/workspaces/1/7"}, {ID: 9, UserID: 2, Generation: 4, Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux", Status: "stopped", Namespace: "cm-fixture", Workspace: "/workspaces/2/9"}}
	teamInventory := &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{{ID: 20, UserID: 1, ResourceScope: "northbound", Owner: "owner-a", Status: "running", SharedMountID: "team_20", RedisScopeID: "redis_a", Members: []team.SourceMember{{ID: 21, InstanceID: 7}}}}, Mounts: []team.SharedMount{{ID: "team_20", TeamID: 20, Namespace: "cm-fixture", PVC: "team-pvc", UID: "team-claim-uid", Root: "/teams/20"}}, Redis: []team.RedisScope{{ID: "redis_a", ServerID: strings.Repeat("a", 40), TeamIDs: []int{20}}}, Objects: []team.ObjectRef{{TeamID: 20, Bucket: "original-bucket", Key: "results/report", Version: "immutable-v1", SHA256: strings.Repeat("b", 64), Size: 3}}}
	facts := &team.SourceFacts{Version: team.SourceFactsVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.TeamSQLFacts{{ID: 20, UserID: 1, ResourceScope: "northbound", Owner: "owner-a", Status: "running", PVC: "team-pvc", Namespace: "cm-fixture", Root: "/teams/20"}}, Members: []team.MemberSQLFacts{{ID: 21, TeamID: 20, UserID: 1, InstanceID: 7}}}
	skills := &sh.CaptureInventory{Version: sh.CaptureInventoryVersion, Skills: []sh.CaptureSkill{{ID: 11, UserID: 1, CurrentVersionID: 13}}, Blobs: []sh.CaptureBlob{{ID: 12, ContentHash: strings.Repeat("a", 32), ObjectKey: "original.zip", SizeBytes: 3}}, Versions: []sh.CaptureVersion{{ID: 13, SkillID: 11, BlobID: 12}}}
	for _, name := range sh.CaptureTableNames() {
		table := sh.CaptureTableKeys{Name: name, SchemaSHA256: strings.Repeat("a", 64), IDs: []int{}}
		switch name {
		case "skills":
			table.IDs = []int{11}
		case "skill_blobs":
			table.IDs = []int{12}
		case "skill_versions":
			table.IDs = []int{13}
		}
		skills.Tables = append(skills.Tables, table)
	}
	source := b.SourceInventory{Database: "original_source", ServerUUID: "b9c4d686-d4d3-11f1-9eb5-745d22085e06", Users: users, Instances: instances, Teams: teamInventory, TeamFacts: facts, Skills: skills}
	var tables []domain.Table
	for _, name := range domain.BusinessCaptureTables() {
		tables = append(tables, domain.Table{Name: name, Engine: "InnoDB", Columns: []domain.Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}, Rows: []domain.Row{}})
	}
	schema, err := domain.BusinessCaptureSchemaForTables(tables)
	if err != nil {
		t.Fatal(err)
	}
	expected := ce.Expected{Scope: ce.Scope{Installation: a.InstallationID, Backup: a.TaskPublicID, Attempt: a.AttemptNo}, ConfigSHA256: a.ConfigSHA256, SourceIdentitySHA256: hash([]byte("source fixture")), SchemaRegistry: ce.RegistryPin{Version: "s1", SHA256: hash([]byte("schema"))}, RedactionRegistry: ce.RegistryPin{Version: "r1", SHA256: hash([]byte("redaction"))}}
	metadata := productionCaptureMetadata{Version: productionCaptureMetadataVersion, SQLSchema: schema, ControlEvidence: controlContentProposal(t, expected).Prepared.Locator, Redis: root.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "redis_a", Version: "v1", SHA256: strings.Repeat("b", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", DB: 0, Prefixes: []string{"claw:team:"}, MaxItems: 100, MaxBytes: 16 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40)}, Skills: worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: skills.SHA256(), Bucket: "skill-bucket", Prefix: "packages", Blobs: []worker.SkillObjectBlobRef{{ID: 12, ObjectKey: "original.zip", SizeBytes: 3}}, Objects: []sh.FrozenObject{{Key: "original.zip", VersionID: "v1", Size: 3, SHA256: strings.Repeat("b", 64)}}, MaxObjects: 10, MaxObjectBytes: 1024, MaxTotalBytes: 1024, MaxIndexBytes: 1 << 16}}
	for _, instance := range instances {
		metadata.Mounts = append(metadata.Mounts, productionInstanceMount{InstanceID: instance.ID, MountID: "workspace", SubPath: strconv.Itoa(instance.ID), Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "instance-pvc", ReadOnly: true}}}, Policy: worker.RuntimePolicy{Version: "fixture-r1", Image: "agent@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: instance.Type, Mode: instance.Mode, Backend: instance.Backend, Variant: instance.Variant, OS: instance.OS}, Files: []worker.FileRule{{Path: "config.json", Fields: []domain.JSONRule{{Path: []string{"enabled"}, Action: "preserve"}}}}}})
	}
	resource := func(part, kind, sa string) worker.ResourceCaptureSpec {
		return worker.ResourceCaptureSpec{Part: part, Namespace: "cm-fixture", NamespaceUID: "source-ns-uid", ServiceAccountName: sa, ServiceAccountUID: sa + "-uid", Selections: []root.KubernetesSelection{{Version: "v1", Resource: kind, Name: "original", UID: "original-uid"}}, MaxItems: 10, OriginalWriters: []worker.ResourceWriterOriginal{}}
	}
	metadata.Deployment = resource("deployment_resources", "configmaps", "resource-reader")
	metadata.Secrets = resource("secret_bundle", "secrets", "secret-reader")
	source.CaptureMetadata, _ = json.Marshal(metadata)
	operations := map[string]productionCaptureOperation{}
	for _, operation := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-team-objects", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation} {
		x := productionCaptureOperation{Request: worker.Request{MaxArchiveBytes: 16 << 20, MaxCompressedBytes: 16 << 20}, Formal: worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), MaxFrames: 64, PermitDelivery: &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}}, Provider: k.Access{Operation: k.Generate, Endpoint: "https://bao.fixture.invalid", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}}}, Workload: kube.JobRequest{Identity: kube.Identity{Namespace: "cm-fixture"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "backup-worker", StagingClaim: "staging-pvc", WorkerControl: &kube.WorkerControl{URL: "https://owner.fixture.invalid", IdentitySecret: "job-identity", BoundPodIdentity: true}, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: strings.TrimPrefix(operation, "capture-") + "-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-original-source", Kind: "Secret", Name: "original-source", Directory: "/run/backup/materials/original", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}}}
		if operation == "capture-workspace" {
			x.Request.MaxFiles = 100
			x.Request.MaxFileBytes = 8 << 20
		}
		if operation == "capture-database" {
			x.Request.Database = &worker.DatabaseSpec{Name: source.Database, ServerUUID: source.ServerUUID, Address: "source.fixture.invalid:3306", TLSServerName: "source.fixture.invalid", RootCA: []byte("named public CA fixture"), MaxRows: 100000, MaxMemoryBytes: 16 << 20, SchemaCensus: &domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: "original_owner@localhost", DefinitionSHA256: strings.Repeat("a", 64)}}
		}
		x.Workload.DeadlineSeconds = 30
		operations[operation] = x
	}
	writers := []b.FrozenWriter{{ID: "original-writer", Original: flow.State{UID: "original-writer-uid", Generation: 3, Running: true, Checkpoint: "original-checkpoint"}}}
	return in, source, hold, writers, operations
}

func TestProductionSixPartFactoryUsesAllOriginalConstructorsAndGlobalIndices(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	catalog, err := productionCaptureModules(in, source, hold, writers, operations, "r1")
	if err != nil {
		t.Fatal("construct", err)
	}
	parts, err := catalog.BuildParts(in, source, hold)
	if err != nil || len(parts) != 11 {
		t.Fatal("all six storage parts including original paired control streams", len(parts), err)
	}
	seen := map[string]bool{}
	configs := map[string]bool{}
	identities := map[string]bool{}
	sql, control := 0, 0
	for index, part := range parts {
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil {
			t.Fatal("decode")
		}
		if seen[part.Part] || configs[part.InvocationConfigMap] || invocation.Request.Binding.PartIndex != uint32(index) || invocation.ProviderKey.Request.Context.PartIndex != strconv.Itoa(index) {
			t.Fatal("duplicate or wrong global binding", part.Part)
		}
		seen[part.Part], configs[part.InvocationConfigMap] = true, true
		var job batchv1.Job
		if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
			t.Fatal("actual Job decode")
		}
		identity := ""
		for _, volume := range job.Spec.Template.Spec.Volumes {
			if volume.Name == "worker-identity" && volume.Secret != nil {
				identity = volume.Secret.SecretName
			}
		}
		if identity == "" || identities[identity] || identity != part.Intent.Name+"-identity" {
			t.Fatal("actual identity mount reused or mismatched", part.Part, identity)
		}
		identities[identity] = true
		if invocation.Request.Database != nil {
			sql++
		}
		if invocation.Request.ControlEvidence != nil {
			control++
		}
	}
	if sql != 1 || control != 2 {
		t.Fatal("shared SQL/control cardinality", sql, control)
	}
	for _, part := range []string{b.UsersInstancesDatabasePart, b.SourceRedisPart, b.SkillObjectsPart, "deployment_resources", "secret_bundle", ce.Part, ce.ProofPart, "instance_7_workspace", "instance_9_workspace", "team_20_workspace", "teams_objects"} {
		if !seen[part] {
			t.Fatal("missing actual part", part)
		}
	}
	// Templates and original writer slices stay caller-owned. Mutating them
	// after construction must leave the exact original plan bytes unchanged.
	operations[ce.Operation].Formal.PermitDelivery.Issuer[0] ^= 1
	operations["capture-workspace"].Workload.WorkerControl.InvocationConfigMap = "foreign"
	operations["capture-database"].Request.Database.Name = "foreign"
	writers[0].Original.Checkpoint = "foreign"
	after, err := catalog.BuildParts(in, source, hold)
	beforeRaw, _ := json.Marshal(parts)
	afterRaw, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatal("caller mutated frozen factory plan", err)
	}
}

func TestProductionSixPartFactoryRejectsMissingOrMismatchedOriginalInputs(t *testing.T) {
	for _, fault := range []string{"missing-operation", "missing-primary", "duplicate-mount", "different-team", "wrong-policy", "missing-control", "wrong-control-scope", "missing-deployment-writer", "wrong-deployment-uid"} {
		t.Run(fault, func(t *testing.T) {
			in, source, hold, writers, operations := productionModuleFixture(t)
			var metadata productionCaptureMetadata
			json.Unmarshal(source.CaptureMetadata, &metadata)
			switch fault {
			case "missing-operation":
				delete(operations, ce.Operation)
			case "missing-primary":
				metadata.Mounts = metadata.Mounts[:1]
			case "duplicate-mount":
				metadata.Mounts = append(metadata.Mounts, metadata.Mounts[0])
			case "different-team":
				source.TeamFacts.Teams[0].Owner = "foreign"
			case "wrong-policy":
				metadata.SQLSchema.PolicySHA256 = strings.Repeat("0", 64)
			case "missing-control":
				metadata.ControlEvidence = ce.CaptureLocator{}
			case "wrong-control-scope":
				metadata.ControlEvidence.Expected.Backup = "sbk_foreign"
			case "missing-deployment-writer", "wrong-deployment-uid":
				metadata.Deployment.Selections = []root.KubernetesSelection{{Group: "apps", Version: "v1", Resource: "deployments", Name: "original", UID: "original-deployment-uid"}}
				if fault == "wrong-deployment-uid" {
					writers = append(writers, b.FrozenWriter{ID: "deployment/cm-fixture/original", Original: flow.State{UID: "foreign-uid", Generation: 3, Checkpoint: "original"}})
				}
			}
			source.CaptureMetadata, _ = json.Marshal(metadata)
			catalog, err := productionCaptureModules(in, source, hold, writers, operations, "r1")
			if err == nil {
				_, err = catalog.BuildParts(in, source, hold)
			}
			if err == nil {
				t.Fatal("incomplete original assembly accepted")
			}
		})
	}
}

func TestProductionFactoryReconstructionKeepsOriginalJobDurationAndBytes(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	first, err := productionCaptureModules(in, source, hold, writers, operations, "stable-r1")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := first.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(parts)
	// Rebuilding across a wall-clock second must not mint a different original
	// Job deadline/spec hash for identical frozen inputs.
	time.Sleep(1100 * time.Millisecond)
	second, err := productionCaptureModules(in, source, hold, writers, operations, "stable-r1")
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := second.BuildParts(in, source, hold)
	after, _ := json.Marshal(rebuilt)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("same original inputs rebuilt different Job/Invocation bytes", err)
	}
	for _, fault := range []int64{0, 3601, int64(time.Until(hold).Seconds()) + 1} {
		operation := operations["capture-workspace"]
		operation.Workload.DeadlineSeconds = fault
		operations["capture-workspace"] = operation
		candidate, err := productionCaptureModules(in, source, hold, writers, operations, "stable-r1")
		if err == nil {
			_, err = candidate.BuildParts(in, source, hold)
		}
		if err == nil {
			t.Fatal("missing/outside original hold template duration accepted", fault)
		}
	}
}
