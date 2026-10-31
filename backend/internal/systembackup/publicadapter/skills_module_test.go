package publicadapter

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
	corev1 "k8s.io/api/core/v1"
)

func skillModuleFixture(t *testing.T) (*fixture, UsersInstancesModuleConfig, SkillObjectsModuleConfig) {
	t.Helper()
	f, b, c := teamsModuleFixture(t)
	b.Source.Teams = nil
	inventory := &sh.CaptureInventory{Version: sh.CaptureInventoryVersion, Skills: []sh.CaptureSkill{{ID: 11, UserID: 1, CurrentVersionID: 13}}, Blobs: []sh.CaptureBlob{{ID: 12, ContentHash: strings.Repeat("a", 32), ObjectKey: "original.zip", SizeBytes: 3}}, Versions: []sh.CaptureVersion{{ID: 13, SkillID: 11, BlobID: 12}}}
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
		inventory.Tables = append(inventory.Tables, table)
	}
	b.Source.Skills = inventory
	r := *c.Objects
	r.Part, r.Category, r.JobUnitKey = SkillObjectsPart, "skill_hub", SkillObjectsPart
	i := &r.Invocation
	i.Request.Operation = "capture-skill-objects"
	i.Request.Teams = nil
	i.Request.SkillObjects = &worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: inventory.SHA256(), Bucket: "skill-bucket", Prefix: "packages", Blobs: []worker.SkillObjectBlobRef{{ID: 12, ObjectKey: "original.zip", SizeBytes: 3}}, Objects: []sh.FrozenObject{{Key: "original.zip", VersionID: "v1", Size: 3, SHA256: strings.Repeat("b", 64)}}, MaxObjects: 10, MaxObjectBytes: 1024, MaxTotalBytes: 1024, MaxIndexBytes: 1 << 16}
	i.Request.Binding.Path = SkillObjectsPart
	i.Request.Binding.PartIndex = 0
	i.ProviderKey.Request.Context.Part = SkillObjectsPart
	i.ProviderKey.Request.Context.PartIndex = "0"
	r.Workload.Identity.Name = "capture-skills"
	r.Workload.WorkerControl.InvocationConfigMap = "invoke-skills"
	r.Workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "skill-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-skill-source", Kind: "Secret", Name: "original-skill-source", Directory: "/run/backup/materials/skill-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}
	f.in.Backup.RequestedParts = []string{"mysql", "workspace", "object_storage"}
	return f, b, SkillObjectsModuleConfig{Revision: "skill-r1", Source: cloneSourceInventory(b.Source), Objects: r}
}

func TestSkillsModuleBuildsActualJobWithOneSharedSQLDependency(t *testing.T) {
	f, b, c := skillModuleFixture(t)
	br, err := NewUsersInstancesModule(b)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := NewSkillObjectsModule(c)
	if err != nil {
		t.Fatal(err)
	}
	point, _ := moduleTestContext(f.in, b.Source, f.x.HoldUntil, "")
	requests, err := sr.Build(CaptureModuleInput{Input: f.in, Source: b.Source, Context: point, Parts: []CaptureModuleSelection{{CaptureModulePart: sr.Descriptor.Parts[0], PartIndex: 0}}})
	if err != nil {
		t.Fatal("concrete Skills builder", err)
	}
	if _, err := BuildCapturePart(f.in, f.x.HoldUntil, requests[0]); err != nil {
		t.Fatal("concrete Skills Job", err)
	}
	if _, err = NewCaptureModules([]CaptureModuleRegistration{sr}, moduleTestContext); err == nil {
		t.Fatal("accepted Skills without shared atomic SQL")
	}
	m, err := NewCaptureModules([]CaptureModuleRegistration{br, sr}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	c.Objects.Invocation.Request.SkillObjects.Objects[0].VersionID = "changed"
	c.Source.Skills.Blobs[0].ObjectKey = "changed.zip"
	parts, err := m.BuildParts(f.in, b.Source, f.x.HoldUntil)
	if err != nil || len(parts) != 4 {
		t.Fatal("actual Skills materialization", len(parts), err)
	}
	skills, databases := 0, 0
	for n, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil || inv.Request.Binding.PartIndex != uint32(n) {
			t.Fatal("global index")
		}
		if inv.Request.Database != nil {
			databases++
			if inv.Request.Database.SkillsInventory == nil || inv.Request.Database.SkillsInventory.SHA256() != b.Source.Skills.SHA256() {
				t.Fatal("shared SQL lost original Skills inventory contract")
			}
		}
		if inv.Request.SkillObjects == nil {
			continue
		}
		skills++
		if inv.Request.Teams != nil || inv.WorkspacePath != "" || inv.Request.SkillObjects.Objects[0].VersionID != "v1" || inv.ProviderKey.Request.Context.PartIndex != strconv.Itoa(n) {
			t.Fatal("borrowed Team identity or mutable provider context")
		}
		var job map[string]any
		if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
			t.Fatal("actual Job missing")
		}
	}
	if skills != 1 || databases != 1 || f.ensures != 0 {
		t.Fatal("duplicated SQL or dispatched while building")
	}
	drift := cloneSourceInventory(b.Source)
	drift.Skills.Blobs[0].SizeBytes++
	if out, err := m.BuildParts(f.in, drift, f.x.HoldUntil); err == nil || out != nil {
		t.Fatal("discovered Skills drift accepted")
	}
}

func TestSkillsModuleFailsClosedWithoutWorkspaceProofOrExactInventory(t *testing.T) {
	for _, mode := range []string{"unpackaged", "wrong-inventory", "wrong-request-version", "foreign-blob", "duplicate-user", "mixed-team", "missing-materials"} {
		t.Run(mode, func(t *testing.T) {
			_, _, c := skillModuleFixture(t)
			switch mode {
			case "unpackaged":
				c.Source.Skills.Blobs[0].ObjectKey = ""
				c.Objects.Invocation.Request.SkillObjects.Blobs[0].ObjectKey = ""
				c.Objects.Invocation.Request.SkillObjects.WorkspaceRequiredBlobIDs = []int{12}
				c.Objects.Invocation.Request.SkillObjects.InventorySHA256 = c.Source.Skills.SHA256()
			case "wrong-inventory":
				c.Objects.Invocation.Request.SkillObjects.InventorySHA256 = strings.Repeat("f", 64)
			case "wrong-request-version":
				c.Objects.Invocation.Request.Version = "foreign.v99"
			case "foreign-blob":
				c.Objects.Invocation.Request.SkillObjects.Blobs[0].ObjectKey = "foreign.zip"
			case "duplicate-user":
				c.Source.Users = append(c.Source.Users, 1)
			case "mixed-team":
				c.Objects.Invocation.Request.Teams = &worker.TeamCaptureSpec{}
			case "missing-materials":
				c.Objects.Workload.FormalMaterials = nil
			}
			if _, err := NewSkillObjectsModule(c); err == nil {
				t.Fatal("unsafe/incomplete Skills module admitted", mode)
			}
		})
	}
}
