package publicadapter

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
)

func finalSkillWorkspaceFixture(t *testing.T, unpackaged bool) (SourceInventory, []JobPart) {
	t.Helper()
	f, users, skills := skillModuleFixture(t)
	if unpackaged {
		inventory := users.Source.Skills
		inventory.Blobs[0].ObjectKey = ""
		inventory.Bindings = []sh.CaptureBinding{{ID: 14, InstanceID: 7, SkillID: 11, SkillVersionID: 13, WorkspaceDir: "demo", ObservedHash: strings.Repeat("a", 32)}}
		for n := range inventory.Tables {
			if inventory.Tables[n].Name == "instance_skills" {
				inventory.Tables[n].IDs = []int{14}
			}
		}
		skills.Source = cloneSourceInventory(users.Source)
		spec := skills.Objects.Invocation.Request.SkillObjects
		spec.Blobs[0].ObjectKey = ""
		spec.WorkspaceRequiredBlobIDs = []int{12}
		spec.InventorySHA256 = inventory.SHA256()
		skills.Workspaces = map[int]string{7: instanceMountPart(7, "workspace")}
		r := &users.Workspaces[0].Request
		i := &r.Invocation
		requirements, err := inventory.WorkspaceRequirements()
		if err != nil {
			t.Fatal(err)
		}
		i.Request.SkillWorkspace = &sh.WorkspaceCaptureSpec{Version: sh.WorkspaceCaptureVersion, InventorySHA256: inventory.SHA256(), InstanceID: 7, MountID: "workspace", Runtime: i.Request.RuntimePolicy.Runtime, SkillRoot: "home/.openclaw/workspace/skills", Requirements: requirements, MaxFiles: i.Request.MaxFiles, MaxBytes: i.Request.MaxFileBytes, MaxProofBytes: 1 << 20}
		provider := *skills.Objects.Invocation.ProviderKey
		i.ProviderKey = &provider
		provider.Request.Context.Part = r.Part
		provider.Request.Context.PartIndex = "1"
		i.Request.Binding.PartIndex = 1
		formal := *skills.Objects.Invocation.FormalCapture
		i.FormalCapture = &formal
		formal.EnvelopeName = "original-instance.envelope"
		r.Workload.FormalMaterials = skills.Objects.Workload.FormalMaterials
	}
	usersModule, err := NewUsersInstancesModule(users)
	if err != nil {
		t.Fatal(err)
	}
	skillsModule, err := NewSkillObjectsModule(skills)
	if err != nil {
		t.Fatal(err)
	}
	modules, err := NewCaptureModules([]CaptureModuleRegistration{usersModule, skillsModule}, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(f.in, users.Source, f.x.HoldUntil)
	if err != nil {
		t.Fatal(err)
	}
	return users.Source, parts
}

func TestValidateFinalSkillWorkspacePartsAcceptsPackagedAndUnpackaged(t *testing.T) {
	for _, unpackaged := range []bool{false, true} {
		source, parts := finalSkillWorkspaceFixture(t, unpackaged)
		// Only authenticated original declarations are needed after local cleanup.
		for n, part := range parts {
			parts[n] = JobPart{Part: part.Part, Category: part.Category, InvocationJSON: part.InvocationJSON, InvocationSHA256: part.InvocationSHA256}
		}
		if err := ValidateFinalSkillWorkspaceParts(source, parts); err != nil {
			t.Fatalf("unpackaged=%v: %v", unpackaged, err)
		}
	}
}

func TestValidateFinalSkillWorkspacePartsRejectsBrokenRelationships(t *testing.T) {
	for _, mode := range []string{"nil-inventory", "invalid-json", "unknown-json-field", "wrong-version", "wrong-invocation-hash", "wrong-binding-part", "wrong-part", "wrong-category", "wrong-runtime", "wrong-inventory", "wrong-requirement", "wrong-blob", "wrong-binding", "wrong-md5", "wrong-mount", "missing-formal", "missing-provider", "missing-workspace", "missing-spec", "empty-parts"} {
		t.Run(mode, func(t *testing.T) {
			source, parts := finalSkillWorkspaceFixture(t, true)
			index := -1
			var inv worker.Invocation
			for n, part := range parts {
				if err := json.Unmarshal(part.InvocationJSON, &inv); err != nil {
					t.Fatal(err)
				}
				if inv.Request.SkillWorkspace != nil {
					index = n
					break
				}
			}
			if index < 0 {
				t.Fatal("fixture lacks unpackaged workspace")
			}
			switch mode {
			case "nil-inventory":
				source.Skills = nil
			case "invalid-json":
				parts[index].InvocationJSON = json.RawMessage(`{`)
			case "unknown-json-field":
				parts[index].InvocationJSON = append(parts[index].InvocationJSON[:len(parts[index].InvocationJSON)-1:len(parts[index].InvocationJSON)-1], []byte(`,"foreign":true}`)...)
			case "wrong-invocation-hash":
				parts[index].InvocationSHA256 = strings.Repeat("f", 64)
			case "wrong-part":
				parts[index].Part = "instance_9_workspace"
			case "wrong-category":
				parts[index].Category = "teams"
			case "missing-workspace":
				parts = append(parts[:index:index], parts[index+1:]...)
			case "empty-parts":
				parts = nil
			default:
				switch mode {
				case "wrong-version":
					inv.Request.Version = "foreign.v1"
				case "wrong-binding-part":
					inv.Request.Binding.Path = "foreign"
				case "wrong-runtime":
					inv.Request.SkillWorkspace.Runtime.Type = "hermes"
					inv.Request.SkillWorkspace.SkillRoot = "home/.hermes/skills"
					inv.Request.RuntimePolicy.Runtime.Type = "hermes"
				case "wrong-inventory":
					inv.Request.SkillWorkspace.InventorySHA256 = strings.Repeat("f", 64)
				case "wrong-requirement":
					inv.Request.SkillWorkspace.Requirements[0].WorkspaceDirectory = "foreign"
				case "wrong-blob":
					inv.Request.SkillWorkspace.Requirements[0].BlobID = 99
				case "wrong-binding":
					inv.Request.SkillWorkspace.Requirements[0].BindingID = 99
				case "wrong-md5":
					inv.Request.SkillWorkspace.Requirements[0].ContentMD5 = strings.Repeat("b", 32)
				case "wrong-mount":
					inv.Request.SkillWorkspace.MountID = "other"
				case "missing-formal":
					inv.FormalCapture = nil
				case "missing-provider":
					inv.ProviderKey = nil
				case "missing-spec":
					inv.Request.SkillWorkspace = nil
				}
				var err error
				parts[index].InvocationJSON, err = json.Marshal(inv)
				if err != nil {
					t.Fatal(err)
				}
				parts[index].InvocationSHA256, err = inv.Hash()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := ValidateFinalSkillWorkspaceParts(source, parts); err == nil {
				t.Fatal("accepted incomplete or mismatched Skills workspace declarations")
			}
		})
	}
}
