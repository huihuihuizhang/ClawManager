package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
)

func TestProductionPersistentMountFactoryBuildsAdditionalOriginalJob(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil || len(metadata.Mounts) == 0 {
		t.Fatal("invalid fixture")
	}
	extra := metadata.Mounts[0]
	extra.MountID, extra.DataOnly, extra.SubPath = "documents", true, "users/1/instances/7/documents"
	extra.Source = *extra.Source.DeepCopy()
	extra.Source.PersistentVolumeClaim.ClaimName = "documents-pvc"
	extra.WorkBuddy, extra.Skills = nil, nil
	metadata.Mounts = append(metadata.Mounts, extra)
	if metadata.MountIdentities == nil {
		metadata.MountIdentities = map[string]kube.MountIdentity{}
	}
	metadata.MountIdentities["instance_7_documents"] = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: "documents-pvc", UID: "documents-uid", PVName: "documents-pv", PVUID: "documents-pv-uid", SHA256: strings.Repeat("a", 64)}
	metadata.FormalMountIdentities = map[string][]kube.MountIdentity{}
	for operation, template := range operations {
		formal := template.Workload.FormalMaterials
		refs := []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: formal.ConfigMap, UID: "mapping-uid", SHA256: strings.Repeat("b", 64)}}
		for _, input := range formal.Inputs {
			refs = append(refs, kube.MountIdentity{Volume: input.Volume, Kind: input.Kind, Name: input.Name, UID: "input-uid", SHA256: strings.Repeat("c", 64)})
		}
		metadata.FormalMountIdentities[operation] = refs
	}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	modules, err := productionCaptureModules(in, source, hold, writers, operations, "fixture-r1")
	if err != nil {
		t.Fatal("production construction", err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal("production Job assembly", err)
	}
	found, primary, sql := false, false, 0
	for _, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil {
			t.Fatal("invocation")
		}
		if inv.Request.Operation == "capture-database" {
			sql++
		}
		if part.Part == "instance_7_workspace" {
			primary = inv.Request.RuntimePolicy != nil
		}
		if part.Part == "instance_7_documents" {
			found = true
			if inv.Request.RuntimePolicy != nil || inv.Request.WorkBuddyIdentity != nil || inv.Request.SkillWorkspace != nil || inv.Request.Binding.BackupID != in.Authority.TaskPublicID || inv.ProviderKey == nil || inv.FormalCapture == nil {
				t.Fatal("extra mount changed original worker/key path")
			}
			refs, err := productionPartMounts(metadata, part)
			if err != nil {
				t.Fatal("original observer did not consume extra pin", err)
			}
			matched := false
			for _, ref := range refs {
				matched = matched || ref.Name == "documents-pvc" && ref.UID == "documents-uid"
			}
			if !matched {
				t.Fatal("extra mount pin missing")
			}
		}
	}
	if !found || !primary || sql != 1 {
		t.Fatal("primary or atomic SQL changed")
	}
}

func TestProductionPersistentMappingsAreInOriginalSignedScope(t *testing.T) {
	materials := productionCaptureMaterials{Discovery: &productionSourceDiscovery{}}
	before, err := sourceMetadataScope(materials)
	if err != nil {
		t.Fatal(err)
	}
	materials.Discovery.PersistentMounts = &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{}}
	after, err := sourceMetadataScope(materials)
	if err != nil || after == before {
		t.Fatal("new mount contract omitted from source grant")
	}
	materials.Discovery.PersistentMounts.Mounts = []productionPersistentMountBinding{{InstanceID: 7, MountID: "data", DataPath: "/private/owned"}}
	changed, err := sourceMetadataScope(materials)
	if err != nil || changed == after {
		t.Fatal("mount scope can change without grant mismatch")
	}
}
