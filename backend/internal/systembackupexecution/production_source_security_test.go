package systembackupexecution

import (
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	batchv1 "k8s.io/api/batch/v1"
)

func TestProductionOriginalPerOperationAndPartMountPins(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("metadata")
	}
	metadata.FormalMountIdentities = map[string][]kube.MountIdentity{}
	metadata.MountIdentities = map[string]kube.MountIdentity{}
	for name, operation := range operations {
		formal := operation.Workload.FormalMaterials
		pins := []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: formal.ConfigMap, UID: name + "-mapping-uid", SHA256: hash([]byte(name))}}
		for _, input := range formal.Inputs {
			pins = append(pins, kube.MountIdentity{Volume: input.Volume, Kind: input.Kind, Name: input.Name, UID: name + "-input-uid", SHA256: hash([]byte(name + "-input"))})
		}
		operation.MountIdentities = pins
		if !validProductionOperationMounts(operation) {
			t.Fatal("original operation pins refused", name)
		}
		metadata.FormalMountIdentities[name] = pins
	}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	modules, err := productionCaptureModules(in, source, hold, writers, operations, "mount-pins")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		var job batchv1.Job
		if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
			t.Fatal("Job")
		}
		for _, volume := range job.Spec.Template.Spec.Volumes {
			if volume.Name == "workspace" && volume.PersistentVolumeClaim != nil {
				metadata.MountIdentities[part.Part] = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: volume.PersistentVolumeClaim.ClaimName, UID: part.Part + "-claim-uid", PVName: part.Part + "-pv", PVUID: part.Part + "-pv-uid", SHA256: hash([]byte(part.Part))}
			}
		}
		pins, err := productionPartMounts(metadata, part)
		if err != nil || len(pins) < 2 {
			t.Fatal("actual original per-part pins", part.Part, err)
		}
		for _, pin := range pins {
			if pin.Volume == "formal-mapping" {
				// Exact expected source mapping is checked below independently of
				// Job volume ordering; operations intentionally reuse volume names.
				found := false
				for _, volume := range job.Spec.Template.Spec.Volumes {
					found = found || volume.Name == pin.Volume && volume.ConfigMap != nil && volume.ConfigMap.Name == pin.Name
				}
				if !found {
					t.Fatal("global formal alias substituted")
				}
			}
		}
	}
	var workspace b.JobPart
	for _, part := range parts {
		if part.Part == "instance_7_workspace" {
			workspace = part
		}
	}
	if workspace.Part == "" {
		t.Fatal("workspace omitted")
	}
	raw, _ := json.Marshal(metadata)
	for _, fault := range []string{"missing-operation", "wrong-configmap", "missing-formal-input", "duplicate-volume", "missing-source", "wrong-source-name", "missing-pv-uid"} {
		t.Run(fault, func(t *testing.T) {
			var changed productionCaptureMetadata
			json.Unmarshal(raw, &changed)
			refs := changed.FormalMountIdentities["capture-workspace"]
			switch fault {
			case "missing-operation":
				delete(changed.FormalMountIdentities, "capture-workspace")
			case "wrong-configmap":
				refs[0].Name = "another-operation-materials"
			case "missing-formal-input":
				changed.FormalMountIdentities["capture-workspace"] = refs[:1]
			case "duplicate-volume":
				changed.FormalMountIdentities["capture-workspace"] = append(refs, refs[0])
			case "missing-source":
				delete(changed.MountIdentities, workspace.Part)
			case "wrong-source-name":
				pin := changed.MountIdentities[workspace.Part]
				pin.Name = "another-source"
				changed.MountIdentities[workspace.Part] = pin
			case "missing-pv-uid":
				pin := changed.MountIdentities[workspace.Part]
				pin.PVUID = ""
				changed.MountIdentities[workspace.Part] = pin
			}
			if _, err := productionPartMounts(changed, workspace); err == nil {
				t.Fatal("foreign/incomplete original part pins accepted")
			}
		})
	}
}
