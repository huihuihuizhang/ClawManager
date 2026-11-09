package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	batchv1 "k8s.io/api/batch/v1"
)

func TestProductionPlanUsesHeldCloneClaim(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if err := json.Unmarshal(source.CaptureMetadata, &metadata); err != nil {
		t.Fatal(err)
	}
	const partName = "instance_7_workspace"
	name := metadata.Mounts[0].Source.PersistentVolumeClaim.ClaimName
	identity := kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: name, UID: "source-uid", PVName: "source-pv", PVUID: "pv-uid", SHA256: strings.Repeat("a", 64)}
	metadata.MountIdentities = map[string]kube.MountIdentity{partName: identity}
	workerNamespace := operations["capture-workspace"].Workload.Identity.Namespace
	installed := originalLonghornSource{Namespace: "tenant-source", NamespaceUID: "tenant-source-uid", Source: identity}
	plan := installed.plan(in.Authority, workerNamespace, "worker-uid")
	materials := productionCaptureMaterials{Discovery: &productionSourceDiscovery{LonghornSources: map[string]originalLonghornSource{partName: installed}}}
	signedScope, err := sourceMetadataScope(materials)
	if err != nil {
		t.Fatal(err)
	}
	replaced := installed
	replaced.NamespaceUID = "replaced-tenant-uid"
	materials.Discovery.LonghornSources[partName] = replaced
	changedScope, err := sourceMetadataScope(materials)
	if err != nil || changedScope == signedScope || replaced.plan(in.Authority, workerNamespace, "worker-uid") == plan {
		t.Fatalf("changed source namespace identity was not bound: %v", err)
	}
	metadata.LonghornClones = map[string]plannedLonghornClone{partName: plan}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	modules, err := productionCaptureModules(in, source, hold, writers, operations, "fixture-r1")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		if part.Part != partName {
			continue
		}
		var job batchv1.Job
		if err := json.Unmarshal(part.Intent.SpecJSON, &job); err != nil {
			t.Fatal(err)
		}
		for _, volume := range job.Spec.Template.Spec.Volumes {
			if volume.Name == "workspace" && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == plan.Target.Claim.Name && volume.PersistentVolumeClaim.ReadOnly {
				return
			}
		}
	}
	t.Fatal("frozen Job is missing its read-only clone mount")
}
