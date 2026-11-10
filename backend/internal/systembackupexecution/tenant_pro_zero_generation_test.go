package systembackupexecution

import (
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
)

// A running desktop Pro row can predate gateway generation tracking. Its
// tenant Deployment/Pod UID chain supplies the writer identity, so zero is a
// valid original generation for exactly that shape and nothing wider.
func tenantProZeroGenerationMount() runningTenantProMount {
	return runningTenantProMount{
		Source: b.InstanceIdentity{
			ID: 2, UserID: 1, Generation: 0, Mode: "pro", Backend: "desktop",
			OS: "linux", Status: "running", Pod: "clawreef-2-deployment-5bc5b96b4d-sk95t",
			Namespace: "clawmanager-sbk-validation-user-1", Workspace: "/config",
		},
		NamespaceUID:  "2aca1e25-1247-4866-8394-32e385170047",
		PodUID:        "9eee51a5-54e2-40c9-8b0d-904304322ebd",
		PodSpecSHA256: strings.Repeat("a", 64),
		ReplicaSetUID: "b98c7473-fe1b-4138-a7c6-52ab89ab850b",
		Deployment:    "clawreef-2-deployment",
		DeploymentUID: "ae62057d-36bb-46d3-897b-bcbd40cde1b3",
		Identity: kube.MountIdentity{
			Volume: "workspace", Kind: "PersistentVolumeClaim",
			Name: "clawreef-2-pvc", UID: "a1af1c62-2b32-412c-8acb-7c954929e547",
			PVName: "pvc-a1af1c62", PVUID: "e83b0f11-a781-4372-9f74-9b3cc3c68d13",
			SHA256: strings.Repeat("b", 64),
		},
	}
}

func TestRunningTenantProMountAcceptsZeroGeneration(t *testing.T) {
	mount := tenantProZeroGenerationMount()
	if !mount.valid() {
		t.Fatal("zero-generation running desktop Pro mount must be accepted")
	}
}

func TestRunningTenantProMountRejectsGenerationAndPodDrift(t *testing.T) {
	mount := tenantProZeroGenerationMount()
	negative := tenantProZeroGenerationMount()
	negative.Source.Generation = -1
	if negative.valid() {
		t.Fatal("negative generation must be rejected")
	}
	lite := tenantProZeroGenerationMount()
	lite.Source.Mode = "lite"
	if lite.valid() {
		t.Fatal("zero generation must stay limited to desktop Pro")
	}
	spec := b.RuntimeWriterSpec{Source: mount.Source, Kind: "deployment", Name: mount.Deployment, UID: mount.DeploymentUID}
	if !mount.matchesWriter(spec) {
		t.Fatal("matching deployment writer must be accepted")
	}
	drift := spec
	drift.UID = "another-deployment"
	if mount.matchesWriter(drift) {
		t.Fatal("deployment UID drift must be rejected")
	}
	drift = spec
	drift.Name = "another-deployment"
	if mount.matchesWriter(drift) {
		t.Fatal("deployment name drift must be rejected")
	}
}
