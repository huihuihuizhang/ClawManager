package scope

import (
	"errors"
	"slices"
	"testing"
)

func pvcStorage() Storage {
	return Storage{Kind: "pvc", Namespace: "source-user", ClaimName: "workspace", ClaimUID: "claim-uid", SubPath: ".", AdditionalMountsKnown: true}
}

func TestPVCOnlyUsesSnapshotWhenCapabilityIsActuallyKnown(t *testing.T) {
	storage := pvcStorage()
	storage.CSIDriver = "driver.longhorn.io"
	storage.SnapshotClass = "longhorn"
	plan, err := PlanStorage(storage, "pro")
	if err != nil || plan.Method != "quiesced_encrypted_copy" || plan.ReleaseGateAt != "encrypted_staging_sealed" {
		t.Fatalf("driver name must not imply successful snapshot support: %+v, %v", plan, err)
	}
	storage.SnapshotProbePassed = true
	plan, err = PlanStorage(storage, "pro")
	if err != nil || plan.Method != "csi_snapshot_then_encrypted_export" || !slices.Contains(plan.RequiredProofs, "snapshot_ready_and_bound") {
		t.Fatalf("expected a verifiable snapshot export plan: %+v, %v", plan, err)
	}
}

func TestHostPathAndNFSRequireSealingBeforeResume(t *testing.T) {
	for _, storage := range []Storage{
		{Kind: "hostpath", NodeName: "storage-worker", HostPath: "/data/clawreef/user-1/instance-2", SubPath: ".", AdditionalMountsKnown: true},
		{Kind: "nfs", NFSServer: "nfs.internal", NFSExport: "/exports/runtime", SubPath: "hermes/user-1/instance-2", Shared: true, AdditionalMountsKnown: true},
	} {
		plan, err := PlanStorage(storage, "pro")
		if err != nil || plan.ReleaseGateAt != "encrypted_staging_sealed" {
			t.Fatalf("unsafe early resume: %+v, %v", plan, err)
		}
		if storage.Kind == "hostpath" && plan.PinToNode != storage.NodeName {
			t.Fatal("HostPath job lost its storage node")
		}
		if storage.Kind == "nfs" && !slices.Contains(plan.RequiredProofs, "all_external_nfs_writers_quiesced") {
			t.Fatal("NFS external writers were not accounted for")
		}
	}
}

func TestSharedStorageCannotCaptureOtherInstances(t *testing.T) {
	for _, relative := range []string{"", ".", "..", "../other", "/workspaces", "instance/../../other", "a/../b", "a//b", "a\\b", "a\x00b", "C:/data", "x/"} {
		storage := pvcStorage()
		storage.Shared = true
		storage.SubPath = relative
		if _, err := PlanStorage(storage, "lite"); !errors.Is(err, ErrStorageUnresolved) {
			t.Errorf("unsafe shared subpath %q: %v", relative, err)
		}
	}
	storage := pvcStorage()
	storage.Shared = true
	storage.SubPath = "hermes/user-1/instance-2"
	if plan, err := PlanStorage(storage, "lite"); err != nil || plan.SubPath != storage.SubPath {
		t.Fatalf("expected instance-scoped directory: %+v, %v", plan, err)
	}
}

func TestStorageRejectsAmbiguousIdentityAndUnsafeRoots(t *testing.T) {
	for _, mutate := range []func(*Storage){
		func(s *Storage) { s.ClaimUID = "" },
		func(s *Storage) { s.AdditionalMountsKnown = false },
		func(s *Storage) { s.SnapshotProbePassed = true },
		func(s *Storage) { s.HostPath = "/also-a-hostpath" },
		func(s *Storage) { s.Kind = "unknown" },
	} {
		storage := pvcStorage()
		mutate(&storage)
		if _, err := PlanStorage(storage, "pro"); !errors.Is(err, ErrStorageUnresolved) {
			t.Fatalf("unresolved storage accepted: %+v, %v", storage, err)
		}
	}
	for _, root := range []string{"/", "/data/../etc", "data", "C:\\data"} {
		storage := Storage{Kind: "hostpath", HostPath: root, NodeName: "node", AdditionalMountsKnown: true}
		if _, err := PlanStorage(storage, "pro"); !errors.Is(err, ErrStorageUnresolved) {
			t.Errorf("unsafe host root %q accepted", root)
		}
	}
	for _, server := range []string{"https://nfs", "password@nfs", "nfs?password=secret", "nfs\nother"} {
		storage := Storage{Kind: "nfs", NFSServer: server, NFSExport: "/exports/data", AdditionalMountsKnown: true}
		if _, err := PlanStorage(storage, "pro"); !errors.Is(err, ErrStorageUnresolved) {
			t.Errorf("credential-bearing or malformed NFS locator accepted")
		}
	}
}
