package scope

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func inventoryInput() Input {
	return Input{
		Orchestrator: "kubernetes", Profile: "cluster", TotalUsers: 2, TotalInstances: 2,
		Users: []User{{ID: 1, Role: "admin", HasPasswordHash: true}, {ID: 2, Role: "user", AuthProvider: "ldap"}},
		Instances: []Instance{
			{ID: 11, UserID: 1, Runtime: Runtime{Type: "hermes", Mode: "pro"}, Mounts: []Mount{{ContainerPath: "/config", Storage: pvcStorage()}}},
			{ID: 12, UserID: 2, Runtime: Runtime{Type: "opencode", Mode: "lite"}, Mounts: []Mount{{ContainerPath: "/workspaces/opencode/user-2/instance-12", Storage: Storage{Kind: "nfs", NFSServer: "nfs.internal", NFSExport: "/exports/runtime", SubPath: "opencode/user-2/instance-12", Shared: true, AdditionalMountsKnown: true}}}},
		},
	}
}

func TestInventoryOrderDoesNotChangeFingerprintOrMutateInput(t *testing.T) {
	input := inventoryInput()
	before, _ := json.Marshal(input)
	first, err := BuildInventory(input)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("planner mutated source input")
	}
	slices.Reverse(input.Users)
	slices.Reverse(input.Instances)
	second, err := BuildInventory(input)
	if err != nil {
		t.Fatal(err)
	}
	firstHash, _ := first.Fingerprint()
	secondHash, _ := second.Fingerprint()
	if firstHash == "" || firstHash != secondHash {
		t.Fatalf("unstable inventory fingerprint: %s != %s", firstHash, secondHash)
	}
	if first.TargetPowerState != "stopped" || first.SourceResumePolicy != "restore_pre_capture_state" || len(first.Dependencies) != 4 {
		t.Fatal("lost lifecycle policy or cross-domain dependency")
	}
}

func TestInventoryRejectsPartialAndInconsistentSources(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"partial users":        func(in *Input) { in.TotalUsers++ },
		"partial instances":    func(in *Input) { in.TotalInstances++ },
		"missing owner":        func(in *Input) { in.Instances[0].UserID = 99 },
		"duplicate user":       func(in *Input) { in.Users[1].ID = in.Users[0].ID },
		"duplicate instance":   func(in *Input) { in.Instances[1].ID = in.Instances[0].ID },
		"missing local hash":   func(in *Input) { in.Users[0].HasPasswordHash = false },
		"unsupported provider": func(in *Input) { in.Users[0].AuthProvider = "unknown" },
		"no admin":             func(in *Input) { in.Users[0].Role = "user" },
		"wrong deployment":     func(in *Input) { in.Orchestrator = "docker-compose" },
		"unknown profile":      func(in *Input) { in.Profile = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			input := inventoryInput()
			mutate(&input)
			if plan, err := BuildInventory(input); !errors.Is(err, ErrInvalidInventory) || plan != nil {
				t.Fatalf("partial plan must not escape: %+v, %v", plan, err)
			}
		})
	}
}

func TestOneUnsupportedInstanceBlocksTheEntireInventory(t *testing.T) {
	input := inventoryInput()
	input.Instances[1].Runtime = Runtime{Type: "codex", Mode: "pro", Variant: "windows"}
	if plan, err := BuildInventory(input); !errors.Is(err, ErrWindowsExcluded) || plan != nil {
		t.Fatalf("must not silently omit Windows: %+v, %v", plan, err)
	}
	input = inventoryInput()
	input.Instances[1].Mounts = nil
	if plan, err := BuildInventory(input); !errors.Is(err, ErrStorageUnresolved) || plan != nil {
		t.Fatalf("must not omit unlocated files: %+v, %v", plan, err)
	}
}

func TestInventoryIncludesAllAdditionalPersistentMounts(t *testing.T) {
	input := inventoryInput()
	input.Instances[0].Mounts = append(input.Instances[0].Mounts, Mount{ContainerPath: "/projects", Storage: Storage{Kind: "hostpath", HostPath: "/data/projects", NodeName: "worker-1", AdditionalMountsKnown: true}})
	plan, err := BuildInventory(input)
	if err != nil || len(plan.Instances[0].Mounts) != 2 {
		t.Fatalf("additional data mount was dropped: %+v, %v", plan, err)
	}
	input.Instances[0].Mounts[1].ContainerPath = "/config"
	if plan, err := BuildInventory(input); !errors.Is(err, ErrStorageUnresolved) || plan != nil {
		t.Fatal("ambiguous duplicate mount accepted")
	}
}

func TestLegacyNFSPlanningDoesNotClaimSharedP0ContractSupport(t *testing.T) {
	input := inventoryInput()
	input.Profile = "legacy-nfs"
	plan, err := BuildInventory(input)
	if err != nil || !plan.LegacyNFSContractExtension {
		t.Fatalf("NFS extension was not identified: %+v, %v", plan, err)
	}
}

func TestDifferentInstancesCannotClaimOverlappingSourceData(t *testing.T) {
	for name, pair := range map[string][2]Storage{
		"same PVC": {pvcStorage(), pvcStorage()},
		"shared PVC ancestor": {
			{Kind: "pvc", Namespace: "source-user", ClaimName: "workspace", ClaimUID: "claim-uid", SubPath: "home", Shared: true, AdditionalMountsKnown: true},
			{Kind: "pvc", Namespace: "source-user", ClaimName: "workspace", ClaimUID: "claim-uid", SubPath: "home/instance-2", Shared: true, AdditionalMountsKnown: true},
		},
		"host directory ancestor": {
			{Kind: "hostpath", HostPath: "/data/runtime", NodeName: "node", AdditionalMountsKnown: true},
			{Kind: "hostpath", HostPath: "/data/runtime/instance-2", NodeName: "node", AdditionalMountsKnown: true},
		},
		"NFS export ancestor": {
			{Kind: "nfs", NFSServer: "nfs.internal", NFSExport: "/exports/runtime", AdditionalMountsKnown: true},
			{Kind: "nfs", NFSServer: "NFS.INTERNAL", NFSExport: "/exports/runtime/instance-2", AdditionalMountsKnown: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := inventoryInput()
			for i := range 2 {
				input.Instances[i].Runtime = Runtime{Type: "hermes", Mode: "pro"}
				input.Instances[i].Mounts = []Mount{{ContainerPath: "/config", Storage: pair[i]}}
			}
			if plan, err := BuildInventory(input); plan != nil || !errors.Is(err, ErrStorageUnresolved) {
				t.Fatalf("overlapping source could mix user data: %+v, %v", plan, err)
			}
		})
	}
}

func TestSharedPVCAllowsDisjointInstanceDirectories(t *testing.T) {
	input := inventoryInput()
	for i := range 2 {
		storage := pvcStorage()
		storage.Shared = true
		storage.SubPath = []string{"hermes/user-1/instance-11", "hermes/user-2/instance-12"}[i]
		input.Instances[i].Runtime = Runtime{Type: "hermes", Mode: "lite"}
		input.Instances[i].Mounts = []Mount{{ContainerPath: "/workspace", Storage: storage}}
	}
	if _, err := BuildInventory(input); err != nil {
		t.Fatalf("non-overlapping Lite directories should be allowed: %v", err)
	}
}

func TestSingleNodeSnapshotDoesNotPermitEarlyGateRelease(t *testing.T) {
	input := inventoryInput()
	input.Profile = "single-node"
	storage := &input.Instances[0].Mounts[0].Storage
	storage.SnapshotProbePassed = true
	storage.CSIDriver = "driver.longhorn.io"
	storage.SnapshotClass = "longhorn"
	plan, err := BuildInventory(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Instances[0].Mounts[0].Capture.ReleaseGateAt != "encrypted_staging_sealed" {
		t.Fatal("single-node snapshot bypassed sealing inside the gate")
	}
}

func TestOverlappingMountDetectionKeepsAncestorAcrossSiblingNames(t *testing.T) {
	groups := map[string][]mountClaim{"hostpath:node": {
		{1, "/data"}, {1, "/data/a"}, {2, "/data/b"}, {3, "/data-independent"},
	}}
	if err := validateStorageClaims(groups); !errors.Is(err, ErrStorageUnresolved) {
		t.Fatalf("ancestor overlap was lost while sorting sibling names: %v", err)
	}
}
