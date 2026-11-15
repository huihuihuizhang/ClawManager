package quiesce

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func sharedLonghornRequestFixture(t *testing.T) SharedRuntimeNodeRequest {
	r := sharedNodeRequestFixture(t)
	b := r.Binding
	b.Kind, b.OperationID, b.ReservationID, b.InventorySHA256 = LonghornExt4Protocol, "", "", ""
	b.Generation, b.FenceEpoch, b.ExpiresAt = 0, 0, time.Time{}
	c := LonghornRWXClientCoordinates{Binding: b, OriginalSourceSHA256: strings.Repeat("1", 64), ProviderNamespaceUID: "provider-ns", PVCName: "workspaces", PVCUID: "workspace-pvc", PVUID: "workspace-pv", VolumeHandle: "pvc-workspace", PodNamespace: b.Namespace, PodName: r.AgentPod.Name, PodUID: r.AgentPod.UID, ContainerID: r.AgentPod.Containers[0], MountPoint: r.WorkspaceRoot, NFSSource: "10.0.0.1:/workspace", Endpoint: "10.0.0.1"}
	c.Identity, _ = LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, b.NodeUID)
	r.SourcePaths, r.LonghornClient = nil, &c
	return r
}

func TestSharedRuntimeLonghornRequiresExplicitPinnedClientInsteadOfEmptyHostPaths(t *testing.T) {
	r := sharedLonghornRequestFixture(t)
	if ValidateSharedRuntimeNodeRequest(r, time.Now()) != nil {
		t.Fatal("explicit original client shape rejected")
	}
	for name, mutate := range map[string]func(*SharedRuntimeNodeRequest){
		"missing-reference": func(r *SharedRuntimeNodeRequest) { r.LonghornClient = nil },
		"mixed-host-roots":  func(r *SharedRuntimeNodeRequest) { r.SourcePaths = []string{"/host/path"} },
		"pod-replacement":   func(r *SharedRuntimeNodeRequest) { r.LonghornClient.PodUID = "replacement" },
		"container-replacement": func(r *SharedRuntimeNodeRequest) {
			r.LonghornClient.ContainerID = "containerd://" + strings.Repeat("a", 64)
		},
		"namespace":   func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Binding.NamespaceUID = "replacement" },
		"node":        func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Binding.NodeUID = "replacement" },
		"mount":       func(r *SharedRuntimeNodeRequest) { r.LonghornClient.MountPoint = "/another" },
		"source":      func(r *SharedRuntimeNodeRequest) { r.LonghornClient.OriginalSourceSHA256 = strings.Repeat("2", 64) },
		"claim":       func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Claim.OriginalOperationID = "caller-claim" },
		"attempt":     func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Attempt = 1 },
		"operation":   func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Binding.OperationID = "another-operation" },
		"reservation": func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Binding.ReservationID = "another-reservation" },
		"generation":  func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Binding.Generation = 1 },
		"endpoint":    func(r *SharedRuntimeNodeRequest) { r.LonghornClient.Endpoint = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := sharedLonghornRequestFixture(t)
			mutate(&bad)
			if ValidateSharedRuntimeNodeRequest(bad, time.Now()) == nil {
				t.Fatal("ambiguous or claimed client accepted")
			}
		})
	}
}

func TestSharedRuntimeLonghornScopeHashAndFactsCannotClaimFilesystemHold(t *testing.T) {
	r := sharedLonghornRequestFixture(t)
	hash := SharedRuntimeNodeSourcePathsSHA(r)
	r.LonghornClient.PVUID = "replacement-pv"
	if SharedRuntimeNodeSourcePathsSHA(r) == hash {
		t.Fatal("replacement volume retained original source digest")
	}
	facts := sharedRuntimeNodeRequestFacts(r, "check-frozen")
	if reflect.DeepEqual(facts, SharedRuntimeNodeFacts("check-frozen")) {
		t.Fatal("CSI component inherited host flush/writer claims")
	}
	for _, fact := range facts {
		if fact == "no_observed_unfrozen_external_source_writer" || fact == "native_source_flush_boundary_current" {
			t.Fatal("component advertised independent physical source work")
		}
	}
	other := sharedLonghornRequestFixture(t)
	if sameSharedRuntimeSourceScope(r, other) {
		t.Fatal("different physical source admitted to cohort")
	}
	r = sharedLonghornRequestFixture(t)
	other.AgentPod.UID, other.LonghornClient.PodUID = "another-original", "another-original"
	if !sameSharedRuntimeSourceScope(r, other) {
		t.Fatal("same installed source with another original client rejected")
	}
}
