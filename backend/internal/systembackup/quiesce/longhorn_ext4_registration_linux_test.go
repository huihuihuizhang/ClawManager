//go:build linux

package quiesce

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLonghornExt4TasklessGrantDerivesSeparateClaimTargets(t *testing.T) {
	template := LonghornExt4Source{Identity: strings.Repeat("a", 64),
		Binding: ObservationBinding{Kind: "shared", InstallationID: "installation", Namespace: "source", NamespaceUID: "namespace-uid", Node: "node", NodeUID: "node-uid"}}
	templateKey := longhornExt4SourceKey(template)
	a := &longhornExt4Actions{templates: map[string]LonghornExt4Source{template.Identity: template},
		sources: map[string]LonghornExt4Source{}, volumes: map[string]longhornExt4Volume{templateKey: {}}}
	request := LonghornExt4Request{Action: "state", Binding: template.Binding, Attempt: 1, SourceIdentity: template.Identity,
		Claim: LonghornExt4Claim{TaskPublicID: "task", Owner: "controller", MaintenanceOwner: "task", EntryRowVersion: 3,
			LeaseObservedAt: time.Unix(100, 0), LeaseExpiresAt: time.Unix(160, 0)}}
	request.Binding.OperationID, request.Binding.Generation = "operation", 2
	request.Binding.InventorySHA256, request.Binding.ExpiresAt = strings.Repeat("b", 64), time.Unix(150, 0)
	oldKey, err := a.sourceForRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Claim.EntryRowVersion++
	newKey, err := a.sourceForRequest(context.Background(), request)
	if err != nil || oldKey == newKey {
		t.Fatal("claim reacquisition reused original target", err)
	}
	if template.Binding.OperationID != "" || template.Claim != (LonghornExt4Claim{}) || len(a.templates) != 1 {
		t.Fatal("runtime registration modified installed grant")
	}
	for _, mutate := range []func(*LonghornExt4Request){
		func(r *LonghornExt4Request) { r.Binding.NodeUID = "replacement-node" },
		func(r *LonghornExt4Request) { r.Binding.NamespaceUID = "replacement-namespace" },
		func(r *LonghornExt4Request) { r.SourceIdentity = strings.Repeat("c", 64) },
		func(r *LonghornExt4Request) { r.ClientContainerID = "unexpected-client" },
	} {
		changed := request
		mutate(&changed)
		if _, err := a.sourceForRequest(context.Background(), changed); err == nil {
			t.Fatal("changed installation binding admitted")
		}
	}
}

func TestLonghornKeeperRegistrationCannotReplaceOrSkipKeeper(t *testing.T) {
	template := LonghornExt4Source{Identity: strings.Repeat("a", 64), Binding: ObservationBinding{
		Kind: LonghornExt4Protocol, InstallationID: "installation", Namespace: "tenant", NamespaceUID: "tenant-uid", Node: "node", NodeUID: "node-uid",
	}}
	request := LonghornExt4Request{Action: "state", Binding: template.Binding, Attempt: 2, SourceIdentity: template.Identity,
		Claim: LonghornExt4Claim{TaskPublicID: "task", Owner: "controller", MaintenanceOwner: "task", EntryRowVersion: 4,
			LeaseObservedAt: time.Unix(100, 0), LeaseExpiresAt: time.Unix(160, 0)},
		Keeper: &LonghornExt4Keeper{OriginalPodUID: "writer-uid", PodName: "keeper", PodUID: "keeper-uid", ContainerID: "containerd://keeper"}}
	request.Binding.OperationID, request.Binding.Generation = "task", 7
	request.Binding.InventorySHA256, request.Binding.ExpiresAt = strings.Repeat("b", 64), time.Unix(150, 0)
	source := template
	source.Binding, source.Attempt, source.Claim, source.Keeper = request.Binding, request.Attempt, request.Claim, request.Keeper
	key := longhornExt4SourceKey(source)
	a := &longhornExt4Actions{templates: map[string]LonghornExt4Source{template.Identity: template},
		sources: map[string]LonghornExt4Source{key: source}, volumes: map[string]longhornExt4Volume{longhornExt4SourceKey(template): {}}}
	if got, err := a.sourceForRequest(context.Background(), request); err != nil || got != key {
		t.Fatalf("original handover not found: %s, %v", got, err)
	}
	wrong := *request.Keeper
	wrong.ContainerID = "containerd://replacement"
	for _, keeper := range []*LonghornExt4Keeper{nil, &wrong} {
		changed := request
		changed.Keeper = keeper
		if _, err := a.sourceForRequest(context.Background(), changed); err == nil {
			t.Fatal("replaced or missing keeper accepted")
		}
	}
	request.Attempt++
	if _, err := a.sourceForRequest(context.Background(), request); err == nil {
		t.Fatal("later attempt inherited the handover")
	}
}

func TestLonghornKeeperDeviceRequiresSameIncarnationAndDistinctMount(t *testing.T) {
	original := longhornExt4Pin{BootID: "boot", Device: 42, DiskSequence: 3, RootInode: 2, UniqueMountID: 7}
	keeper := original
	keeper.UniqueMountID++
	if !sameLonghornKeeperDevice(original, keeper) {
		t.Fatal("separate mount of the original device rejected")
	}
	for _, changed := range []func(*longhornExt4Pin){
		func(p *longhornExt4Pin) { p.BootID = "reboot" },
		func(p *longhornExt4Pin) { p.Device++ },
		func(p *longhornExt4Pin) { p.DiskSequence++ },
		func(p *longhornExt4Pin) { p.RootInode++ },
		func(p *longhornExt4Pin) { p.ErrorCount++ },
		func(p *longhornExt4Pin) { p.UniqueMountID = original.UniqueMountID },
	} {
		candidate := keeper
		changed(&candidate)
		if sameLonghornKeeperDevice(original, candidate) {
			t.Fatalf("replaced device or reused mount accepted: %+v", candidate)
		}
	}
}

func TestLonghornRWXClientKeySeparatesContainersAndMounts(t *testing.T) {
	original := longhornRWXClient{source: LonghornExt4Source{Identity: strings.Repeat("a", 64),
		ProviderPodUID: "pod", ProviderContainerID: "containerd://one"},
		pin: longhornRWXClientMountPin{mountID: "17", device: "0:23", root: "/", point: "/work", source: "10.0.0.1:/volume", endpoint: netip.MustParseAddr("10.0.0.1")}}
	key := longhornRWXClientKey(original)
	for _, mutate := range []func(*longhornRWXClient){
		func(c *longhornRWXClient) { c.source.ProviderContainerID = "containerd://two" },
		func(c *longhornRWXClient) { c.pin.mountID = "18" },
		func(c *longhornRWXClient) { c.pin.point = "/other" },
	} {
		other := original
		mutate(&other)
		if longhornRWXClientKey(other) == key {
			t.Fatal("different client mount reused same entry")
		}
	}
}
