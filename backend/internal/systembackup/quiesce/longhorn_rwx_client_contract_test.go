package quiesce

import (
	"strings"
	"testing"
)

func TestLonghornColdClientExitRequirementIsOriginalOnly(t *testing.T) {
	r := LonghornExt4Request{Action: "register-client", ClientPodName: "app", ClientPodUID: "pod", ClientContainerID: "containerd://original", RegistrationBoundarySHA256: strings.Repeat("a", 64), ClientMustExit: true}
	if validLonghornRWXClientTransition(r) {
		t.Fatal("unbound exit mode accepted")
	}
	r.Claim.OriginalOperationID = strings.Repeat("1", 32)
	if !validLonghornRWXClientTransition(r) {
		t.Fatal("original cold mode refused")
	}
	r.Claim.TaskPublicID = "task"
	if validLonghornRWXClientTransition(r) {
		t.Fatal("original cold mode borrowed task scope")
	}
}

func TestLonghornRWXClientSyncRequiresBothOriginalAndDrainBoundaries(t *testing.T) {
	r := LonghornExt4Request{Action: "register-client", ClientPodName: "original-app", ClientPodUID: "original-pod", ClientContainerID: "containerd://original", RegistrationBoundarySHA256: strings.Repeat("a", 64)}
	if !validLonghornRWXClientTransition(r) {
		t.Fatal("original mount registration rejected")
	}
	r.Action = "sync-client"
	if validLonghornRWXClientTransition(r) {
		t.Fatal("the previous empty-drain sync call was accepted")
	}
	r.DrainBoundarySHA256 = strings.Repeat("b", 64)
	if !validLonghornRWXClientTransition(r) {
		t.Fatal("post-drain sync rejected")
	}
	for _, mutate := range []func(*LonghornExt4Request){
		func(r *LonghornExt4Request) { r.RegistrationBoundarySHA256 = "" },
		func(r *LonghornExt4Request) { r.ClientPodUID = "" },
		func(r *LonghornExt4Request) { r.ClientPodName = "" },
		func(r *LonghornExt4Request) { r.ClientContainerID = "" },
		func(r *LonghornExt4Request) { r.RecoveryBoundarySHA256 = strings.Repeat("c", 64) },
		func(r *LonghornExt4Request) { r.Keeper = &LonghornExt4Keeper{} },
	} {
		changed := r
		mutate(&changed)
		if validLonghornRWXClientTransition(changed) {
			t.Fatal("incomplete or foreign-phase client sync accepted")
		}
	}
	r.Action = "register-client"
	if validLonghornRWXClientTransition(r) {
		t.Fatal("registration was silently treated as a completed drain")
	}
}
