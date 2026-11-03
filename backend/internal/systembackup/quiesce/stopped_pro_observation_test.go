package quiesce

import (
	"context"
	"strings"
	"testing"
	"time"
)

// DATA fixtures below never produce a native verified observation.
func stoppedProDataFixture() StoppedProNodeObservationRequest {
	h := strings.Repeat("a", 64)
	r := StoppedProNodeObservationRequest{Version: StoppedProObservationProtocol, Action: "prepare", Nonce: h, OriginalReservationIdentitySHA256: h, OriginalStateSHA256: h, Binding: ObservationBinding{Kind: StoppedProObservationProtocol, InstallationID: "install", OperationID: "original", ReservationID: "source-reservation", InventorySHA256: h, Namespace: "ns", NamespaceUID: "ns-uid", Node: "node", NodeUID: "node-uid", Generation: 5, FenceEpoch: 3, ExpiresAt: time.Now().UTC().Add(time.Hour)}, Baseline: StoppedProBaseline{SourceKey: "stopped/1", RuntimeType: "opencode-pro", InstanceID: 1, UserID: 2, InstanceGeneration: 5, NamespaceUID: "ns-uid", CurrentConfigSHA256: h, Volumes: []StoppedProVolume{{NamespaceUID: "ns-uid", ClaimName: "source", ClaimUID: "pvc-uid", PVName: "pv", PVUID: "pv-uid", PVSpecSHA256: h, DataNodeUID: "node-uid", UniqueNodeEvidenceSHA256: h, HostPath: "/data/source"}}}}
	r.NativeScopeSHA256 = StoppedProNativeScopeSHA256(r)
	return r
}
func TestStoppedProCurrentBaselineNoHistoricalPodRequired(t *testing.T) {
	r := stoppedProDataFixture()
	if _, e := stoppedProBaselinePaths(r); e != nil {
		t.Fatal("controller-absent DATA refused", e)
	}
	r.Baseline.ControllerUID = "actual-deployment"
	r.Baseline.ControllerGeneration = 73
	r.Baseline.ControllerSpecSHA256 = strings.Repeat("b", 64)
	if _, e := stoppedProBaselinePaths(r); e != nil {
		t.Fatal("independent controller/instance generations conflated", e)
	}
	r.Baseline.ControllerReplicas = 1
	if _, e := stoppedProBaselinePaths(r); e == nil {
		t.Fatal("desired running controller accepted as stopped")
	}
}
func TestStoppedProUniqueVolumeBindingRefusesAmbiguity(t *testing.T) {
	for _, change := range []func(*StoppedProNodeObservationRequest){func(r *StoppedProNodeObservationRequest) { r.Baseline.Volumes[0].UniqueNodeEvidenceSHA256 = "" }, func(r *StoppedProNodeObservationRequest) { r.Baseline.Volumes[0].DataNodeUID = "other-node" }, func(r *StoppedProNodeObservationRequest) {
		r.Baseline.Volumes = append(r.Baseline.Volumes, r.Baseline.Volumes[0])
	}, func(r *StoppedProNodeObservationRequest) { r.Baseline.ControllerGeneration = 10 }} {
		r := stoppedProDataFixture()
		change(&r)
		if _, e := stoppedProBaselinePaths(r); e == nil {
			t.Fatal("ambiguous/invented source DATA accepted")
		}
	}
}
func TestStoppedProNativeScopeHasNoReservationHashCycle(t *testing.T) {
	r := stoppedProDataFixture()
	before := StoppedProNativeScopeSHA256(r)
	r.OriginalReservationIdentitySHA256 = strings.Repeat("f", 64)
	r.Nonce = strings.Repeat("e", 64)
	r.Deadline = time.Now().Add(time.Second)
	r.Anchor = "opaque-response"
	r.NativeScopeSHA256 = "not-an-input-to-itself"
	if StoppedProNativeScopeSHA256(r) != before {
		t.Fatal("transport/reservation hash entered stable source-scope hash")
	}
	r.Baseline.Volumes[0].PVUID = "changed-pv"
	if StoppedProNativeScopeSHA256(r) == before {
		t.Fatal("source PV change escaped stable scope")
	}
}
func TestStoppedProAnchorCannotBecomeWholePodOrGateway(t *testing.T) {
	o := &NodeObserver{key: make([]byte, 32)}
	a := stoppedProAnchor{Version: StoppedProObservationProtocol, BootID: "boot"}
	token, e := o.sealStoppedPro(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.openStoppedPro(token + "0"); e == nil {
		t.Fatal("tampered source anchor accepted")
	}
	if _, e = o.open(token); e == nil {
		t.Fatal("stopped Pro token became whole-Pod token")
	}
	if _, e = o.openGateway(token); e == nil {
		t.Fatal("stopped Pro token became Agent token")
	}
}
func TestStoppedProExpiredFreshRequestRefusesBeforeNativeIO(t *testing.T) {
	r := stoppedProDataFixture()
	r.Binding.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	r.Deadline = time.Now().UTC().Add(3 * time.Second)
	r.NativeScopeSHA256 = StoppedProNativeScopeSHA256(r)
	ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
	defer cancel()
	o := &NodeObserver{Node: "node", NodeUID: "node-uid", HostProc: "/must-not-read", key: make([]byte, 32)}
	if _, e := o.ObserveStoppedPro(ctx, r); e != ErrNodeObservation {
		t.Fatal("expired source attempted native I/O or became fresh", e)
	}
}
