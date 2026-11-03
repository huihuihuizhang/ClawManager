package quiesce

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/services"
)

func gatewayStoppedDataFixture(t *testing.T) (GatewayNodeObservationRequest, services.RuntimeStoppedBackupReceipt) {
	t.Helper()
	hold := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	q := services.RuntimeStoppedBackupRequest{RuntimeStoppedBackupIdentity: services.RuntimeStoppedBackupIdentity{Protocol: services.RuntimeStoppedBackupProtocol, Namespace: "ns", PodUID: "pod", AgentEpoch: strings.Repeat("a", 32), RuntimeType: "opencode", InstanceID: 1, UserID: 3, Generation: 2, GatewayID: "gw-1-2", GatewayPort: 18790}, OperationID: strings.Repeat("b", 32), CheckpointSHA256: strings.Repeat("c", 64), HoldUntil: hold}
	i := services.RuntimeStoppedBackupInspection{Identity: q.RuntimeStoppedBackupIdentity, Slot: "slot-0", Scope: services.RuntimeStoppedBackupScope, CheckpointSHA256: q.CheckpointSHA256, State: "stopped_unreserved"}
	raw, e := json.Marshal(i)
	if e != nil {
		t.Fatal(e)
	}
	r := GatewayNodeObservationRequest{Action: "prepare", Binding: ObservationBinding{Kind: GatewayNodeOriginallyStopped}, Stopped: &q, Slot: "slot-0", RawAction: "inspect", Raw: append(raw, '\n')}
	receipt := services.RuntimeStoppedBackupReceipt{Request: q, Slot: r.Slot, Scope: services.RuntimeStoppedBackupScope, State: "reserved_stopped", CheckpointSHA256: q.CheckpointSHA256, ConfirmedAt: time.Now().UTC()}
	return r, receipt
}

func TestGatewayNodeStoppedWireRetainsExactRawAndNoPID(t *testing.T) {
	r, reserved := gatewayStoppedDataFixture(t)
	if gatewayDataReceipt(r) != nil {
		t.Fatal("valid DATA inspection refused")
	}
	original := append([]byte(nil), r.Raw...)
	withWhitespace := append(append([]byte(nil), r.Raw...), '\n')
	r.Raw = withWhitespace
	if gatewayDataReceipt(r) != nil || observationRawDigest(original) == observationRawDigest(r.Raw) {
		t.Fatal("exact received whitespace was canonicalized for raw hash")
	}
	r.Action = "stopped"
	r.RawAction = "observe"
	r.Raw, _ = json.Marshal(reserved)
	if gatewayDataReceipt(r) != nil {
		t.Fatal("valid reserved DATA refused")
	}
	r.Raw = bytes.Replace(r.Raw, []byte("\"checkpoint_sha256\""), []byte("\"checkpoint_SHA256\""), 1)
	if gatewayDataReceipt(r) == nil {
		t.Fatal("case-aliased raw object accepted")
	}
	r.Raw, _ = json.Marshal(reserved)
	r.Raw = bytes.Replace(r.Raw, []byte("\"state\":\"reserved_stopped\""), []byte("\"state\":\"reserved_stopped\",\"state\":\"reserved_stopped\""), 1)
	if gatewayDataReceipt(r) == nil {
		t.Fatal("duplicate raw field accepted")
	}
	r, _ = gatewayStoppedDataFixture(t)
	r.Binding.Kind = GatewayNodeRunning
	r.Stopped = nil
	r.Running = &services.RuntimeBackupRequest{}
	if gatewayDataReceipt(r) == nil {
		t.Fatal("originally stopped relabeled as v1 PID0 source")
	}
}

func TestGatewayNodeStoppedCompletionNeedsBothActualRawBodies(t *testing.T) {
	r, _ := gatewayStoppedDataFixture(t)
	r.Action = "recovered-stopped"
	if gatewayDataReceipt(r) == nil {
		t.Fatal("final inspect alone became completion")
	}
	completed := services.RuntimeStoppedBackupReceipt{Request: *r.Stopped, Slot: r.Slot, Scope: services.RuntimeStoppedBackupScope, State: "completed_stopped", CheckpointSHA256: r.Stopped.CheckpointSHA256, ConfirmedAt: time.Now().UTC()}
	r.CompletionRaw, _ = json.Marshal(completed)
	if gatewayDataReceipt(r) != nil {
		t.Fatal("actual completed DATA plus final inspection refused")
	}
	completed.Request.OperationID = strings.Repeat("d", 32)
	r.CompletionRaw, _ = json.Marshal(completed)
	if gatewayDataReceipt(r) == nil {
		t.Fatal("foreign completion operation accepted")
	}
}

func TestGatewayNodeExpiredStoppedCannotBecomeFreshObservation(t *testing.T) {
	r, reserved := gatewayStoppedDataFixture(t)
	r.Stopped.HoldUntil = time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	reserved.Request = *r.Stopped
	r.Raw, _ = json.Marshal(reserved)
	r.RawAction = "observe"
	r.Action = "stopped"
	r.Version = GatewayNodeObservationProtocol
	r.Nonce = strings.Repeat("e", 64)
	r.OriginalStateSHA256 = strings.Repeat("9", 64)
	r.Binding = ObservationBinding{Kind: GatewayNodeOriginallyStopped, InstallationID: "install", OperationID: "actual-original-controller-operation", ReservationID: r.Stopped.OperationID, InventorySHA256: strings.Repeat("f", 64), Namespace: "ns", NamespaceUID: "ns-uid", Node: "node", NodeUID: "node-uid", Generation: 2, FenceEpoch: 1, ExpiresAt: r.Stopped.HoldUntil}
	r.AgentPod = PodIdentity{Name: "agent", UID: "pod", Node: "node", Containers: []string{"containerd://" + strings.Repeat("1", 64)}}
	r.WorkspaceRoot = "/workspaces"
	r.AgentDataDir = "/state"
	r.Deadline = time.Now().UTC().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
	defer cancel()
	o := &NodeObserver{Node: "node", NodeUID: "node-uid", HostProc: "/must-not-be-opened", key: make([]byte, 32)}
	if _, e := o.ObserveGateway(ctx, r); e != ErrNodeObservation {
		t.Fatal("expired original stop did not refuse before native access", e)
	}
}

func TestGatewayNodeAnchorDomainAndSharedAgentScope(t *testing.T) {
	o := &NodeObserver{key: make([]byte, 32)}
	a := gatewayObservationAnchor{Version: GatewayNodeObservationProtocol, Binding: ObservationBinding{Kind: GatewayNodeRunning, OperationID: "original"}}
	token, e := o.sealGateway(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.openGateway(token + "0"); e == nil {
		t.Fatal("tampered anchor accepted")
	}
	if _, e = o.open(token); e == nil {
		t.Fatal("gateway anchor accepted by whole-Pod protocol")
	}
	agent := observedProcess{PID: 100, Start: "1", PIDNamespace: "pid:[1]", MountNamespace: "mnt:[1]", Cgroup: "/pod/container"}
	scope := gatewayNativeScope{Monitor: observedProcess{PID: 101, Start: "2", PIDNamespace: agent.PIDNamespace, Cgroup: agent.Cgroup}, Init: observedProcess{PID: 102, Start: "3", PIDNamespace: "pid:[2]", MountNamespace: "mnt:[2]", Cgroup: agent.Cgroup}}
	if gatewayScopeContains(agent, scope) {
		t.Fatal("shared Agent namespace/cgroup was classified as stopped gateway")
	}
	if !gatewayScopeContains(observedProcess{PID: 103, Start: "4", PIDNamespace: "pid:[2]", MountNamespace: "mnt:[2]", Cgroup: agent.Cgroup}, scope) {
		t.Fatal("actual private namespace descendant escaped scope")
	}
}
