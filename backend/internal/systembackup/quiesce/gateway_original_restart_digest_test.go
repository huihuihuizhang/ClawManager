package quiesce

import (
	"strings"
	"testing"

	"clawreef/internal/services"
)

// This test exercises anchor correlation DATA and the existing wire-digest
// function only. It never creates a VerifiedGatewayNodeObservation or a
// positive HTTP/native response, and cannot act as an Installer/held-gate proof.
func gatewayOriginalRestartDataFixture(t *testing.T) (GatewayNodeObservationRequest, GatewayNodeObservationResponse, string, string) {
	t.Helper()
	in, _ := nodeGatewayZeroRunningRequest()
	original := services.RuntimeAgentCreateGatewayRequest{PodUID: "pod", SecurityProfile: "isolated", InstanceID: 1, UserID: 3, AgentType: "opencode", WorkspacePath: "/workspaces/3/1", GatewayPort: 18790, UID: 10000, GID: 10000, CPUCores: 1, MemoryMB: 1024, DiskQuotaMB: 2048, Generation: 2}
	originalSHA, e := services.RuntimeBackupRestartDigest(original)
	if e != nil {
		t.Fatal(e)
	}
	next := original
	next.Generation = 3
	successorSHA, e := services.RuntimeBackupRestartDigest(next)
	if e != nil {
		t.Fatal(e)
	}
	if originalSHA == successorSHA {
		t.Fatal("generation missing from original wire digest")
	}
	in.Running.RestartSHA256 = successorSHA
	a := gatewayObservationAnchor{Version: GatewayNodeObservationProtocol, Binding: in.Binding, AgentPod: in.AgentPod, Slot: in.Slot, WorkspaceRoot: in.WorkspaceRoot, AgentDataDir: in.AgentDataDir, OriginalDigest: originalSHA, RequestSHA256: gatewayRequestSHA(in), OriginalStateSHA256: in.OriginalStateSHA256, BootID: "original-node-boot"}
	o := &NodeObserver{key: make([]byte, 32)}
	token, e := o.sealGateway(a)
	if e != nil {
		t.Fatal(e)
	}
	out := GatewayNodeObservationResponse{Binding: in.Binding, OriginalStateSHA256: in.OriginalStateSHA256, Anchor: token, BootID: a.BootID}
	return in, out, originalSHA, successorSHA
}

func TestGatewayOriginalRestartAnchorDataKeepsOriginalWireDigest(t *testing.T) {
	in, out, originalSHA, successorSHA := gatewayOriginalRestartDataFixture(t)
	actual, e := gatewayOriginalRestartFromAnchor(in, out)
	if e != nil || actual != originalSHA || actual == successorSHA {
		t.Fatal("original assignment was replaced with successor digest", e)
	}
	var absent *VerifiedGatewayNodeObservation
	if absent.OriginalRestartSHA256() != "" {
		t.Fatal("nil opaque invented an assignment")
	}
	var zero VerifiedGatewayNodeObservation
	if zero.OriginalRestartSHA256() != "" {
		t.Fatal("empty opaque invented an assignment")
	}
	// This is the exact D interface, without importing D or constructing proof.
	var _ interface{ OriginalRestartSHA256() string } = absent
}

func TestGatewayOriginalRestartAnchorDataRefusesForeignContext(t *testing.T) {
	cases := []struct {
		name   string
		change func(*GatewayNodeObservationRequest, *GatewayNodeObservationResponse)
	}{
		{"epoch-zero-is-not-one", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.Binding.FenceEpoch = 1
		}},
		{"foreign-operation", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.Binding.OperationID = "other-original-operation"
		}},
		{"foreign-reservation", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.Binding.ReservationID = strings.Repeat("f", 32)
		}},
		{"foreign-agent-pod", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.AgentPod.UID = "other-pod"
		}},
		{"foreign-original-state", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.OriginalStateSHA256 = strings.Repeat("f", 64)
		}},
		{"foreign-original-request", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			copy := *in.Running
			copy.AgentEpoch = strings.Repeat("f", 32)
			in.Running = &copy
		}},
		{"foreign-slot", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) { in.Slot = "slot-1" }},
		{"foreign-workspace-config", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.WorkspaceRoot = "/other-source"
		}},
		{"foreign-book-config", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			in.AgentDataDir = "/other-book"
		}},
		{"foreign-response-binding", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			out.Binding.NodeUID = "other-node"
		}},
		{"foreign-boot", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			out.BootID = "other-boot"
		}},
		{"malformed-anchor", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) {
			out.Anchor = "not-an-anchor"
		}},
		{"malformed-signature-shape", func(in *GatewayNodeObservationRequest, out *GatewayNodeObservationResponse) { out.Anchor += "0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, out, _, _ := gatewayOriginalRestartDataFixture(t)
			tc.change(&in, &out)
			if digest, e := gatewayOriginalRestartFromAnchor(in, out); e == nil || digest != "" {
				t.Fatal("foreign anchor context returned original assignment DATA", e)
			}
		})
	}
	in, out, _, _ := gatewayOriginalRestartDataFixture(t)
	in.Binding.Kind = GatewayNodeOriginallyStopped
	if digest, e := gatewayOriginalRestartFromAnchor(in, out); e != nil || digest != "" {
		t.Fatal("originally stopped source borrowed running assignment API", e)
	}
}
