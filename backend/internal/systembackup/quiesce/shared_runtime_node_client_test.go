package quiesce

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clawreef/internal/services"
)

func sharedNodeRequestFixture(t *testing.T) SharedRuntimeNodeRequest {
	t.Helper()
	now := time.Now().UTC()
	id := services.RuntimeSharedBackupIdentity{Protocol: services.RuntimeSharedBackupProtocol, Namespace: "ns", PodUID: "pod-1", Deployment: "shared-runtime", AgentEpoch: strings.Repeat("a", 32), OperationID: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64)}
	o := services.RuntimeSharedNativeState{Version: "shared-runtime-native-state.v1", Identity: id, Phase: "reserved", OriginalSHA256: "", JournalSHA256: strings.Repeat("d", 64), JournalPath: "/var/lib/clawmanager-agent/shared-backup/current.json", GuardPath: "/var/lib/clawmanager-agent/shared-backup.guard", AgentPID: 12, AgentStartTicks: "12345", PIDNamespace: "pid:[1]", MountNamespace: "mnt:[2]", BootID: "original-boot", Entries: []services.RuntimeSharedBackupEntry{}, Sequence: 1, PreparedAt: now, UpdatedAt: now}
	o.OriginalSHA256 = services.SharedRuntimeOriginalSHA(o)
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return SharedRuntimeNodeRequest{Version: SharedRuntimeNodeProtocol, Action: "prepare", Nonce: strings.Repeat("e", 64), Binding: ObservationBinding{Kind: SharedRuntimeNodeKind, InstallationID: "installation", OperationID: "actual-public-task-id", ReservationID: id.OperationID, InventorySHA256: id.InventorySHA256, Namespace: "ns", NamespaceUID: "namespace-uid", Node: "node-a", NodeUID: "node-uid", Generation: 7, FenceEpoch: 0, ExpiresAt: now.Add(time.Minute)}, Deadline: now.Add(8 * time.Second), AgentPod: PodIdentity{Name: "shared-runtime-pod", UID: id.PodUID, Node: "node-a", Containers: []string{"containerd://" + strings.Repeat("f", 64)}}, WorkspaceRoot: "/workspaces", AgentDataDir: "/var/lib/clawmanager-agent", Original: o, OriginalRaw: raw, SourcePaths: []string{"/host/original-volume"}}
}

func TestSharedNodeContractSeparatesOriginalTaskAndAgentReservationAndRejectsAliases(t *testing.T) {
	r := sharedNodeRequestFixture(t)
	if ValidateSharedRuntimeNodeRequest(r, time.Now()) != nil {
		t.Fatal("distinct real task/wire identities or legal zero fence rejected")
	}
	raw, _ := json.Marshal(r)
	for _, bad := range []string{strings.Replace(string(raw), `"Action":`, `"action":`, 1), strings.TrimSuffix(string(raw), "}") + `,"Action":"freeze"}`, string(raw) + ` {}`} {
		if _, err := DecodeSharedRuntimeNodeRequest(strings.NewReader(bad)); err == nil {
			t.Fatal("ambiguous Node request accepted")
		}
	}
	r.Binding.ReservationID = strings.Repeat("0", 32)
	if ValidateSharedRuntimeNodeRequest(r, time.Now()) == nil {
		t.Fatal("foreign Agent operation accepted")
	}
}

// Real mutual TLS/URI and one actual HTTP roundtrip. The response fixture is
// transport DATA only, never a native freezer/SQL/source-consistency fixture.
func TestSharedNodeTransportPinsMutualTLSNonceAndNeverRetriesOrFollowsRedirect(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-node-uri", "wrong-nonce", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			roots, serverCert, clientCert := proofCertificates(t)
			calls := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls++
				if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 || request.TLS.PeerCertificates[0].URIs[0].String() != "spiffe://backup.internal/controller" {
					t.Error("actual controller mTLS absent")
					w.WriteHeader(403)
					return
				}
				if scenario == "redirect" {
					http.Redirect(w, request, "https://127.0.0.1:1", http.StatusTemporaryRedirect)
					return
				}
				r, err := DecodeSharedRuntimeNodeRequest(request.Body)
				if err != nil || ValidateSharedRuntimeNodeRequest(r, time.Now()) != nil {
					t.Error("invalid actual Node request")
					w.WriteHeader(400)
					return
				}
				out := SharedRuntimeNodeResponse{Version: r.Version, Action: r.Action, Nonce: r.Nonce, RequestSHA256: SharedRuntimeNodeRequestSHA256(r), Binding: r.Binding, Anchor: "opaque-native-owner-anchor", BootID: "original-boot", OriginalSHA256: r.Original.OriginalSHA256, OriginalRawSHA256: observationRawDigest(r.OriginalRaw), CurrentRawSHA256: observationRawDigest(r.CurrentRaw), CohortSHA256: SharedRuntimeNodeCohortSHA(r), SourcePathsSHA256: SharedRuntimeNodeSourcePathsSHA(r), NativeJournalSHA256: strings.Repeat("1", 64), Phase: "prepared", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), ValidUntil: r.Deadline, TasksChecked: 1, Files: 1, Facts: SharedRuntimeNodeFacts(r.Action)}
				if scenario == "wrong-nonce" {
					out.Nonce = strings.Repeat("0", 64)
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			server.StartTLS()
			defer server.Close()
			uri := "spiffe://backup.internal/node/node-a"
			if scenario == "wrong-node-uri" {
				uri = "spiffe://backup.internal/node/foreign"
			}
			client := &SharedRuntimeNodeClient{proof: &ProofClient{Endpoints: map[string]ProofEndpoint{"node-a": {URL: server.URL + SharedRuntimeNodeRoute, ServerURI: uri}}, Roots: roots, Certificate: clientCert}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r := sharedNodeRequestFixture(t)
			proof, raw, err := client.Transition(ctx, r)
			if scenario == "valid" {
				if err != nil || proof == nil || len(raw) == 0 || calls != 1 {
					t.Fatal("actual mutual TLS exchange failed", err)
				}
			} else if err == nil || proof != nil || calls > 1 {
				t.Fatal("foreign/unknown response accepted or retried")
			}
		})
	}
}
