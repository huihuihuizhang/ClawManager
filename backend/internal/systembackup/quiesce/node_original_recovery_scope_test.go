package quiesce

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Synthetic HMAC/context DATA only. No native success or opaque proof is made.
func scopedRecoveryData(t *testing.T, action string) (*NodeObserver, NodeObservationRequest, nodeObservationAnchor) {
	t.Helper()
	binding := nodeGatewayZeroBinding(NodeObservationWholePodColdCut)
	binding.Generation = 41
	binding.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	aPod := PodIdentity{Name: "a", UID: "old-a", Node: "node", Containers: []string{"containerd://" + strings.Repeat("1", 64)}}
	bPod := PodIdentity{Name: "b", UID: "old-b", Node: "node", Containers: []string{"containerd://" + strings.Repeat("2", 64)}}
	aRoot := observedProcess{PID: 101, Start: "11", PIDNamespace: "pid:[101]", MountNamespace: "mnt:[101]", Cgroup: "/kubepods/podold-a"}
	bRoot := observedProcess{PID: 201, Start: "21", PIDNamespace: "pid:[201]", MountNamespace: "mnt:[201]", Cgroup: "/kubepods/podold-b"}
	child := observedProcess{PID: 102, Start: "12", PIDNamespace: aRoot.PIDNamespace, MountNamespace: aRoot.MountNamespace, Cgroup: aRoot.Cgroup + "/container"}
	anchor := nodeObservationAnchor{Binding: binding, Pods: []PodIdentity{aPod, bPod}, Processes: []observedProcess{aRoot, bRoot, child}, BootID: "boot", PreparedAt: time.Now().UTC().Add(-2 * time.Minute), Paths: []observedPath{{Path: "/source", Device: 1, Inode: 2, Mount: "DATA only"}}}
	o := nodeGatewayUnavailableObserver(t)
	o.BootID = anchor.BootID
	token, e := o.seal(anchor)
	if e != nil {
		t.Fatal(e)
	}
	r := NodeObservationRequest{Version: "node-observation.v1", Action: action, Nonce: strings.Repeat("e", 64), Binding: binding, Deadline: time.Now().UTC().Add(4 * time.Second), Pods: copyRecoveryPods(anchor.Pods), Anchor: token, RecoveredGeneration: binding.Generation, RecoveredPods: []PodIdentity{bPod}, RecoverySnapshotSHA256: strings.Repeat("f", 64)}
	if action == "recovery-source-stopped" {
		r.RecoveryAffectedPods = []PodIdentity{aPod}
	} else {
		r.RecoveredPods = append(r.RecoveredPods, PodIdentity{Name: "replacement", UID: "new-a", Node: "node", Containers: []string{"containerd://" + strings.Repeat("3", 64)}})
	}
	return o, r, anchor
}
func TestOriginalRecoverySealedActorPartitionData(t *testing.T) {
	_, _, a := scopedRecoveryData(t, "recovery-reconciled")
	actors, e := originalRecoveryActors(a)
	if e != nil || len(actors) != 2 || len(actors[0].Processes) != 2 || len(actors[1].Processes) != 1 {
		t.Fatal("sealed root-prefix ownership lost", e)
	}
	cases := []struct {
		name   string
		mutate func(*nodeObservationAnchor)
	}{
		{"missing-root-prefix", func(a *nodeObservationAnchor) { a.Processes = a.Processes[:1] }},
		{"wrong-pod-cgroup", func(a *nodeObservationAnchor) { a.Processes[0].Cgroup = "/kubepods/podforeign" }},
		{"overlapping-root-namespace", func(a *nodeObservationAnchor) { a.Processes[1].PIDNamespace = a.Processes[0].PIDNamespace }},
		{"unassigned-stored-process", func(a *nodeObservationAnchor) {
			a.Processes = append(a.Processes, observedProcess{PID: 999, Start: "9", PIDNamespace: "pid:[999]", MountNamespace: "mnt:[999]", Cgroup: "/unrelated"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, a := scopedRecoveryData(t, "recovery-reconciled")
			tc.mutate(&a)
			if _, e := originalRecoveryActors(a); e == nil {
				t.Fatal("unknown or ambiguous original actor anchor accepted")
			}
		})
	}
}
func TestOriginalRecoveryLiveScopeDoesNotWidenHostDomainData(t *testing.T) {
	root := observedProcess{PID: 101, Start: "11", PIDNamespace: "pid:[101]", MountNamespace: "mnt:[101]", Cgroup: "/kubepods/podold-a"}
	escaped := observedProcess{PID: 555, Start: "55", PIDNamespace: "pid:[host]", MountNamespace: "mnt:[host]", Cgroup: "/"}
	unknown := escaped
	unknown.PID = 999
	unknown.Start = "99"
	if originalRecoveryLiveContains(unknown, []observedProcess{root}, []observedProcess{escaped}) {
		t.Fatal("one observed descendant whitelisted a host domain")
	}
	if !originalRecoveryLiveContains(escaped, []observedProcess{root}, []observedProcess{escaped}) {
		t.Fatal("exact observed tuple refused")
	}
	mountOnly := unknown
	mountOnly.MountNamespace = root.MountNamespace
	if originalRecoveryLiveContains(mountOnly, []observedProcess{root}, nil) {
		t.Fatal("mount namespace alone whitelisted an unknown actor")
	}
}
func TestOriginalRecoveryScopeHashAndExplicitEmptyWire(t *testing.T) {
	for _, action := range []string{"recovery-source-stopped", "recovery-reconciled"} {
		t.Run(action, func(t *testing.T) {
			_, r, _ := scopedRecoveryData(t, action)
			r.RecoveredPods = []PodIdentity{}
			raw, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || string(fields["RecoveredPods"]) != "[]" {
				t.Fatal("explicit actual-empty membership lost on wire", string(raw))
			}
			var decoded NodeObservationRequest
			if observationJSON(bytes.NewReader(raw), &decoded) != nil || decoded.RecoveredPods == nil || !nodeObservationPhaseDataValid(decoded, "node") {
				t.Fatal("actual-empty wire roundtrip refused")
			}
			digest, e := OriginalRecoveryScopeSHA256(r, r.RecoveryAffectedPods)
			if e != nil {
				t.Fatal(e)
			}
			again, e := OriginalRecoveryScopeSHA256(decoded, decoded.RecoveryAffectedPods)
			if e != nil || again != digest {
				t.Fatal("wire changed scope hash", e)
			}
			for _, mode := range []string{"missing", "null"} {
				copy := map[string]json.RawMessage{}
				for k, v := range fields {
					copy[k] = v
				}
				if mode == "missing" {
					delete(copy, "RecoveredPods")
				} else {
					copy["RecoveredPods"] = json.RawMessage("null")
				}
				bad, e := json.Marshal(copy)
				if e != nil {
					t.Fatal(e)
				}
				var in NodeObservationRequest
				if observationJSON(bytes.NewReader(bad), &in) != nil {
					t.Fatal("JSON shape decode failed")
				}
				if nodeObservationPhaseDataValid(in, "node") {
					t.Fatal("unknown current membership became actual empty", mode)
				}
			}
			r.RecoveredPods = nil
			if nodeObservationPhaseDataValid(r, "node") {
				t.Fatal("nil current membership accepted")
			}
		})
	}
	_, r, _ := scopedRecoveryData(t, "recovery-source-stopped")
	original, e := OriginalRecoveryScopeSHA256(r, r.RecoveryAffectedPods)
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(*NodeObservationRequest)
	}{
		{"snapshot", func(r *NodeObservationRequest) { r.RecoverySnapshotSHA256 = strings.Repeat("a", 64) }},
		{"current", func(r *NodeObservationRequest) { r.RecoveredPods = []PodIdentity{} }},
		{"epoch", func(r *NodeObservationRequest) { r.Binding.FenceEpoch = 1 }},
		{"operation", func(r *NodeObservationRequest) { r.Binding.OperationID = "foreign" }},
		{"anchor", func(r *NodeObservationRequest) { r.Anchor += "0" }},
	}
	baseRaw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var changed NodeObservationRequest
			if json.Unmarshal(baseRaw, &changed) != nil {
				t.Fatal("scope fixture clone")
			}
			tc.change(&changed)
			digest, e := OriginalRecoveryScopeSHA256(changed, changed.RecoveryAffectedPods)
			if e == nil && digest == original {
				t.Fatal("changed scope reused original hash")
			}
		})
	}
	r.Nonce = "different-transport-nonce"
	r.Deadline = time.Now().Add(time.Second)
	same, e := OriginalRecoveryScopeSHA256(r, r.RecoveryAffectedPods)
	if e != nil || same != original {
		t.Fatal("transport nonce created a snapshot self-hash", e)
	}
	var absent *VerifiedNodeObservation
	if absent.RecheckOriginalRecoveryScope(context.Background(), r, r.RecoveryAffectedPods, "boot", time.Now()) == nil || absent.Recheck(context.Background(), r.Binding, r.Action, "boot", time.Now()) == nil {
		t.Fatal("DATA created an opaque observation")
	}
	var _ interface {
		ObserveOriginalRecoveryScope(context.Context, NodeObservationRequest, []PodIdentity) (*VerifiedNodeObservation, error)
	} = (*NodeObservationClient)(nil)
}
func TestOriginalRecoveryScopedPhaseRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NodeObservationRequest)
	}{
		{"missing-facts", func(r *NodeObservationRequest) { r.RecoverySnapshotSHA256 = "" }},
		{"unknown-current", func(r *NodeObservationRequest) { r.RecoveredPods = nil }},
		{"fake-next-gate", func(r *NodeObservationRequest) { r.RecoveredGeneration++ }},
		{"missing-affected", func(r *NodeObservationRequest) { r.RecoveryAffectedPods = nil }},
		{"not-strict-subset", func(r *NodeObservationRequest) { r.RecoveryAffectedPods = copyRecoveryPods(r.Pods) }},
		{"foreign-affected", func(r *NodeObservationRequest) { r.RecoveryAffectedPods[0].UID = "foreign" }},
		{"affected-still-current", func(r *NodeObservationRequest) { r.RecoveredPods = append(r.RecoveredPods, r.RecoveryAffectedPods[0]) }},
		{"forged-old-container", func(r *NodeObservationRequest) {
			r.RecoveredPods[0].Containers = []string{"containerd://" + strings.Repeat("9", 64)}
		}},
		{"new-source-path", func(r *NodeObservationRequest) { r.SourcePaths = []string{"/other"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r, _ := scopedRecoveryData(t, "recovery-source-stopped")
			tc.change(&r)
			if nodeObservationPhaseDataValid(r, "node") {
				t.Fatal("invalid scoped role request accepted")
			}
		})
	}
	_, r, _ := scopedRecoveryData(t, "recovery-reconciled")
	r.RecoveryAffectedPods = []PodIdentity{r.Pods[0]}
	if nodeObservationPhaseDataValid(r, "node") {
		t.Fatal("final reconciliation selected a stopped subset")
	}
	legacy := nodeGatewayZeroWholeRequest()
	raw, e := json.Marshal(legacy)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("RecoveryAffectedPods")) || bytes.Contains(raw, []byte("RecoverySnapshotSHA256")) {
		t.Fatal("legacy normal-phase wire gained new fields")
	}
}

// Actual TLS/production handler runs end only in native host_visibility refusal;
// neither current=[], nor a private-journal hash, may mint opaque success.
func TestOriginalRecoveryScopedClientRealTLSRefusesUnavailableNative(t *testing.T) {
	f := nodeGatewayZeroTLS(t)
	o, _, _ := scopedRecoveryData(t, "recovery-reconciled")
	handler := &NodeObservationHandler{Observer: o, ControllerURI: f.clientURI}
	received := make(chan NodeObservationRequest, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, e := io.ReadAll(io.LimitReader(r.Body, 512<<10))
		if e != nil {
			w.WriteHeader(400)
			return
		}
		var in NodeObservationRequest
		if observationJSON(bytes.NewReader(raw), &in) != nil {
			w.WriteHeader(400)
			return
		}
		received <- in
		r.Body = io.NopCloser(bytes.NewReader(raw))
		handler.ServeHTTP(w, r)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.roots}
	server.StartTLS()
	defer server.Close()
	client, e := NewNodeObservationClient(map[string]ProofEndpoint{"node": {URL: server.URL + "/observation/v1", ServerURI: f.serverURI}}, f.caPath, f.clientCert, f.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"recovery-source-stopped", "recovery-reconciled"} {
		for _, empty := range []bool{false, true} {
			name := action
			if empty {
				name += "-actual-empty"
			}
			t.Run(name, func(t *testing.T) {
				_, r, _ := scopedRecoveryData(t, action)
				if empty {
					r.RecoveredPods = []PodIdentity{}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var proof *VerifiedNodeObservation
				var e error
				if action == "recovery-source-stopped" {
					proof, e = client.ObserveOriginalRecoveryScope(ctx, r, r.RecoveryAffectedPods)
				} else {
					proof, e = client.ObserveVerified(ctx, r)
				}
				var failure NodeObservationFailure
				if proof != nil || !errors.As(e, &failure) || failure.Stage != "host_visibility" {
					t.Fatal("scoped refusal became success or never dispatched", e)
				}
				select {
				case actual := <-received:
					if actual.RecoveredPods == nil || !reflect.DeepEqual(actual.RecoveredPods, r.RecoveredPods) || actual.RecoverySnapshotSHA256 != r.RecoverySnapshotSHA256 || actual.Anchor != r.Anchor || observationDigest(actual.Binding) != observationDigest(r.Binding) {
						t.Fatal("scope changed in authenticated JSON roundtrip")
					}
					expected, e := OriginalRecoveryScopeSHA256(r, r.RecoveryAffectedPods)
					if e != nil {
						t.Fatal(e)
					}
					got, e := OriginalRecoveryScopeSHA256(actual, actual.RecoveryAffectedPods)
					if e != nil || got != expected {
						t.Fatal("TLS body changed stable scope", e)
					}
				default:
					t.Fatal("request was not dispatched")
				}
			})
		}
	}
	t.Run("expired-capture-still-refuses", func(t *testing.T) {
		_, r, _ := scopedRecoveryData(t, "recovery-reconciled")
		r.Action = "stopped"
		r.RecoveredPods = nil
		r.RecoveredGeneration = 0
		r.RecoverySnapshotSHA256 = ""
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if proof, e := client.ObserveVerified(ctx, r); proof != nil || e == nil {
			t.Fatal("capture expired window widened")
		}
		select {
		case <-received:
			t.Fatal("expired capture dispatched")
		default:
		}
	})
}
