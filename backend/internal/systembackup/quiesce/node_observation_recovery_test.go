package quiesce

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wholeRecoveryDataRequest(action string) NodeObservationRequest {
	r := nodeGatewayZeroWholeRequest()
	r.Action = action
	r.SourcePaths = nil
	r.Anchor = "correlation-data-only"
	r.Binding.Generation = 41
	if action == "recovered" {
		r.RecoveredGeneration = r.Binding.Generation
		r.RecoveredPods = []PodIdentity{{Name: "replacement", UID: "replacement-pod", Node: r.Binding.Node, Containers: []string{"containerd://" + strings.Repeat("2", 64)}}}
	}
	return r
}

// These are request correlation DATA tests, not successful native observations.
// The SQL gate generation is deliberately independent of any source counter.
func TestWholePodRecoveryPhaseAndOriginalGateGenerationData(t *testing.T) {
	for _, phase := range []string{"recovery-stopped", "recovered"} {
		r := wholeRecoveryDataRequest(phase)
		if !nodeObservationPhaseDataValid(r, r.Binding.Node) {
			t.Fatal("original gate generation refused", phase)
		}
	}
	cases := []struct {
		name   string
		mutate func(*NodeObservationRequest)
	}{
		{"recovered-next-gate-is-not-original", func(r *NodeObservationRequest) { r.RecoveredGeneration++ }},
		{"recovered-zero-generation", func(r *NodeObservationRequest) { r.RecoveredGeneration = 0 }},
		{"recovered-original-pod-replay", func(r *NodeObservationRequest) { r.RecoveredPods[0].UID = r.Pods[0].UID }},
		{"recovered-new-source-path", func(r *NodeObservationRequest) { r.SourcePaths = []string{"/new-source"} }},
		{"recovered-missing-anchor", func(r *NodeObservationRequest) { r.Anchor = "" }},
		{"recovered-zero-original-gate", func(r *NodeObservationRequest) { r.Binding.Generation = 0; r.RecoveredGeneration = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := wholeRecoveryDataRequest("recovered")
			tc.mutate(&r)
			if nodeObservationPhaseDataValid(r, r.Binding.Node) {
				t.Fatal("foreign recovery correlation accepted")
			}
		})
	}
	t.Run("recovery-stopped-does-not-claim-replacements", func(t *testing.T) {
		r := wholeRecoveryDataRequest("recovery-stopped")
		r.RecoveredPods = wholeRecoveryDataRequest("recovered").RecoveredPods
		if nodeObservationPhaseDataValid(r, r.Binding.Node) {
			t.Fatal("replacement accepted before source recovery")
		}
	})
	t.Run("recovery-stopped-does-not-fill-generation", func(t *testing.T) {
		r := wholeRecoveryDataRequest("recovery-stopped")
		r.RecoveredGeneration = r.Binding.Generation
		if nodeObservationPhaseDataValid(r, r.Binding.Node) {
			t.Fatal("generation field was fabricated for pre-recovery stopped phase")
		}
	})
	t.Run("unknown-phase-not-recovery", func(t *testing.T) {
		r := wholeRecoveryDataRequest("unknown")
		if nodeObservationRecoveryAction(r.Action) || nodeObservationPhaseDataValid(r, r.Binding.Node) {
			t.Fatal("unknown phase gained recovery exception")
		}
	})
	for _, phase := range []string{"prepare", "stopped"} {
		if nodeObservationRecoveryAction(phase) {
			t.Fatal("capture phase gained expiry exception", phase)
		}
	}
}

func wholeRecoverySignedAnchorData(t *testing.T, phase string) (*NodeObserver, NodeObservationRequest, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	o := nodeGatewayUnavailableObserver(t)
	o.BootID = "original-node-boot"
	r := wholeRecoveryDataRequest(phase)
	r.Binding.ExpiresAt = now.Add(-time.Minute)
	a := nodeObservationAnchor{Binding: r.Binding, Pods: r.Pods, BootID: o.BootID, PreparedAt: now.Add(-2 * time.Minute), Paths: []observedPath{{Path: "/source", Device: 1, Inode: 2, Mount: "correlation-only-not-a-native-positive"}}}
	token, e := o.seal(a)
	if e != nil {
		t.Fatal(e)
	}
	r.Anchor = token
	return o, r, now
}

// This exercises the real HMAC and original anchor correlation only. No
// native/HTTP positive, client opaque proof, SQL authority or held gate is made.
func TestWholePodRecoveryOriginalAnchorExpiryAndReplayData(t *testing.T) {
	for _, phase := range []string{"recovery-stopped", "recovered"} {
		o, r, now := wholeRecoverySignedAnchorData(t, phase)
		if _, e := o.originalNodeObservationAnchor(r, now); e != nil {
			t.Fatal("unchanged original recovery anchor refused", phase, e)
		}
	}
	o, capture, now := wholeRecoverySignedAnchorData(t, "stopped")
	if _, e := o.originalNodeObservationAnchor(capture, now); e == nil {
		t.Fatal("expired capture stopped reused a recovery exception")
	}
	cases := []struct {
		name   string
		change func(*NodeObserver, *NodeObservationRequest)
	}{
		{"foreign-operation", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.OperationID = "foreign-original-operation" }},
		{"foreign-reservation", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.ReservationID = strings.Repeat("f", 32) }},
		{"foreign-inventory", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.InventorySHA256 = strings.Repeat("f", 64) }},
		{"foreign-node", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.NodeUID = "foreign-node" }},
		{"foreign-namespace", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.NamespaceUID = "foreign-namespace" }},
		{"next-gate-replay", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.Generation++ }},
		{"epoch-zero-is-not-one", func(o *NodeObserver, r *NodeObservationRequest) { r.Binding.FenceEpoch = 1 }},
		{"changed-original-expiry", func(o *NodeObserver, r *NodeObservationRequest) {
			r.Binding.ExpiresAt = r.Binding.ExpiresAt.Add(time.Hour)
		}},
		{"changed-original-pod", func(o *NodeObserver, r *NodeObservationRequest) { r.Pods[0].UID = "foreign-original-pod" }},
		{"changed-original-container", func(o *NodeObserver, r *NodeObservationRequest) {
			r.Pods[0].Containers = []string{"containerd://" + strings.Repeat("3", 64)}
		}},
		{"reboot", func(o *NodeObserver, r *NodeObservationRequest) { o.BootID = "replacement-node-boot" }},
		{"tampered-mac", func(o *NodeObserver, r *NodeObservationRequest) { r.Anchor += "0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, r, now := wholeRecoverySignedAnchorData(t, "recovery-stopped")
			tc.change(o, &r)
			if _, e := o.originalNodeObservationAnchor(r, now); e == nil {
				t.Fatal("foreign or replayed original anchor accepted")
			}
		})
	}
	t.Run("future-original-anchor", func(t *testing.T) {
		o, r, now := wholeRecoverySignedAnchorData(t, "recovery-stopped")
		a, e := o.open(r.Anchor)
		if e != nil {
			t.Fatal(e)
		}
		a.PreparedAt = now.Add(time.Minute)
		r.Anchor, e = o.seal(a)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = o.originalNodeObservationAnchor(r, now); e == nil {
			t.Fatal("future original anchor accepted")
		}
	})
}

func TestWholePodRecoveryExpiredClientDispatchUsesFreshRPC(t *testing.T) {
	f := nodeGatewayZeroTLS(t)
	o, _, _ := wholeRecoverySignedAnchorData(t, "recovery-stopped")
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
	client, e := NewNodeObservationClient(map[string]ProofEndpoint{o.Node: {URL: server.URL + "/observation/v1", ServerURI: f.serverURI}}, f.caPath, f.clientCert, f.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"recovery-stopped", "recovered"} {
		t.Run(phase, func(t *testing.T) {
			_, r, _ := wholeRecoverySignedAnchorData(t, phase)
			start := time.Now().UTC()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proof, e := client.ObserveVerified(ctx, r)
			var failure NodeObservationFailure
			if proof != nil || !errors.As(e, &failure) || failure.Stage != "host_visibility" {
				t.Fatal("expired recovery did not reach real native refusal, or refusal became proof", e)
			}
			select {
			case actual := <-received:
				if actual.Action != phase || actual.Anchor != r.Anchor || observationDigest(actual.Binding) != observationDigest(r.Binding) || actual.RecoveredGeneration != r.RecoveredGeneration || actual.Nonce == r.Nonce || !validObservationHash(actual.Nonce) || !start.Before(actual.Deadline) || actual.Deadline.After(start.Add(11*time.Second)) {
					t.Fatal("original anchor/gate or fresh RPC binding changed")
				}
			default:
				t.Fatal("fresh authenticated recovery request was never dispatched")
			}
		})
	}
	t.Run("capture-remains-expired", func(t *testing.T) {
		_, r, _ := wholeRecoverySignedAnchorData(t, "stopped")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if proof, e := client.ObserveVerified(ctx, r); e == nil || proof != nil {
			t.Fatal("expired capture accepted")
		}
		select {
		case <-received:
			t.Fatal("expired capture dispatched")
		default:
		}
	})
	t.Run("fake-next-gate-never-dispatches", func(t *testing.T) {
		_, r, _ := wholeRecoverySignedAnchorData(t, "recovered")
		r.RecoveredGeneration++
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if proof, e := client.ObserveVerified(ctx, r); e == nil || proof != nil {
			t.Fatal("invented next gate accepted")
		}
		select {
		case <-received:
			t.Fatal("invented next gate dispatched")
		default:
		}
	})
}

// The certificate is signed by the trusted CA but its actor URI is not the
// configured controller. The actual production handler must reject it before
// any native recovery observation; this is not a SQL releasing-authority test.
func TestWholePodRecoveryWrongTLSActorCannotGetObservation(t *testing.T) {
	f := nodeGatewayZeroTLS(t)
	o, r, _ := wholeRecoverySignedAnchorData(t, "recovery-stopped")
	handler := &NodeObservationHandler{Observer: o, ControllerURI: "spiffe://test/unrelated-controller"}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.roots}
	server.StartTLS()
	defer server.Close()
	client, e := NewNodeObservationClient(map[string]ProofEndpoint{o.Node: {URL: server.URL + "/observation/v1", ServerURI: f.serverURI}}, f.caPath, f.clientCert, f.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proof, e := client.ObserveVerified(ctx, r)
	if proof != nil || e != ErrNodeObservation {
		t.Fatal("foreign TLS actor got a recovery observation", e)
	}
}
