package quiesce

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/flow"
)

func nodeGatewayZeroBinding(kind string) ObservationBinding {
	return ObservationBinding{Kind: kind, InstallationID: "install", OperationID: "actual-controller-operation", ReservationID: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64), Namespace: "ns", NamespaceUID: "ns-uid", Node: "node", NodeUID: "node-uid", Generation: 2, FenceEpoch: 0, ExpiresAt: time.Now().UTC().Add(time.Minute)}
}
func nodeGatewayZeroWholeRequest() NodeObservationRequest {
	return NodeObservationRequest{Version: "node-observation.v1", Action: "prepare", Nonce: strings.Repeat("d", 64), Binding: nodeGatewayZeroBinding(NodeObservationWholePodColdCut), Deadline: time.Now().UTC().Add(4 * time.Second), Pods: []PodIdentity{{Name: "original", UID: "pod", Node: "node", Containers: []string{"containerd://" + strings.Repeat("1", 64)}}}, SourcePaths: []string{"/source"}}
}
func nodeGatewayZeroRunningRequest() (GatewayNodeObservationRequest, flow.State) {
	b := nodeGatewayZeroBinding(GatewayNodeRunning)
	q := &services.RuntimeBackupRequest{Protocol: services.RuntimeBackupProtocol, Namespace: b.Namespace, PodUID: "pod", AgentEpoch: strings.Repeat("a", 32), OperationID: b.ReservationID, RuntimeType: "opencode", InstanceID: 1, UserID: 3, Generation: 2, GatewayID: "gw-1-2", GatewayPort: 18790, ExpectedPID: 123, ResumeGeneration: 3, RestartSHA256: strings.Repeat("e", 64)}
	s := flow.State{UID: "pod/gw-1-2", Generation: 2, Running: true, Checkpoint: "original-running-checkpoint"}
	r := GatewayNodeObservationRequest{Version: GatewayNodeObservationProtocol, Action: "prepare", Nonce: strings.Repeat("d", 64), Binding: b, Deadline: time.Now().UTC().Add(4 * time.Second), AgentPod: PodIdentity{Name: "agent", UID: "pod", Node: "node", Containers: []string{"containerd://" + strings.Repeat("1", 64)}}, Running: q, Slot: "slot-0", WorkspaceRoot: "/workspaces", AgentDataDir: "/state", SourcePaths: []string{"/source"}, OriginalStateSHA256: observationDigest(s)}
	return r, s
}
func nodeGatewayZeroStoppedRequest(t *testing.T) (GatewayNodeObservationRequest, flow.State) {
	t.Helper()
	r, _ := gatewayStoppedDataFixture(t)
	r.Version = GatewayNodeObservationProtocol
	r.Nonce = strings.Repeat("d", 64)
	r.Binding = nodeGatewayZeroBinding(GatewayNodeOriginallyStopped)
	r.Binding.ExpiresAt = r.Stopped.HoldUntil
	r.Deadline = time.Now().UTC().Add(4 * time.Second)
	r.AgentPod = PodIdentity{Name: "agent", UID: "pod", Node: "node", Containers: []string{"containerd://" + strings.Repeat("1", 64)}}
	r.WorkspaceRoot = "/workspaces"
	r.AgentDataDir = "/state"
	r.SourcePaths = []string{"/source"}
	s := flow.State{UID: "pod/gw-1-2", Generation: 2, Running: false, Checkpoint: r.Stopped.CheckpointSHA256}
	r.OriginalStateSHA256 = observationDigest(s)
	return r, s
}
func nodeGatewayUnavailableObserver(t *testing.T) *NodeObserver {
	t.Helper()
	dir := t.TempDir()
	return &NodeObserver{Node: "node", NodeUID: "node-uid", HostProc: filepath.Join(dir, "missing-proc"), HostRoot: filepath.Join(dir, "missing-root"), key: make([]byte, 32)}
}

// Valid epoch-zero requests must reach a real unavailable-native refusal,
// never a fabricated native success. SQL gate/hold authority is not modeled.
func TestNodeGatewayEpochZeroReachesNativeRefusal(t *testing.T) {
	o := nodeGatewayUnavailableObserver(t)
	t.Run("whole-pod", func(t *testing.T) {
		r := nodeGatewayZeroWholeRequest()
		ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
		defer cancel()
		out, e := o.Observe(ctx, r)
		var f NodeObservationFailure
		if !errors.As(e, &f) || f.Stage != "host_visibility" || out.Anchor != "" {
			t.Fatal("epoch zero did not reach native refusal", e)
		}
		other := r.Binding
		other.FenceEpoch = 1
		if observationDigest(other) == observationDigest(r.Binding) {
			t.Fatal("original epoch lost from binding")
		}
	})
	t.Run("gateway-running", func(t *testing.T) {
		r, _ := nodeGatewayZeroRunningRequest()
		ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
		defer cancel()
		out, e := o.ObserveGateway(ctx, r)
		var f NodeObservationFailure
		if !errors.As(e, &f) || f.Stage != "host_visibility" || out.Anchor != "" {
			t.Fatal("epoch zero did not reach native refusal", e)
		}
	})
	t.Run("gateway-originally-stopped", func(t *testing.T) {
		r, _ := nodeGatewayZeroStoppedRequest(t)
		ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
		defer cancel()
		out, e := o.ObserveGateway(ctx, r)
		var f NodeObservationFailure
		if !errors.As(e, &f) || f.Stage != "host_visibility" || out.Anchor != "" {
			t.Fatal("epoch zero did not reach native refusal", e)
		}
	})
}

func TestNodeGatewayEpochZeroRetainsIdentityExpiryAndPhaseRefusals(t *testing.T) {
	o := nodeGatewayUnavailableObserver(t)
	for _, tc := range []struct {
		name   string
		mutate func(*NodeObservationRequest)
	}{
		{"whole-node-identity", func(r *NodeObservationRequest) { r.Binding.NodeUID = "foreign" }},
		{"whole-zero-generation", func(r *NodeObservationRequest) { r.Binding.Generation = 0 }},
		{"whole-expired-capture", func(r *NodeObservationRequest) { r.Binding.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"whole-foreign-kind", func(r *NodeObservationRequest) { r.Binding.Kind = GatewayNodeRunning }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nodeGatewayZeroWholeRequest()
			tc.mutate(&r)
			ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
			defer cancel()
			if _, e := o.Observe(ctx, r); e != ErrNodeObservation {
				t.Fatal("invalid identity or expiry reached native access", e)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*GatewayNodeObservationRequest)
	}{
		{"gateway-node-identity", func(r *GatewayNodeObservationRequest) { r.Binding.NodeUID = "foreign" }},
		{"gateway-reservation-identity", func(r *GatewayNodeObservationRequest) { r.Binding.ReservationID = strings.Repeat("f", 32) }},
		{"gateway-expired-capture", func(r *GatewayNodeObservationRequest) { r.Binding.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"gateway-unknown-phase", func(r *GatewayNodeObservationRequest) { r.Action = "unknown" }},
		{"gateway-original-state-missing", func(r *GatewayNodeObservationRequest) { r.OriginalStateSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := nodeGatewayZeroRunningRequest()
			tc.mutate(&r)
			ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
			defer cancel()
			if _, e := o.ObserveGateway(ctx, r); e != ErrNodeObservation {
				t.Fatal("invalid original binding/phase reached native access", e)
			}
		})
	}
}

type nodeGatewayZeroTLSFixture struct {
	serverURI, clientURI, caPath, clientCert, clientKey string
	serverPair                                          tls.Certificate
	roots                                               *x509.CertPool
}

func nodeGatewayZeroTLS(t *testing.T) nodeGatewayZeroTLSFixture {
	t.Helper()
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node-gateway-zero-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	issue := func(serial int64, uriText, stem string, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		leaf, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		uri, e := url.Parse(uriText)
		if e != nil {
			t.Fatal(e)
		}
		x := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: stem}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{uri}}
		if usage == x509.ExtKeyUsageServerAuth {
			x.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		raw, e := x509.CreateCertificate(rand.Reader, x, ca, &leaf.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(leaf)
		if e != nil {
			t.Fatal(e)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		certPath := filepath.Join(dir, stem+".pem")
		keyPath := filepath.Join(dir, stem+"-key.pem")
		if e = os.WriteFile(certPath, certPEM, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(keyPath, keyPEM, 0600); e != nil {
			t.Fatal(e)
		}
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return pair, certPath, keyPath
	}
	f := nodeGatewayZeroTLSFixture{serverURI: "spiffe://test/node/gateway-zero", clientURI: "spiffe://test/controller", caPath: caPath, roots: x509.NewCertPool()}
	f.roots.AddCert(ca)
	f.serverPair, _, _ = issue(2, f.serverURI, "node", x509.ExtKeyUsageServerAuth)
	_, f.clientCert, f.clientKey = issue(3, f.clientURI, "controller", x509.ExtKeyUsageClientAuth)
	return f
}

// Actual mTLS and the real production HTTP handlers reach only host_visibility
// failures. No positive native response, assignment or opaque proof is forged.
func TestNodeGatewayEpochZeroClientsDispatchButNeverPromoteRefusal(t *testing.T) {
	tlsFixture := nodeGatewayZeroTLS(t)
	o := nodeGatewayUnavailableObserver(t)
	wholeHandler := &NodeObservationHandler{Observer: o, ControllerURI: tlsFixture.clientURI}
	gatewayHandler := &GatewayNodeObservationHandler{Observer: o, ControllerURI: tlsFixture.clientURI}
	type seenRequest struct {
		binding          ObservationBinding
		originalStateSHA string
	}
	received := make(chan seenRequest, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, e := io.ReadAll(io.LimitReader(r.Body, 512<<10))
		if e != nil {
			w.WriteHeader(400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		switch r.URL.Path {
		case "/observation/v1":
			var in NodeObservationRequest
			if observationJSON(bytes.NewReader(raw), &in) != nil {
				w.WriteHeader(400)
				return
			}
			received <- seenRequest{binding: in.Binding}
			wholeHandler.ServeHTTP(w, r)
		case "/gateway-observation/v1":
			var in GatewayNodeObservationRequest
			if observationJSON(bytes.NewReader(raw), &in) != nil {
				w.WriteHeader(400)
				return
			}
			received <- seenRequest{binding: in.Binding, originalStateSHA: in.OriginalStateSHA256}
			gatewayHandler.ServeHTTP(w, r)
		default:
			w.WriteHeader(404)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{tlsFixture.serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: tlsFixture.roots}
	server.StartTLS()
	defer server.Close()
	expectOriginal := func(binding ObservationBinding, originalStateSHA string) {
		t.Helper()
		select {
		case got := <-received:
			if got.binding.FenceEpoch != 0 || observationDigest(got.binding) != observationDigest(binding) || got.originalStateSHA != originalStateSHA {
				t.Fatal("original acquisition binding changed at real TLS dispatch")
			}
		default:
			t.Fatal("request never reached authenticated native handler")
		}
	}
	t.Run("whole-pod", func(t *testing.T) {
		r := nodeGatewayZeroWholeRequest()
		client, e := NewNodeObservationClient(map[string]ProofEndpoint{r.Binding.Node: {URL: server.URL + "/observation/v1", ServerURI: tlsFixture.serverURI}}, tlsFixture.caPath, tlsFixture.clientCert, tlsFixture.clientKey)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proof, e := client.ObserveVerified(ctx, r)
		var f NodeObservationFailure
		if proof != nil || !errors.As(e, &f) || f.Stage != "host_visibility" {
			t.Fatal("refusal promoted or dispatch blocked", e)
		}
		expectOriginal(r.Binding, "")
	})
	t.Run("gateway-running", func(t *testing.T) {
		r, state := nodeGatewayZeroRunningRequest()
		client, e := NewGatewayNodeObservationClient(map[string]ProofEndpoint{r.Binding.Node: {URL: server.URL + "/gateway-observation/v1", ServerURI: tlsFixture.serverURI}}, tlsFixture.caPath, tlsFixture.clientCert, tlsFixture.clientKey)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proof, e := client.ObserveWriter(ctx, r, state)
		var f NodeObservationFailure
		if proof != nil || !errors.As(e, &f) || f.Stage != "host_visibility" || proof.OriginalRestartSHA256() != "" {
			t.Fatal("refusal promoted or dispatch blocked", e)
		}
		expectOriginal(r.Binding, observationDigest(state))
		foreign := state
		foreign.UID = "foreign"
		if proof, e = client.ObserveWriter(ctx, r, foreign); e == nil || proof != nil {
			t.Fatal("foreign original state accepted")
		}
		expired := r
		expired.Binding.ExpiresAt = time.Now().Add(-time.Minute)
		if proof, e = client.ObserveWriter(ctx, expired, state); e == nil || proof != nil {
			t.Fatal("expired original capture accepted")
		}
		select {
		case <-received:
			t.Fatal("foreign state or expired original capture dispatched")
		default:
		}
	})
	t.Run("gateway-originally-stopped", func(t *testing.T) {
		r, state := nodeGatewayZeroStoppedRequest(t)
		client, e := NewGatewayNodeObservationClient(map[string]ProofEndpoint{r.Binding.Node: {URL: server.URL + "/gateway-observation/v1", ServerURI: tlsFixture.serverURI}}, tlsFixture.caPath, tlsFixture.clientCert, tlsFixture.clientKey)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proof, e := client.ObserveWriter(ctx, r, state)
		var f NodeObservationFailure
		if proof != nil || !errors.As(e, &f) || f.Stage != "host_visibility" || proof.OriginalRestartSHA256() != "" {
			t.Fatal("refusal promoted or dispatch blocked", e)
		}
		expectOriginal(r.Binding, observationDigest(state))
	})
}
