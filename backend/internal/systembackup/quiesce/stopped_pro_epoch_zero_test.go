package quiesce

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
)

// Epoch zero is legitimate original acquisition DATA, not a held-gate proof.
// A deliberately unavailable native path must still refuse after validation.
func TestStoppedProEpochZeroReachesNativeRefusal(t *testing.T) {
	r := stoppedProDataFixture()
	r.Binding.FenceEpoch = 0
	r.Deadline = time.Now().UTC().Add(5 * time.Second)
	r.NativeScopeSHA256 = StoppedProNativeScopeSHA256(r)
	if _, e := stoppedProBaselinePaths(r); e != nil {
		t.Fatal("epoch zero DATA refused", e)
	}
	ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
	defer cancel()
	dir := t.TempDir()
	o := &NodeObserver{Node: r.Binding.Node, NodeUID: r.Binding.NodeUID, HostProc: filepath.Join(dir, "missing-proc"), HostRoot: filepath.Join(dir, "missing-root"), key: make([]byte, 32)}
	out, e := o.ObserveStoppedPro(ctx, r)
	var failure NodeObservationFailure
	if !errors.As(e, &failure) || failure.Stage != "host_visibility" || out.Anchor != "" {
		t.Fatal("epoch zero did not reach actual unavailable-native refusal", e)
	}
	other := r
	other.Binding.FenceEpoch = 1
	if StoppedProNativeScopeSHA256(other) == r.NativeScopeSHA256 {
		t.Fatal("epoch remains required in the exact original scope hash")
	}
}

// Real mTLS client transport reaches a negative-only endpoint with epoch zero.
// It never mints an opaque/native success, an anchor or any all-writer proof.
func TestStoppedProEpochZeroClientDispatchesButNeverPromotesRefusal(t *testing.T) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "epoch-zero-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); e != nil {
		t.Fatal(e)
	}
	issue := func(serial int64, uriText, stem string, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		uri, e := url.Parse(uriText)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: stem}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{uri}}
		if usage == x509.ExtKeyUsageServerAuth {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
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
	serverURI := "spiffe://test/node/epoch-zero"
	clientURI := "spiffe://test/controller"
	serverPair, _, _ := issue(2, serverURI, "node", x509.ExtKeyUsageServerAuth)
	_, clientCert, clientKey := issue(3, clientURI, "controller", x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	received := make(chan StoppedProNodeObservationRequest, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != clientURI {
			w.WriteHeader(403)
			return
		}
		var in StoppedProNodeObservationRequest
		if observationJSON(r.Body, &in) != nil {
			w.WriteHeader(400)
			return
		}
		received <- in
		w.Header().Set("X-Claw-Observation-Stage", "host_visibility")
		w.WriteHeader(503)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	r := stoppedProDataFixture()
	r.Binding.FenceEpoch = 0
	state := flow.State{UID: r.Baseline.SourceKey, Generation: int64(r.Baseline.InstanceGeneration), Running: false, Checkpoint: StoppedProBaselineSHA256(r.Baseline)}
	r.OriginalStateSHA256 = StoppedProOriginalStateSHA256(state)
	r.NativeScopeSHA256 = StoppedProNativeScopeSHA256(r)
	client, e := NewStoppedProNodeObservationClient(map[string]ProofEndpoint{r.Binding.Node: {URL: server.URL + "/stopped-pro-observation/v1", ServerURI: serverURI}}, caPath, clientCert, clientKey)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	verified, e := client.ObserveWriter(ctx, r, state)
	var failure NodeObservationFailure
	if verified != nil || !errors.As(e, &failure) || failure.Stage != "host_visibility" {
		t.Fatal("client failed epoch-zero dispatch or promoted a refusal", e)
	}
	select {
	case actual := <-received:
		if actual.Binding.FenceEpoch != 0 || actual.NativeScopeSHA256 != r.NativeScopeSHA256 || actual.OriginalStateSHA256 != r.OriginalStateSHA256 {
			t.Fatal("client changed original acquisition DATA")
		}
	default:
		t.Fatal("epoch-zero request never reached authenticated negative endpoint")
	}
	var absent *VerifiedStoppedProNodeObservation
	if absent.Recheck(ctx, r.Binding, "stopped", "boot", StoppedProBaselineSHA256(r.Baseline), r.OriginalReservationIdentitySHA256, r.OriginalStateSHA256, r.NativeScopeSHA256, time.Now()) == nil {
		t.Fatal("missing opaque observation bypassed gate/physical proof")
	}
}
