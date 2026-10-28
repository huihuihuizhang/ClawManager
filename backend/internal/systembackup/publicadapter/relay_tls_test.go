package publicadapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRelayLoopbackRequiresRealMutualTLS(t *testing.T) {
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated B test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://b.test/worker")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), URIs: []*url.URL{uri}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parsed, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	peer := tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	owner := &relayFixture{}
	handler, err := newRelayHandler(owner)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{peer}
	client = &http.Client{Transport: transport, Timeout: time.Second}
	defer transport.CloseIdleConnections()
	m := RelayMessage{SchemaVersion: RelayVersion, InstallationID: "installation_test", TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", AttemptNo: "1", Phase: "capture", JobUnitKey: "users", Namespace: "cm-drill-b", JobName: "capture-one", JobUID: "22222222-2222-4222-8222-222222222222", JobGeneration: "1", RelayIdentityRef: "reference", RelayIdentityVersion: "version", Sequence: "1", Status: "ready"}
	raw, _ := json.Marshal(m)
	response, err := client.Post(srv.URL, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || owner.calls.Load() != 1 {
		t.Fatal("mutual TLS boundary rejected valid peer", response.StatusCode, owner.calls.Load())
	}
	noCert := srv.Client()
	noCert.Timeout = time.Second
	if response, err := noCert.Post(srv.URL, "application/json", strings.NewReader(string(raw))); err == nil {
		response.Body.Close()
		t.Fatal("TLS handshake accepted a client without certificate")
	}
	if owner.calls.Load() != 1 {
		t.Fatal("unauthenticated request reached transaction owner")
	}
	// Trust uses synthetic local keys. This proves native TLS transport only,
	// not the missing A workload binding/revocation or D SQL transaction.
}
