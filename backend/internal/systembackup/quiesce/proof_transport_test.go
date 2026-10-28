package quiesce

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func proofCertificates(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, identity string, usage x509.ExtKeyUsage) tls.Certificate {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		uri, _ := url.Parse(identity)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{uri}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}
	}
	return roots, issue(2, "spiffe://backup.internal/node/node-a", x509.ExtKeyUsageServerAuth), issue(3, "spiffe://backup.internal/controller", x509.ExtKeyUsageClientAuth)
}
func TestProofTransportAuthenticatesNodeControllerAndFreshRequest(t *testing.T) {
	roots, serverCert, clientCert := proofCertificates(t)
	id := strings.Repeat("a", 64)
	pods := []PodIdentity{{Name: "agent", UID: "pod-1", Node: "node-a", Containers: []string{"containerd://" + id}}}
	for _, scenario := range []string{"valid", "running", "wrong-node-certificate", "wrong-controller", "wrong-nonce", "stale-proof", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			inspected := 0
			handler := ProofHandler{ControllerURIs: map[string]bool{"spiffe://backup.internal/controller": scenario != "wrong-controller"}, Prover: CRIProver{Node: "node-a", Inspector: inspectFunc(func(context.Context, string) ([]byte, error) {
				inspected++
				state := "CONTAINER_EXITED"
				if scenario == "running" {
					state = "CONTAINER_RUNNING"
				}
				return []byte(fmt.Sprintf(`{"status":{"id":%q,"state":%q,"finishedAt":"123456789","labels":{"io.kubernetes.pod.uid":"pod-1"}}}`, id, state)), nil
			})}}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "redirect" {
					http.Redirect(w, r, "https://127.0.0.1:1", http.StatusTemporaryRedirect)
					return
				}
				if scenario == "wrong-nonce" || scenario == "stale-proof" {
					var q ProofRequest
					if readProofJSON(r.Body, &q) != nil {
						t.Error("bad request")
						return
					}
					response := ProofResponse{Node: q.Node, Nonce: q.Nonce, RequestSHA256: proofHash(q), Stopped: true, ObservedAt: time.Now()}
					if scenario == "wrong-nonce" {
						response.Nonce = strings.Repeat("0", 64)
					} else {
						response.ObservedAt = time.Now().Add(-time.Hour)
					}
					json.NewEncoder(w).Encode(response)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			server.StartTLS()
			defer server.Close()
			serverURI := "spiffe://backup.internal/node/node-a"
			if scenario == "wrong-node-certificate" {
				serverURI = "spiffe://backup.internal/node/node-b"
			}
			client := ProofClient{Roots: roots, Certificate: clientCert, Endpoints: map[string]ProofEndpoint{"node-a": {URL: server.URL + "/proof/v1", ServerURI: serverURI}}}
			e := client.Confirm(testDeadline(t), pods)
			if (scenario == "valid") != (e == nil) {
				t.Fatal("proof acceptance mismatch", e)
			}
			if (scenario == "wrong-controller" || scenario == "wrong-node-certificate") && inspected != 0 {
				t.Fatal("unauthenticated caller reached runtime")
			}
		})
	}
}
