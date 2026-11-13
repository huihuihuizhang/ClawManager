package systembackupinstallationowner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInstalledVaultLocalForwardPreservesTLSIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, tc := range []struct {
		name  string
		roots *x509.CertPool
		ok    bool
	}{
		{server.Certificate().DNSNames[0], roots, true},
		{"wrong-vault.invalid", roots, false},
		{server.Certificate().DNSNames[0], x509.NewCertPool(), false},
	} {
		endpoint := "https://" + tc.name + ":8200"
		dial, err := installedVaultLocalForwardDial(endpoint, server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: tc.roots, MinVersion: tls.VersionTLS12}}
		client := &http.Client{Transport: transport}
		res, err := client.Get(endpoint)
		if res != nil {
			res.Body.Close()
		}
		transport.CloseIdleConnections()
		if (err == nil) != tc.ok {
			t.Fatalf("host=%s expected success=%v, got %v", tc.name, tc.ok, err)
		}
	}
}

func TestInstalledVaultMetadataForwardKeepsIdentityAndClosedTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:8200" || r.Header.Get("X-Vault-Token") != "fixture-metadata-token" {
			t.Error("original host/token lost")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cfg := InstalledVaultDependencyConfig{Version: "installed-vault-dependency-input.v1", Endpoint: "https://example.com:8200", CAPEM: ca, CASHA256: digest(ca), ClusterID: "cluster", TransitMount: "transit", JWTMount: "jwt", PinnedKeyName: "key", PinnedKeyVersion: "1", TokenFile: filepath.Join(t.TempDir(), "not-read-by-constructor"), TokenSHA256: digest([]byte("fixture-metadata-token")), IdentityMode: "metadata-only", ObserverPolicy: "sbk-fixture", Trust: a.VaultJWTTrust{Issuer: "https://issuer.invalid", Algorithms: []string{"RS256"}, ValidationPublicKeys: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}}
	for _, fault := range []string{"valid", "wrong-host", "wrong-ca", "root", "remote-route", "root-policy"} {
		t.Run(fault, func(t *testing.T) {
			current := cfg
			address := server.Listener.Addr().String()
			switch fault {
			case "wrong-host":
				current.Endpoint = "https://wrong.invalid:8200"
			case "wrong-ca":
				current.CASHA256 = digest([]byte("foreign"))
			case "root":
				current.IdentityMode = "original-owner-readonly"
				current.ObserverPolicy = ""
			case "remote-route":
				address = "10.0.0.1:8200"
			case "root-policy":
				current.ObserverPolicy = "root"
			}
			before := current
			o, e := NewInstalledVaultMetadataObserverWithLocalForward(current, fake.NewSimpleClientset(), "ns", "ns-uid", address)
			if e == nil {
				defer o.Close()
				_, e = o.transport.request(context.Background(), http.MethodGet, "/v1/sys/health", []byte("fixture-metadata-token"), nil)
			}
			if (e == nil) != (fault == "valid") {
				t.Fatal("identity/route boundary", e)
			}
			if !reflect.DeepEqual(current, before) || o != nil && !reflect.DeepEqual(o.cfg, before) {
				t.Fatal("local route persisted into input")
			}
		})
	}
	if _, err := NewInstalledVaultDependencyObserverWithLocalForward(cfg, fake.NewSimpleClientset(), "ns", "uid", server.Listener.Addr().String()); err == nil {
		t.Fatal("root-only installer entry accepted metadata identity")
	}
	admin := cfg
	admin.IdentityMode, admin.ObserverPolicy = "original-owner-readonly", ""
	o, err := NewInstalledVaultDependencyObserverWithLocalForward(admin, fake.NewSimpleClientset(), "ns", "uid", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	// Transport fixture only: exercise the native policy-write path through the
	// same route. No real Vault policy, administrator or mint is represented.
	if _, err := o.metadataIdentityWrite(context.Background(), "/v1/sys/policies/acl/fixture", []byte("fixture-metadata-token"), []byte(`{"policy":"fixture"}`)); err != nil {
		t.Fatal("policy writer lost the installer route", err)
	}
}

func TestInstalledVaultLocalForwardRejectsOtherRoutes(t *testing.T) {
	for _, address := range []string{"localhost:8200", "10.0.0.1:8200", "0.0.0.0:8200", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:08200", "127.0.0.1"} {
		if _, err := installedVaultLocalForwardDial("https://vault.invalid:8200", address); err == nil {
			t.Fatal(address)
		}
	}
	dial, err := installedVaultLocalForwardDial("https://vault.invalid:8200", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range [][2]string{{"tcp", "other.invalid:8200"}, {"tcp", "vault.invalid:443"}, {"udp", "vault.invalid:8200"}} {
		if _, err := dial(context.Background(), route[0], route[1]); err != ErrOwner {
			t.Fatalf("unexpected route result: %v", err)
		}
	}
}
