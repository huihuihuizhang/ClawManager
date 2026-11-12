package systembackupinstallationowner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
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
