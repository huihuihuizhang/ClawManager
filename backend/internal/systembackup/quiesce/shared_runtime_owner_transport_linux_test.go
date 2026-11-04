//go:build linux

package quiesce

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Actual mutual TLS and the concrete handler's rejection path. No native
// lifecycle success is manufactured with a transport callback.
func TestSharedOwnerTransportAuthenticatesBeforeNativeMutation(t *testing.T) {
	for _, scenario := range []string{"wrong-controller", "duplicate-field", "missing-host-source"} {
		t.Run(scenario, func(t *testing.T) {
			roots, serverCert, clientCert := proofCertificates(t)
			o, _, _ := sharedOwnerStoreFixture(t)
			h := &SharedRuntimeNodeHandler{owner: o, controllerURI: "spiffe://backup.internal/controller"}
			if scenario == "wrong-controller" {
				h.controllerURI = "spiffe://backup.internal/other-controller"
			}
			server := httptest.NewUnstartedServer(h)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			server.StartTLS()
			defer server.Close()
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Proxy: nil}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			raw, err := json.Marshal(sharedNodeRequestFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			want := http.StatusServiceUnavailable
			if scenario == "wrong-controller" {
				want = http.StatusForbidden
			}
			if scenario == "duplicate-field" {
				raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"Action":"freeze"}`)
				want = http.StatusBadRequest
			}
			res, err := client.Post(server.URL+SharedRuntimeNodeRoute, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil || res.StatusCode != want || len(body) != 0 || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("native rejection became proof", res.StatusCode, err)
			}
			entries, err := os.ReadDir(o.directory)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid request mutated native journal", err)
			}
		})
	}
}
