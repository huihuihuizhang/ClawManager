package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/config"
)

func TestObjectStorageOriginalCAUsesScopedVerifiedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	file := filepath.Join(t.TempDir(), "minio-original-ca.pem")
	if e := os.WriteFile(file, ca, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(ca)
	cfg := config.ObjectStorageConfig{Endpoint: strings.TrimPrefix(server.URL, "https://"), UseSSL: true, TLSCAFile: file, TLSCASHA256: hex.EncodeToString(sum[:])}
	transport, e := objectStorageOriginalCATransport(cfg)
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: transport}
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("actual trusted TLS handshake", e)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("TLS was mistaken for provider authorization")
	}
	for _, fault := range []string{"plaintext", "missing-pin", "wrong-pin"} {
		t.Run(fault, func(t *testing.T) {
			bad := cfg
			switch fault {
			case "plaintext":
				bad.UseSSL = false
			case "missing-pin":
				bad.TLSCASHA256 = ""
			case "wrong-pin":
				bad.TLSCASHA256 = strings.Repeat("a", 64)
			}
			if _, e := objectStorageOriginalCATransport(bad); e == nil {
				t.Fatal("invalid original CA selection accepted")
			}
		})
	}
	if _, e := NewObjectStorageService(config.ObjectStorageConfig{TLSCAFile: file, TLSCASHA256: cfg.TLSCASHA256}); e == nil {
		t.Fatal("invalid selected TLS silently became local fallback")
	}
}
