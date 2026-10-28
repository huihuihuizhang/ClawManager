package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransitSignerTLSVersionAndPublicKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, mode := range []string{"valid", "wrong-version", "wrong-signature", "provider-error", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			redirected := false
			other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
			defer other.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/transit/sign/test-key" || r.Header.Get("X-Vault-Token") != strings.Repeat("t", 32) {
					t.Error("invalid provider request")
					w.WriteHeader(400)
					return
				}
				if mode == "provider-error" {
					http.Error(w, "PRIVATE provider error", 500)
					return
				}
				if mode == "redirect" {
					http.Redirect(w, r, other.URL, 307)
					return
				}
				var wire struct {
					Input   string `json:"input"`
					Version string `json:"key_version"`
				}
				if json.NewDecoder(r.Body).Decode(&wire) != nil || wire.Version != "1" {
					t.Error("provider requires explicit string key version")
					w.WriteHeader(400)
					return
				}
				raw, _ := base64.StdEncoding.DecodeString(wire.Input)
				sig := ed25519.Sign(key, raw)
				prefix := "vault:v1:"
				if mode == "wrong-version" {
					prefix = "vault:v2:"
				}
				if mode == "wrong-signature" {
					sig[0] ^= 1
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": prefix + base64.StdEncoding.EncodeToString(sig)}})
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			signer, err := NewTransitSigner(server.URL, "test-key", "1", strings.Repeat("t", 32), ca, pub)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte("bounded signing input")
			sig, err := signer.Sign(context.Background(), raw)
			if mode == "valid" {
				if err != nil || !ed25519.Verify(pub, raw, sig) {
					t.Fatal("valid TLS signature rejected", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe signer response accepted")
			}
			if redirected {
				t.Fatal("token redirect followed")
			}
		})
	}
}
