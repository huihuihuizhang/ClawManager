package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type signingCredentialResolver func(context.Context, TransitSigningRequest) (TransitSigningCredential, error)

func (f signingCredentialResolver) ResolveSigning(ctx context.Context, r TransitSigningRequest) (TransitSigningCredential, error) {
	return f(ctx, r)
}

func TestCredentialTransitSignerCallAuthority(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-purpose", "wrong-input", "wrong-provider-version", "expired", "future", "resolve-error", "no-recheck", "revoked-before", "revoked-after", "expires-during-call", "clock-rollback", "expires-after-recheck", "cancel-after", "input-mutated"} {
		t.Run(mode, func(t *testing.T) {
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			base := now
			input := []byte("original bounded artifact signing bytes")
			original := append([]byte(nil), input...)
			secret := []byte(strings.Repeat("t", 32))
			var calls atomic.Int32
			checks, resolutions := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/transit/sign/test-key" || r.Header.Get("X-Vault-Token") != strings.Repeat("t", 32) {
					t.Error("wrong key or credential")
				}
				var body struct {
					Input   string `json:"input"`
					Version string `json:"key_version"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != "1" {
					t.Error("wrong provider version wire")
				}
				raw, _ := base64.StdEncoding.DecodeString(body.Input)
				if string(raw) != string(original) {
					t.Error("caller changed authorized bytes")
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))}})
			}))
			defer server.Close()
			binding := TransitSigningBinding{InstallationID: "installation_test", Purpose: "capture_certificate", KeyID: "capture", KeyVersion: "opaque-v3", Endpoint: server.URL, KeyName: "test-key", ProviderVersion: "1"}
			key := ArtifactSigningPublicKey{InstallationID: binding.InstallationID, Purpose: binding.Purpose, KeyID: binding.KeyID, KeyVersion: binding.KeyVersion, PublicKey: pub, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
			resolver := signingCredentialResolver(func(cctx context.Context, r TransitSigningRequest) (TransitSigningCredential, error) {
				resolutions++
				if _, ok := cctx.Deadline(); !ok {
					t.Error("resolver lacks bounded context")
				}
				c := TransitSigningCredential{Request: r, Secret: secret, NotBefore: base.Add(-time.Minute), ExpiresAt: base.Add(time.Minute)}
				c.Recheck = func(recheckCtx context.Context, rr TransitSigningRequest) error {
					checks++
					if recheckCtx != cctx || rr != r {
						t.Error("recheck changed context or request")
					}
					if mode == "revoked-before" || (mode == "revoked-after" && checks == 2) {
						return errors.New("PRIVATE revoked")
					}
					if mode == "expires-after-recheck" && checks == 2 {
						now = c.ExpiresAt
					}
					if mode == "cancel-after" && checks == 2 {
						cancel()
					}
					return nil
				}
				switch mode {
				case "wrong-purpose":
					c.Request.Binding.Purpose = "catalog_record"
				case "wrong-input":
					c.Request.InputSHA256 = strings.Repeat("0", 64)
				case "wrong-provider-version":
					c.Request.Binding.ProviderVersion = "2"
				case "expired":
					c.ExpiresAt = base
				case "future":
					c.NotBefore = base.Add(time.Second)
				case "resolve-error":
					return c, errors.New("PRIVATE resolver failure")
				case "no-recheck":
					c.Recheck = nil
				case "input-mutated":
					input[0] ^= 1
				}
				return c, nil
			})
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			s, err := NewCredentialTransitSigner(binding, key, ca, resolver)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			// Update the clock after transport completes, on the caller goroutine.
			s.now = func() time.Time {
				if calls.Load() > 0 && mode == "expires-during-call" {
					return base.Add(time.Minute)
				}
				if calls.Load() > 0 && mode == "clock-rollback" {
					return base.Add(-time.Second)
				}
				return now
			}
			sig, err := s.Sign(ctx, input)
			valid := mode == "valid" || mode == "input-mutated"
			if valid {
				if err != nil || !ed25519.Verify(pub, original, sig) || calls.Load() != 1 || checks != 2 {
					t.Fatalf("valid call rejected: %v", err)
				}
			} else if err != ErrRegistrationUnavailable || len(sig) != 0 {
				t.Fatalf("unauthorized signature exposed: %v", err)
			}
			if resolutions != 1 || s.transport.token != "" {
				t.Fatal("credential refreshed or retained")
			}
			for _, b := range secret {
				if b != 0 {
					t.Fatal("owned credential buffer not erased")
				}
			}
			if checks < 1 && calls.Load() != 0 {
				t.Fatal("invalid credential reached provider")
			}
			if mode == "revoked-before" && calls.Load() != 0 {
				t.Fatal("revoked grant reached provider")
			}
		})
	}
}

func TestCredentialTransitSignerConstructorBoundary(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("constructor performed I/O") }))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	b := TransitSigningBinding{InstallationID: "installation_test", Purpose: "capture_certificate", KeyID: "capture", KeyVersion: "opaque", Endpoint: server.URL, KeyName: "test-key", ProviderVersion: "1"}
	k := ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: pub, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	resolver := signingCredentialResolver(func(context.Context, TransitSigningRequest) (TransitSigningCredential, error) {
		t.Fatal("unexpected resolve")
		return TransitSigningCredential{}, nil
	})
	var absent signingCredentialResolver
	if s, err := NewCredentialTransitSigner(b, k, ca, absent); err == nil || s != nil {
		t.Fatal("typed nil accepted")
	}
	k.Revoked = true
	if s, err := NewCredentialTransitSigner(b, k, ca, resolver); err == nil || s != nil {
		t.Fatal("revoked key accepted")
	}
	k.Revoked = false
	b.ProviderVersion = "01"
	if s, err := NewCredentialTransitSigner(b, k, ca, resolver); err == nil || s != nil {
		t.Fatal("noncanonical provider version accepted")
	}
	b.ProviderVersion = "1"
	b.Endpoint += "?"
	if s, err := NewCredentialTransitSigner(b, k, ca, resolver); err == nil || s != nil {
		t.Fatal("query accepted")
	}
}
