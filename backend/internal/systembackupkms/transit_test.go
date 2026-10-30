package systembackupkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	w "clawreef/internal/systembackupwire"
)

type resolverFunc func(context.Context, Access) (Grant, error)

func (f resolverFunc) Resolve(c context.Context, a Access) (Grant, error) { return f(c, a) }

func testRequest() w.KeyRequest {
	return w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: hash([]byte("key")), RegistryVersion: "registry-r17", ProviderKeyID: "backup-key", ProviderVersion: "3"}, Context: w.KeyContext{InstallationID: "installation_test", BackupPublicID: "sbk_original", AttemptNo: "1", Phase: "capture", Part: "workspace", PartIndex: "0", EnvelopeID: "env-1", CaptureContextHash: hash([]byte("frozen"))}}
}
func testCiphertext() string {
	return "vault:v3:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 60))
}
func testConfig(s *httptest.Server) Config {
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	return Config{Endpoint: s.URL, InstallationID: testRequest().Context.InstallationID, KeyName: "backup-key", Key: testRequest().Key, CAPEM: ca, CASHA256: hash(ca), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
}

func TestCaptureGeneratorRejectsMissingProviderHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid endpoint reached provider")
	}))
	defer server.Close()
	cfg := testConfig(server)
	cfg.Endpoint = "https://:8200"
	resolver := resolverFunc(func(context.Context, Access) (Grant, error) {
		t.Fatal("invalid endpoint reached resolver")
		return Grant{}, nil
	})
	if _, err := NewCaptureGenerator(cfg, resolver); !errors.Is(err, ErrBinding) {
		t.Fatalf("missing hostname admitted: %v", err)
	}
}

func TestOnlineGenerateUnwrapBindingAndRevocation(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-purpose", "wrong-installation", "wrong-key", "wrong-version", "wrong-registry", "wrong-context", "expired", "not-yet-valid", "revoked-before", "revoked-after-provider", "revoke-at-use", "wrong-response-version", "wrong-ciphertext", "bad-plaintext", "duplicate-json", "provider-denied", "callback-fails", "use-not-called", "callback-error-swallowed", "cancel-at-provider", "revoked-after-use", "unknown-use-commit"} {
		t.Run(mode, func(t *testing.T) {
			r := testRequest()
			calls, used := 0, 0
			revoked := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dek := bytes.Repeat([]byte{7}, 32)
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
				calls++
				if req.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || req.Method != "POST" || req.Header.Get("X-Vault-Token") != "synthetic-token-only" {
					t.Error("wrong provider wire")
				}
				var body map[string]string
				if json.NewDecoder(req.Body).Decode(&body) != nil {
					t.Error("body")
				}
				want, _ := TransitContext(r)
				if len(body) != 3 || body["context"] != want || body["bits"] != "256" || body["key_version"] != "3" {
					t.Error("context/version not explicit")
				}
				if mode == "revoked-after-provider" {
					revoked = true
				}
				if mode == "cancel-at-provider" {
					cancel()
				}
				if mode == "provider-denied" {
					out.WriteHeader(403)
					return
				}
				data := map[string]any{"plaintext": dek, "ciphertext": testCiphertext(), "key_version": 3}
				if mode == "wrong-response-version" {
					data["key_version"] = 1
				}
				if mode == "wrong-ciphertext" {
					data["ciphertext"] = "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 60))
				}
				if mode == "bad-plaintext" {
					data["plaintext"] = []byte{1}
				}
				if mode == "duplicate-json" {
					out.Write([]byte(`{"data":{"plaintext":"a","plaintext":"b"}}`))
					return
				}
				json.NewEncoder(out).Encode(map[string]any{"data": data})
			}))
			defer server.Close()
			var secret []byte
			var borrowed []byte
			resolver := resolverFunc(func(_ context.Context, a Access) (Grant, error) {
				secret = []byte("synthetic-token-only")
				g := Grant{Access: a, Secret: secret, NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
				g.Recheck = func(context.Context, Access) error {
					if revoked {
						return ErrPermission
					}
					return nil
				}
				g.WithUse = func(c context.Context, a Access, f func() error) error {
					if mode == "revoke-at-use" {
						revoked = true
					}
					if revoked {
						return ErrPermission
					}
					if mode == "use-not-called" {
						return nil
					}
					if mode == "unknown-use-commit" {
						return ErrUnknown
					}
					e := f()
					if mode == "revoked-after-use" {
						revoked = true
					}
					if mode == "callback-error-swallowed" {
						return nil
					}
					return e
				}
				switch mode {
				case "wrong-purpose":
					g.Access.Operation = Unwrap
				case "wrong-installation":
					g.Access.Request.Context.InstallationID = "installation_other"
				case "wrong-key":
					g.Access.Request.Key.ProviderKeyID = "other"
				case "wrong-version":
					g.Access.Request.Key.ProviderVersion = "1"
				case "wrong-registry":
					g.Access.Request.Key.RegistryVersion = "other"
				case "wrong-context":
					g.Access.Request.Context.EnvelopeID = "other"
				case "expired":
					g.ExpiresAt = time.Now().Add(-time.Second)
				case "not-yet-valid":
					g.NotBefore = time.Now().Add(time.Second)
				case "revoked-before":
					revoked = true
				}
				return g, nil
			})
			g, e := NewCaptureGenerator(testConfig(server), resolver)
			if e != nil {
				t.Fatal(e)
			}
			defer g.Close()
			result, e := g.Generate(ctx, r, func(b []byte) error {
				used++
				borrowed = b
				if !bytes.Equal(b, dek) {
					t.Error("wrong DEK")
				}
				if mode == "callback-fails" || mode == "callback-error-swallowed" {
					return errors.New("secret callback error must be masked")
				}
				return nil
			})
			if mode == "unknown-use-commit" && !errors.Is(e, ErrUnknown) {
				t.Fatal("unknown use commit disguised", e)
			}
			if mode == "valid" {
				if e != nil || used != 1 || calls != 1 || string(result.Ciphertext) != testCiphertext() {
					t.Fatalf("valid: %v, %d, %d", e, used, calls)
				}
			} else {
				if e == nil || len(result.Ciphertext) != 0 {
					t.Fatal("unauthorized success")
				}
				if mode != "callback-fails" && mode != "callback-error-swallowed" && mode != "revoked-after-use" && used != 0 {
					t.Fatal("released denied DEK")
				}
				if e.Error() == "secret callback error must be masked" {
					t.Fatal("leaked callback error")
				}
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("owned secret not erased")
			}
			if _, ok := any(g).(w.Unwrapper); ok {
				t.Fatal("capture exposes unwrap")
			}
		})
	}
}

func TestOnlineUnwrapExpectedRequestAndHistory(t *testing.T) {
	r := testRequest()
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
		calls++
		var body map[string]string
		json.NewDecoder(req.Body).Decode(&body)
		c, _ := TransitContext(r)
		if req.URL.Path != "/v1/transit/decrypt/backup-key" || len(body) != 2 || body["context"] != c || body["ciphertext"] != testCiphertext() {
			t.Error("unwrap wire mismatch")
		}
		json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": bytes.Repeat([]byte{9}, 32)}})
	}))
	defer s.Close()
	resolver := resolverFunc(func(_ context.Context, a Access) (Grant, error) {
		if a.Operation != Unwrap {
			t.Fatal("borrowed forward permission")
		}
		return Grant{Access: a, Secret: []byte("synthetic-token-only"), NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute), Recheck: func(context.Context, Access) error { return nil }, WithUse: func(_ context.Context, _ Access, f func() error) error { return f() }}, nil
	})
	u, e := NewRecoveryUnwrapper(testConfig(s), resolver)
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	wrapped := w.WrappedKey{Request: r, Algorithm: "provider-native", Ciphertext: []byte(testCiphertext())}
	used := 0
	use := func(b []byte) error {
		used++
		if !bytes.Equal(b, bytes.Repeat([]byte{9}, 32)) {
			t.Fatal("wrong recovered DEK")
		}
		return nil
	}
	if e = u.Unwrap(context.Background(), r, wrapped, use); e != nil || used != 1 || calls != 1 {
		t.Fatalf("independent recovery %v", e)
	}
	for _, mutate := range []func(*w.WrappedKey){func(v *w.WrappedKey) { v.Request.Key.RegistryVersion = "latest" }, func(v *w.WrappedKey) { v.Request.Context.AttemptNo = "2" }, func(v *w.WrappedKey) { v.Request.Context.InstallationID = "other" }, func(v *w.WrappedKey) { v.Algorithm = "AES-256-KW" }, func(v *w.WrappedKey) { v.Ciphertext = []byte("vault:v1:bad") }} {
		bad := wrapped
		mutate(&bad)
		if u.Unwrap(context.Background(), r, bad, use) == nil {
			t.Fatal("untrusted envelope authorized its own unwrap")
		}
	}
	if used != 1 || calls != 1 {
		t.Fatal("rejected unwrap reached provider/callback")
	}
}

func TestFinalUseSerializesWithRevocation(t *testing.T) {
	var mu sync.Mutex
	revoked := false
	entered, release, revoking, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": bytes.Repeat([]byte{7}, 32), "ciphertext": testCiphertext(), "key_version": 3}})
	}))
	defer s.Close()
	r := resolverFunc(func(_ context.Context, a Access) (Grant, error) {
		check := func(context.Context, Access) error {
			mu.Lock()
			defer mu.Unlock()
			if revoked {
				return ErrPermission
			}
			return nil
		}
		return Grant{Access: a, Secret: []byte("synthetic-token-only"), NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute), Recheck: check, WithUse: func(_ context.Context, _ Access, f func() error) error {
			mu.Lock()
			defer mu.Unlock()
			if revoked {
				return ErrPermission
			}
			return f()
		}}, nil
	})
	g, e := NewCaptureGenerator(testConfig(s), r)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	go func() {
		defer close(done)
		g.Generate(context.Background(), testRequest(), func([]byte) error { close(entered); <-release; return nil })
	}()
	<-entered
	committed := make(chan struct{})
	go func() { close(revoking); mu.Lock(); revoked = true; close(committed); mu.Unlock() }()
	<-revoking
	select {
	case <-committed:
		t.Fatal("revocation committed during protected use")
	default:
	}
	close(release)
	<-done
	<-committed
	if _, e = g.Generate(context.Background(), testRequest(), func([]byte) error { t.Fatal("used after revocation"); return nil }); e == nil {
		t.Fatal("revocation ignored")
	}
}

func TestContextFullBinding(t *testing.T) {
	r := testRequest()
	encoded, e := TransitContext(r)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := base64.StdEncoding.DecodeString(encoded)
	var fields map[string]string
	if json.Unmarshal(b, &fields) != nil || len(fields) != 9 || fields["origin_installation_id"] != r.Context.InstallationID || fields["provider_version"] != "" {
		t.Fatal("context shape")
	}
	keyJSON := `{"identity_hash":"` + r.Key.IdentityHash + `","provider":"external-kms","provider_key_id":"backup-key","provider_version":"3","registry_version":"registry-r17"}`
	if fields["kek_binding_sha256"] != hash([]byte(keyJSON)) {
		t.Fatal("full KEK binding hash mismatch")
	}
}
