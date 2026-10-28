package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type systemPreparationFunc func(context.Context, Identity, string) (SystemPreparationAuthorization, error)

func (f systemPreparationFunc) AuthorizeSystemPreparation(ctx context.Context, i Identity, h string) (SystemPreparationAuthorization, error) {
	return f(ctx, i, h)
}

type systemTransitFixture struct {
	i                        Identity
	body                     []byte
	grant                    SystemPreparationAuthorization
	c                        TransitJWTConfig
	p                        *SystemTransitPreparer
	seed                     testKeys
	logins, encrypts, checks atomic.Int32
	revoked                  atomic.Bool
	mode                     string
}

func newSystemTransitFixture(t *testing.T, mode string) *systemTransitFixture {
	t.Helper()
	i, body, a, seed := smallSystemFixture(t)
	x := &systemTransitFixture{i: i, body: body, seed: seed, mode: mode}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("unexpected method")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/system-evidence/login":
			x.logins.Add(1)
			var payload map[string]string
			want, _ := os.ReadFile(x.c.TokenFile)
			if r.Header.Get("X-Vault-Token") != "" || json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload) != 2 || payload["role"] != x.c.Role || payload["jwt"] != string(want) {
				t.Error("unbound system JWT exchange")
				w.WriteHeader(400)
				return
			}
			if mode == "after login" {
				x.revoked.Store(true)
			}
			policy, ttl := x.c.Policy, 5
			if mode == "extra policy" {
				policy = "default"
			}
			if mode == "long ttl" {
				ttl = 21
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "system-batch-token-0123456789", "token_type": "batch", "renewable": false, "lease_duration": ttl, "policies": []string{policy}, "metadata": map[string]any{"role": x.c.Role}}})
		case "/v1/transit/encrypt/system-evidence-key":
			x.encrypts.Add(1)
			var payload struct {
				Plaintext []byte `json:"plaintext"`
				Context   string `json:"context"`
				Version   uint32 `json:"key_version"`
			}
			want, _ := EvidenceTransitContext(i.Installation, x.c.Transit.Key)
			if r.Header.Get("X-Vault-Token") != "system-batch-token-0123456789" || json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload.Plaintext) != 32 || payload.Context != want || payload.Version != 1 {
				t.Error("unbound system encryption")
				w.WriteHeader(400)
				return
			}
			defer wipe(payload.Plaintext)
			wrapped, err := (transitSeedKeys{seed}).Wrap(r.Context(), x.c.Transit.Key, payload.Plaintext)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			if mode == "after encrypt" {
				x.revoked.Store(true)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": string(wrapped), "key_version": 1}})
		default:
			t.Error("non-encrypt system endpoint used")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	dir := t.TempDir()
	x.c = TransitJWTConfig{Transit: TransitConfig{Endpoint: srv.URL, Installation: i.Installation, Key: KeyRef{strings.Repeat("b", 64), "v1"}, KeyName: "system-evidence-key", KeyVersion: 1, CAPEM: ca, CASHA256: hash(ca)}, Mount: "system-evidence", Role: "system-wrap", Policy: "system-encrypt-only", Issuer: "https://workload.example.invalid", Audience: "system-evidence-wrap", Subject: "system-producer", TokenFile: filepath.Join(dir, "wrap-token")}
	x.grant = SystemPreparationAuthorization{Content: a.grant, Key: x.c.Transit.Key, ProfileHash: SystemWrapProfileHash(x.c), AuthenticationAudience: "system-authentication", AuthenticationTokenFile: filepath.Join(dir, "authentication-token")}
	x.writeJWT(t, x.c.Issuer, x.c.Audience, x.c.Subject, "first-signature")
	authority := systemPreparationFunc(func(ctx context.Context, got Identity, profile string) (SystemPreparationAuthorization, error) {
		n := x.checks.Add(1)
		if got != i || profile != x.grant.ProfileHash || x.revoked.Load() || ctx.Err() != nil {
			return SystemPreparationAuthorization{}, ErrDenied
		}
		g := x.grant
		if mode == "renew" && n >= 5 {
			g.Content.ValidUntil = g.Content.ValidUntil.Add(time.Minute)
		}
		return g, nil
	})
	var err error
	x.p, err = NewSystemTransitPreparer(authority, x.c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.p.Close)
	return x
}

func (x *systemTransitFixture) writeJWT(t *testing.T, issuer, audience, subject, signature string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": subject, "exp": time.Now().Add(time.Minute).Unix()})
	if err := os.WriteFile(x.c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString(raw)+"."+signature), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSystemTransitPreparation(t *testing.T) {
	x := newSystemTransitFixture(t, "")
	for _, signature := range []string{"first-signature", "rotated-signature"} {
		x.writeJWT(t, x.c.Issuer, x.c.Audience, x.c.Subject, signature)
		var dst bytes.Buffer
		p, err := x.p.Prepare(context.Background(), x.i, source(x.body), &dst)
		if err != nil || bytes.Contains(dst.Bytes(), x.body) {
			t.Fatal("system preparation failed", err)
		}
		m := p.Manifest()
		ref := Ref{strings.Repeat("a", 64), "v1", "system/evidence", "exact-version"}
		store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: ref.ImmutableVersion}}
		plain, err := OpenRange(context.Background(), m, ref, store, taskPreparedReadKeys{x.seed}, 0, x.i.ContentSize-1)
		if err != nil || !bytes.Equal(plain, x.body) {
			t.Fatal("system Transit bytes did not round-trip", err)
		}
		wipe(plain)
	}
	if x.logins.Load() != 2 || x.encrypts.Load() != 2 || x.checks.Load() != 18 {
		t.Fatal("missing live checks or cached credentials", x.checks.Load())
	}
	if _, err := x.p.keys.Wrap(context.Background(), x.c.Transit.Key, make([]byte, 32)); err != ErrKey || x.logins.Load() != 2 {
		t.Fatal("unbound Wrap accepted", err)
	}
	if _, err := (systemTransitKeys{}).Unwrap(context.Background(), x.c.Transit.Key, nil); err != ErrKey {
		t.Fatal("system preparer can unwrap")
	}
	x.p.Close()
	x.p.Close()
	if _, err := x.p.Prepare(context.Background(), x.i, source(x.body), io.Discard); err != ErrDenied {
		t.Fatal("closed preparer accepted", err)
	}
}

func TestSystemTransitRevocationAndCredentialBoundaries(t *testing.T) {
	for _, mode := range []string{"after login", "after encrypt", "after staging", "renew", "extra policy", "long ttl", "JWT issuer", "JWT audience", "JWT subject", "caller deadline", "canceled", "same audience", "same file", "key drift", "profile drift"} {
		t.Run(mode, func(t *testing.T) {
			x := newSystemTransitFixture(t, mode)
			ctx := context.Background()
			var cancel context.CancelFunc
			switch mode {
			case "JWT issuer":
				x.writeJWT(t, "https://wrong.example.invalid", x.c.Audience, x.c.Subject, "signature")
			case "JWT audience":
				x.writeJWT(t, x.c.Issuer, "other-audience", x.c.Subject, "signature")
			case "JWT subject":
				x.writeJWT(t, x.c.Issuer, x.c.Audience, "other-subject", "signature")
			case "caller deadline":
				ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
			case "canceled":
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "same audience":
				x.grant.AuthenticationAudience = x.c.Audience
			case "same file":
				x.grant.AuthenticationTokenFile = strings.ToUpper(x.c.TokenFile)
			case "key drift":
				x.grant.Key.Version = "other"
			case "profile drift":
				x.grant.ProfileHash = strings.Repeat("f", 64)
			}
			dst := systemTransitWriter(func(b []byte) (int, error) {
				if mode == "after staging" {
					x.revoked.Store(true)
				}
				return len(b), nil
			})
			p, err := x.p.Prepare(ctx, x.i, source(x.body), dst)
			if err == nil || len(p.Manifest().Chunks) != 0 || strings.Contains(err.Error(), "token") {
				t.Fatal("bad system preparation accepted or leaked credentials", err)
			}
			if mode != "after encrypt" && mode != "after staging" && x.encrypts.Load() != 0 {
				t.Fatal("encryption reached after failed credential/authority check")
			}
		})
	}
}

type systemTransitWriter func([]byte) (int, error)

func (f systemTransitWriter) Write(b []byte) (int, error) { return f(b) }

func TestSystemTransitProfileAndConstructor(t *testing.T) {
	x := newSystemTransitFixture(t, "")
	for name, change := range map[string]func(*TransitJWTConfig){
		"endpoint":     func(c *TransitJWTConfig) { c.Transit.Endpoint += "other" },
		"installation": func(c *TransitJWTConfig) { c.Transit.Installation = "installation_other" },
		"key_name":     func(c *TransitJWTConfig) { c.Transit.KeyName = "other" },
		"key_ref":      func(c *TransitJWTConfig) { c.Transit.Key.Version = "v2" },
		"key_version":  func(c *TransitJWTConfig) { c.Transit.KeyVersion = 2 },
		"ca":           func(c *TransitJWTConfig) { c.Transit.CASHA256 = strings.Repeat("f", 64) },
		"mount":        func(c *TransitJWTConfig) { c.Mount = "other" },
		"role":         func(c *TransitJWTConfig) { c.Role = "other" },
		"policy":       func(c *TransitJWTConfig) { c.Policy = "other" },
		"issuer":       func(c *TransitJWTConfig) { c.Issuer = "https://other.example.invalid" },
		"audience":     func(c *TransitJWTConfig) { c.Audience = "other" },
		"subject":      func(c *TransitJWTConfig) { c.Subject = "other" },
		"token_file":   func(c *TransitJWTConfig) { c.TokenFile += "other" },
	} {
		t.Run(name, func(t *testing.T) {
			c := x.c
			change(&c)
			if SystemWrapProfileHash(c) == x.grant.ProfileHash {
				t.Fatal("profile omitted setting")
			}
		})
	}
	for name, change := range map[string]func(*TransitJWTConfig){
		"http":           func(c *TransitJWTConfig) { c.Transit.Endpoint = "http://example.invalid" },
		"issuer":         func(c *TransitJWTConfig) { c.Issuer = "http://issuer.invalid" },
		"root_policy":    func(c *TransitJWTConfig) { c.Policy = "root" },
		"default_policy": func(c *TransitJWTConfig) { c.Policy = "default" },
		"relative_token": func(c *TransitJWTConfig) { c.TokenFile = "token" },
		"invalid_role":   func(c *TransitJWTConfig) { c.Role = "../role" },
		"bad_ca":         func(c *TransitJWTConfig) { c.Transit.CAPEM = []byte("PRIVATE") },
	} {
		t.Run(name, func(t *testing.T) {
			c := x.c
			change(&c)
			if p, err := NewSystemTransitPreparer(x.p.authority, c); err != ErrKey || p != nil {
				t.Fatal("invalid configuration accepted", err)
			}
		})
	}
	var absent systemPreparationFunc
	if p, err := NewSystemTransitPreparer(absent, x.c); err != ErrKey || p != nil {
		t.Fatal("typed nil authority accepted")
	}
}
