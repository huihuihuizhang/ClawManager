package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql/driver"
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

type transitSeedKeys struct{ testKeys }

func (k transitSeedKeys) Wrap(ctx context.Context, key KeyRef, dek []byte) ([]byte, error) {
	raw, err := k.testKeys.Wrap(ctx, key, dek)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	return []byte("vault:v1:" + base64.StdEncoding.EncodeToString(raw)), nil
}

type downloadTransitFixture struct {
	f                           *downloadFixture
	d                           *DownloadTransit
	c                           DownloadTransitConfig
	logins, decrypts, redirects atomic.Int32
	mode                        string
}

func newDownloadTransitFixture(t *testing.T, mode string) *downloadTransitFixture {
	t.Helper()
	f := newDownloadFixture(t, "security_admin")
	x := &downloadTransitFixture{f: f, mode: mode}
	var object bytes.Buffer
	p, err := Prepare(context.Background(), f.record.Manifest.Identity, f.record.Manifest.Key, source(f.plain), testRedactor{}, transitSeedKeys{f.keys}, &object)
	if err != nil {
		t.Fatal(err)
	}
	f.record.Manifest = p.Manifest()
	f.object = object.Bytes()
	var env envelope
	if json.Unmarshal(f.object[12:p.manifest.HeaderSize], &env) != nil {
		t.Fatal("invalid seed")
	}
	f.wrapped, err = base64.StdEncoding.DecodeString(env.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	m, ch := p.manifest, p.manifest.Chunks[0]
	f.db.plan[7].values[12] = m.ObjectHash
	f.db.plan[7].values[13] = m.ObjectSize
	f.db.plan[7].values[16] = m.ChunkRoot
	f.db.plan[7].values[21] = m.EnvelopeHash
	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
	tag, _ := base64.RawURLEncoding.DecodeString(ch.Tag)
	f.db.plan[8].values = []driver.Value{ch.Index, ch.PlainOffset, ch.PlainLength, ch.PlainHash, ch.FrameOffset, ch.FrameLength, ch.CipherHash, nonce, tag}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { x.redirects.Add(1); w.WriteHeader(500) }))
	t.Cleanup(other.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("unexpected method")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/evidence-jwt/login":
			x.logins.Add(1)
			if r.Header.Get("X-Vault-Token") != "" {
				t.Error("static credential sent at login")
			}
			var login map[string]string
			want, _ := os.ReadFile(x.c.TokenFile)
			if json.NewDecoder(r.Body).Decode(&login) != nil || len(login) != 2 || login["role"] != x.c.Role || login["jwt"] != string(want) {
				t.Error("unbound JWT login")
				w.WriteHeader(400)
				return
			}
			switch mode {
			case "redirect":
				http.Redirect(w, r, other.URL, 307)
				return
			case "denied":
				http.Error(w, "PRIVATE_PROVIDER_ERROR", 403)
				return
			case "oversize":
				io.WriteString(w, strings.Repeat("x", 65537))
				return
			case "compressed":
				w.Header().Set("Content-Encoding", "gzip")
				io.WriteString(w, "PRIVATE")
				return
			case "duplicate":
				io.WriteString(w, `{"auth":{},"auth":{}}`)
				return
			}
			auth := map[string]any{"client_token": "transit-batch-token-0123456789", "token_type": "batch", "renewable": false, "lease_duration": 5, "policies": []string{x.c.Policy}, "metadata": map[string]any{"role": x.c.Role}, "token_policies": []string{x.c.Policy}, "identity_policies": []string{}}
			root := map[string]any{"auth": auth}
			switch mode {
			case "long ttl":
				auth["lease_duration"] = 21
			case "zero ttl":
				auth["lease_duration"] = 0
			case "service":
				auth["token_type"] = "service"
			case "renewable":
				auth["renewable"] = true
			case "missing renewable":
				delete(auth, "renewable")
			case "null renewable":
				auth["renewable"] = nil
			case "extra policy":
				auth["policies"] = []string{x.c.Policy, "default"}
			case "wrong policy":
				auth["policies"] = []string{"root"}
			case "identity policy":
				auth["identity_policies"] = []string{"extra"}
			case "token policy":
				auth["token_policies"] = []string{"extra"}
			case "role":
				auth["metadata"] = map[string]any{"role": "other"}
			case "token":
				auth["client_token"] = "bad\ntoken"
			case "wrapped":
				root["wrap_info"] = map[string]any{"token": "PRIVATE"}
			case "errors":
				root["errors"] = []string{"PRIVATE"}
			}
			json.NewEncoder(w).Encode(root)
			if mode == "trailing" {
				io.WriteString(w, `{}`)
			}
		case "/v1/transit/decrypt/evidence-key":
			x.decrypts.Add(1)
			var body struct{ Ciphertext, Context string }
			wantContext, _ := EvidenceTransitContext(f.c.Registry.Installation, f.record.Manifest.Key)
			if r.Header.Get("X-Vault-Token") != "transit-batch-token-0123456789" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Context != wantContext || body.Ciphertext != string(f.wrapped) {
				t.Error("unbound decrypt")
				w.WriteHeader(400)
				return
			}
			raw, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(body.Ciphertext, "vault:v1:"))
			if e != nil {
				t.Error(e)
				w.WriteHeader(400)
				return
			}
			dek, e := f.keys.Unwrap(r.Context(), f.record.Manifest.Key, raw)
			if e != nil {
				t.Error(e)
				w.WriteHeader(400)
				return
			}
			defer wipe(dek)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": dek}})
		default:
			t.Error("unexpected provider path")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	x.c = DownloadTransitConfig{Transit: TransitConfig{Endpoint: srv.URL, Installation: f.c.Registry.Installation, Key: f.record.Manifest.Key, KeyName: "evidence-key", KeyVersion: 1, CAPEM: ca, CASHA256: hash(ca)}, Mount: "evidence-jwt", Role: "evidence-reader", Policy: "evidence-decrypt-v1", Issuer: f.c.Issuer, Audience: "evidence-transit", Subject: f.c.Subject, TokenFile: filepath.Join(t.TempDir(), "transit-jwt")}
	x.writeJWT(t, "signature")
	x.d, err = NewDownloadTransit(f.a, []DownloadTransitConfig{x.c})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.d.Close)
	return x
}
func (x *downloadTransitFixture) writeJWT(t *testing.T, signature string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"iss": x.c.Issuer, "aud": x.c.Audience, "sub": x.c.Subject, "exp": time.Now().Add(time.Minute).Unix()})
	if err := os.WriteFile(x.c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString(body)+"."+signature), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadTransitReadsWithFreshJWTAndRealEnvelope(t *testing.T) {
	x := newDownloadTransitFixture(t, "ok")
	f := x.f
	store := &testStore{data: f.object, present: true, info: ObjectInfo{Version: f.record.Ref.ImmutableVersion}}
	for i := 0; i < 2; i++ {
		if i == 1 {
			x.writeJWT(t, "rotated")
		}
		got, err := OpenRange(f.ctx, f.record.Manifest, f.record.Ref, store, x.d, 0, 99)
		if err != nil || !bytes.Equal(got, f.plain[:100]) {
			t.Fatal("read pipeline failed", err)
		}
		wipe(got)
	}
	if x.logins.Load() != 2 || x.decrypts.Load() != 2 || f.db.commits != 8 {
		t.Fatal("cached credential or missing SQL reauthorization")
	}
	if got, err := x.d.Wrap(f.ctx, f.record.Manifest.Key, bytes.Repeat([]byte{1}, 32)); err != ErrKey || got != nil || x.logins.Load() != 2 {
		t.Fatal("download granted wrap")
	}
}

func TestDownloadTransitRejectsLoginResponses(t *testing.T) {
	for _, mode := range []string{"redirect", "denied", "oversize", "compressed", "duplicate", "trailing", "long ttl", "zero ttl", "service", "renewable", "missing renewable", "null renewable", "extra policy", "wrong policy", "identity policy", "token policy", "role", "token", "wrapped", "errors"} {
		t.Run(mode, func(t *testing.T) {
			x := newDownloadTransitFixture(t, mode)
			got, err := x.d.Unwrap(x.f.ctx, x.f.record.Manifest.Key, x.f.wrapped)
			if err != ErrKey || got != nil || x.logins.Load() != 1 || x.decrypts.Load() != 0 || x.redirects.Load() != 0 {
				t.Fatal("invalid login reached decrypt", err)
			}
		})
	}
}

func TestDownloadTransitRechecksAuthorityAndDeadline(t *testing.T) {
	for _, mode := range []string{"before login", "after login", "after decrypt", "claim takeover", "TTL exceeds claim", "database clock ahead", "wrong envelope", "wrong key", "wrong JWT audience", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			x := newDownloadTransitFixture(t, "ok")
			f := x.f
			ctx, key, wrapped := f.ctx, f.record.Manifest.Key, f.wrapped
			switch mode {
			case "before login":
				f.db.plan[5].values[4] = true
			case "after login":
				f.db.onBegin = func(n int) {
					if n == 3 {
						f.db.plan[5].values[4] = true
					}
				}
			case "after decrypt":
				f.db.onBegin = func(n int) {
					if n == 4 {
						f.db.plan[5].values[4] = true
					}
				}
			case "claim takeover":
				f.db.onBegin = func(n int) {
					if n == 3 {
						f.db.plan[7].values[23] = "other"
					}
				}
			case "TTL exceeds claim":
				f.db.plan[7].values[24] = time.Now().Add(4 * time.Second)
			case "database clock ahead":
				// SQL sees only two seconds left, while the local clock sees six.
				// A five-second provider token must not reach Transit decrypt.
				f.db.plan[9].values[0] = time.Now().Add(4 * time.Second)
				f.db.plan[7].values[24] = time.Now().Add(6 * time.Second)
			case "wrong envelope":
				wrapped = append([]byte(nil), wrapped...)
				wrapped[len(wrapped)-2] ^= 1
			case "wrong key":
				key.Version = "other"
			case "wrong JWT audience":
				x.c.Audience = "other"
				x.writeJWT(t, "signature")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := x.d.Unwrap(ctx, key, wrapped)
			wantDecrypt := int32(0)
			if mode == "after decrypt" {
				wantDecrypt = 1
			}
			if err != ErrKey || got != nil || x.decrypts.Load() != wantDecrypt {
				t.Fatal("revocation/expiry released DEK", err)
			}
		})
	}
}

func TestDownloadTransitRejectsUnreviewedMappings(t *testing.T) {
	x := newDownloadTransitFixture(t, "ok")
	for _, mode := range []string{"empty", "duplicate key", "duplicate role", "duplicate policy", "installation", "mount path", "root policy", "S3 audience", "S3 token", "subject", "CA", "HTTP", "version"} {
		t.Run(mode, func(t *testing.T) {
			c := x.c
			configs := []DownloadTransitConfig{c}
			switch mode {
			case "empty":
				configs = nil
			case "duplicate key":
				configs = append(configs, c)
			case "duplicate role":
				c.Transit.Key.Version = "v2"
				c.Policy = "policy2"
				configs = append(configs, c)
			case "duplicate policy":
				c.Transit.Key.Version = "v2"
				c.Role = "role2"
				configs = append(configs, c)
			case "installation":
				configs[0].Transit.Installation = "installation_other"
			case "mount path":
				configs[0].Mount = "../token"
			case "root policy":
				configs[0].Policy = "root"
			case "S3 audience":
				configs[0].Audience = x.f.c.Audience
			case "S3 token":
				configs[0].TokenFile = x.f.c.TokenFile
			case "subject":
				configs[0].Subject = "other"
			case "CA":
				configs[0].Transit.CASHA256 = strings.Repeat("0", 64)
			case "HTTP":
				configs[0].Transit.Endpoint = "http://localhost"
			case "version":
				configs[0].Transit.KeyVersion = 0
			}
			keys, err := NewDownloadTransit(x.f.a, configs)
			if keys != nil {
				keys.Close()
			}
			if err != ErrKey || keys != nil || x.logins.Load() != 0 {
				t.Fatal("unreviewed mapping accepted", err)
			}
		})
	}
}
