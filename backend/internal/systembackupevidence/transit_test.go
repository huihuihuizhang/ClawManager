package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type transitCredentialFunc func(context.Context, KeyRef, TransitOperation) (TransitCredential, error)

func (f transitCredentialFunc) Resolve(ctx context.Context, key KeyRef, op TransitOperation) (TransitCredential, error) {
	return f(ctx, key, op)
}

func transitFixture(t *testing.T, mode string) (*TransitKeys, *atomic.Int32, *atomic.Int32, *[]byte) {
	t.Helper()
	var calls, redirected atomic.Int32
	var lastSecret []byte
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(500) }))
	t.Cleanup(other.Close)
	key := KeyRef{strings.Repeat("b", 64), "kek-ref-v1"}
	wantContext, _ := EvidenceTransitContext("installation_test", key)
	block, _ := aes.NewCipher(bytes.Repeat([]byte{9}, 32))
	gcm, _ := cipher.NewGCM(block)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if mode == "redirect" {
			http.Redirect(w, r, other.URL, 307)
			return
		}
		if mode == "provider-denied" {
			http.Error(w, "PRIVATE token and provider error", 403)
			return
		}
		if mode == "oversize" {
			io.WriteString(w, strings.Repeat("x", 65537))
			return
		}
		if mode == "grant-expires-during-read" {
			// HTTP/1 may not observe peer cancellation until an unread body is
			// consumed. Bound the synthetic delay so server cleanup cannot hang.
			io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-time.After(300 * time.Millisecond):
			}
			return
		}
		if mode == "encoded-response" {
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, "not gzip")
			return
		}
		var body struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
			Context    string `json:"context"`
			Version    uint32 `json:"key_version"`
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Context != wantContext {
			t.Error("incorrect method, context or version wire type")
			w.WriteHeader(400)
			return
		}
		defer wipe(body.Plaintext)
		var value map[string]any
		switch r.URL.Path {
		case "/v1/transit/encrypt/evidence-key":
			if body.Version != 1 || len(body.Plaintext) != 32 || body.Ciphertext != "" || r.Header.Get("X-Vault-Token") != "wrap-token-0123456789" {
				t.Error("unbound encryption request")
				w.WriteHeader(400)
				return
			}
			nonce := make([]byte, 12)
			rand.Read(nonce)
			sealed := append(nonce, gcm.Seal(nil, nonce, body.Plaintext, []byte(body.Context))...)
			prefix := "vault:v1:"
			if mode == "wrong-version" {
				prefix = "vault:v2:"
			}
			wrapped := prefix + base64.StdEncoding.EncodeToString(sealed)
			value = map[string]any{"ciphertext": wrapped, "key_version": 1}
			if mode == "duplicate-data" {
				io.WriteString(w, `{"data":{},"data":{"ciphertext":"`+wrapped+`"}}`)
				return
			}
			if mode == "duplicate-field" {
				io.WriteString(w, `{"data":{"ciphertext":"`+wrapped+`","ciphertext":"`+wrapped+`"}}`)
				return
			}
			if mode == "mismatched-version-field" {
				value["key_version"] = 2
			}
		case "/v1/transit/decrypt/evidence-key":
			if body.Version != 0 || body.Plaintext != nil || r.Header.Get("X-Vault-Token") != "unwrap-token-0123456789" || !strings.HasPrefix(body.Ciphertext, "vault:v1:") {
				t.Error("unbound decryption request")
				w.WriteHeader(400)
				return
			}
			frame, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(body.Ciphertext, "vault:v1:"))
			if e != nil || len(frame) != 60 {
				w.WriteHeader(400)
				return
			}
			plain, e := gcm.Open(nil, frame[:12], frame[12:], []byte(body.Context))
			if e != nil {
				w.WriteHeader(400)
				return
			}
			defer wipe(plain)
			if mode == "short-dek" {
				plain = plain[:31]
			}
			value = map[string]any{"plaintext": plain}
		default:
			t.Error("unexpected Transit endpoint")
			w.WriteHeader(400)
			return
		}
		wire := map[string]any{"request_id": "synthetic-provider", "data": value, "wrap_info": nil}
		if mode == "errors-with-200" {
			wire["errors"] = []string{"PRIVATE"}
		}
		if mode == "response-wrapping" {
			wire["wrap_info"] = map[string]string{"token": "PRIVATE"}
		}
		json.NewEncoder(w).Encode(wire)
		if mode == "trailing-json" {
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	credentials := transitCredentialFunc(func(_ context.Context, requested KeyRef, op TransitOperation) (TransitCredential, error) {
		secret := "wrap-token-0123456789"
		if op == TransitUnwrap {
			secret = "unwrap-token-0123456789"
		}
		grant := TransitCredential{Key: requested, Installation: "installation_test", Operation: op, Secret: []byte(secret), ExpiresAt: time.Now().Add(time.Minute)}
		lastSecret = grant.Secret
		switch mode {
		case "expired-grant":
			grant.ExpiresAt = time.Now().Add(-time.Second)
		case "wrong-installation":
			grant.Installation = "installation_other"
		case "wrong-key":
			grant.Key.Version = "wrong-ref"
		case "wrong-operation":
			grant.Operation = "capture_dek_unwrap"
		case "resolver-error":
			return grant, errors.New("PRIVATE provider token")
		case "invalid-token":
			grant.Secret[0] = '\n'
		case "grant-expires-during-read":
			grant.ExpiresAt = time.Now().Add(100 * time.Millisecond)
		}
		return grant, nil
	})
	k, e := NewTransitKeys(TransitConfig{Endpoint: server.URL, Installation: "installation_test", KeyName: "evidence-key", Key: key, KeyVersion: 1, CAPEM: ca, CASHA256: hash(ca)}, credentials)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(k.Close)
	return k, &calls, &redirected, &lastSecret
}

func TestTransitEvidenceEnvelopeRoundTrip(t *testing.T) {
	k, calls, _, secret := transitFixture(t, "valid")
	p, plain, _, _ := fixture(t, int(ChunkSize)+11)
	var dst bytes.Buffer
	prepared, e := Prepare(context.Background(), p.manifest.Identity, k.key, source(plain), testRedactor{}, k, &dst)
	if e != nil {
		t.Fatal(e)
	}
	ref := Ref{Identity: strings.Repeat("a", 64), Version: "v1", RelativeKey: "evidence/test", ImmutableVersion: "immutable-v1"}
	store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: hash(dst.Bytes()), Size: int64(dst.Len())}}
	got, e := OpenRange(context.Background(), prepared.Manifest(), ref, store, k, ChunkSize-2, ChunkSize+2)
	if e != nil || !bytes.Equal(got, plain[ChunkSize-2:ChunkSize+3]) || calls.Load() != 2 {
		t.Fatal("Transit envelope roundtrip", e)
	}
	wipe(got)
	if !bytes.Equal(*secret, make([]byte, len(*secret))) {
		t.Fatal("owned token copy retained")
	}
}

func TestTransitEvidenceFailuresAreClosed(t *testing.T) {
	for _, mode := range []string{"wrong-version", "mismatched-version-field", "provider-denied", "redirect", "oversize", "encoded-response", "duplicate-data", "duplicate-field", "trailing-json", "errors-with-200", "response-wrapping", "expired-grant", "wrong-installation", "wrong-key", "wrong-operation", "invalid-token", "resolver-error", "grant-expires-during-read"} {
		t.Run(mode, func(t *testing.T) {
			k, calls, redirected, secret := transitFixture(t, mode)
			wrapped, e := k.Wrap(context.Background(), k.key, bytes.Repeat([]byte{7}, 32))
			if e != ErrKey || wrapped != nil {
				t.Fatal("unsafe provider response accepted", e)
			}
			if redirected.Load() != 0 {
				t.Fatal("followed token redirect")
			}
			if oneOf(mode, "expired-grant", "wrong-installation", "wrong-key", "wrong-operation", "invalid-token", "resolver-error") && calls.Load() != 0 {
				t.Fatal("invalid grant reached provider")
			}
			if !bytes.Equal(*secret, make([]byte, len(*secret))) {
				t.Fatal("owned credential retained")
			}
		})
	}
}

func TestTransitEvidenceRejectsWrongUnwrapAndRefs(t *testing.T) {
	k, calls, _, _ := transitFixture(t, "short-dek")
	dek := bytes.Repeat([]byte{5}, 32)
	wrapped, e := k.Wrap(context.Background(), k.key, dek)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := k.Unwrap(context.Background(), k.key, wrapped); e != ErrKey || got != nil {
		t.Fatal("short DEK accepted")
	}
	before := calls.Load()
	for _, bad := range [][]byte{[]byte("vault:v0:" + strings.Repeat("A", 80)), []byte("vault:v2:" + strings.Repeat("A", 80)), []byte("vault:v1:AAAA"), []byte("vault:v1:" + strings.Repeat("!", 80))} {
		if _, e := k.Unwrap(context.Background(), k.key, bad); e != ErrKey {
			t.Fatal("bad ciphertext version/frame accepted")
		}
	}
	wrong := k.key
	wrong.Identity = strings.Repeat("c", 64)
	if _, e := k.Wrap(context.Background(), wrong, dek); e != ErrKey {
		t.Fatal("wrong ref accepted")
	}
	if _, e := k.Unwrap(context.Background(), wrong, wrapped); e != ErrKey {
		t.Fatal("wrong unwrap ref accepted")
	}
	if _, e := k.Wrap(context.Background(), k.key, dek[:31]); e != ErrKey {
		t.Fatal("short wrapping input accepted")
	}
	if calls.Load() != before {
		t.Fatal("invalid input contacted provider")
	}
}

func TestTransitEvidenceTLSPinningAndConfiguration(t *testing.T) {
	k, calls, _, _ := transitFixture(t, "valid")
	k.client.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong-host.invalid"
	if _, e := k.Wrap(context.Background(), k.key, make([]byte, 32)); e != ErrKey || calls.Load() != 0 {
		t.Fatal("hostname mismatch accepted")
	}
	// Replace trust only inside this test; the production constructor has no
	// insecure/custom-client option and creates its own root pool.
	k.Close()
	k.client.Transport.(*http.Transport).TLSClientConfig.ServerName = ""
	k.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = nil
	if _, e := k.Wrap(context.Background(), k.key, make([]byte, 32)); e != ErrKey || calls.Load() != 0 {
		t.Fatal("untrusted CA accepted")
	}
	trustServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer trustServer.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustServer.Certificate().Raw})
	baseline := TransitConfig{Endpoint: trustServer.URL, Installation: "installation_test", Key: k.key, KeyVersion: 1, KeyName: "evidence-key", CAPEM: ca, CASHA256: hash(ca)}
	valid, e := NewTransitKeys(baseline, k.credentials)
	if e != nil {
		t.Fatal("valid constructor rejected", e)
	}
	valid.Close()
	for _, endpoint := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/", "https://example.com?", "https://example.com#", "https://example.com/v1/transit"} {
		bad := baseline
		bad.Endpoint = endpoint
		if _, e := NewTransitKeys(bad, k.credentials); e != ErrKey {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, mutate := range []func(*TransitConfig){
		func(c *TransitConfig) { c.KeyVersion = 0 },
		func(c *TransitConfig) { c.KeyName = "../capture-key" },
		func(c *TransitConfig) { c.CASHA256 = strings.Repeat("0", 64) },
		func(c *TransitConfig) { c.CAPEM = []byte("not a CA"); c.CASHA256 = hash(c.CAPEM) },
		func(c *TransitConfig) { c.Installation = "" },
	} {
		bad := baseline
		mutate(&bad)
		if _, e := NewTransitKeys(bad, k.credentials); e != ErrKey {
			t.Fatal("invalid binding accepted")
		}
	}
	if _, e := NewTransitKeys(baseline, nil); e != ErrKey {
		t.Fatal("missing live credential resolver accepted")
	}
	ctx1, _ := EvidenceTransitContext("installation_test", k.key)
	ctx2, _ := EvidenceTransitContext("installation_other", k.key)
	other := k.key
	other.Version = "kek-ref-v2"
	ctx3, _ := EvidenceTransitContext("installation_test", other)
	if ctx1 == ctx2 || ctx1 == ctx3 || ctx1 == "" {
		t.Fatal("context did not bind installation and immutable ref")
	}
}
