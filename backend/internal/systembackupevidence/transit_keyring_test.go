package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Each fixture has independent encryption material and a real local TLS
// endpoint. These are synthetic providers, not a live key-rotation receipt.
func keyringProvider(t *testing.T, ref KeyRef, version uint32, material byte) (TransitConfig, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	var calls atomic.Int32
	var denied atomic.Bool
	wantContext, _ := EvidenceTransitContext("installation_test", ref)
	kek := testKeys{key: bytes.Repeat([]byte{material}, 32)}
	prefix := fmt.Sprintf("vault:v%d:", version)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if denied.Load() {
			w.WriteHeader(403)
			return
		}
		var body struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
			Context    string `json:"context"`
			Version    uint32 `json:"key_version"`
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Context != wantContext {
			t.Error("incorrect Transit request binding")
			w.WriteHeader(400)
			return
		}
		defer wipe(body.Plaintext)
		var data map[string]any
		switch r.URL.Path {
		case "/v1/transit/encrypt/evidence-key":
			if body.Version != version || len(body.Plaintext) != 32 || body.Ciphertext != "" || r.Header.Get("X-Vault-Token") != string(TransitWrap) {
				t.Error("wrong wrap binding")
				w.WriteHeader(400)
				return
			}
			wrapped, err := kek.Wrap(r.Context(), ref, body.Plaintext)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			data = map[string]any{"ciphertext": prefix + base64.StdEncoding.EncodeToString(wrapped), "key_version": version}
		case "/v1/transit/decrypt/evidence-key":
			if !strings.HasPrefix(body.Ciphertext, prefix) || body.Version != 0 || body.Plaintext != nil || r.Header.Get("X-Vault-Token") != string(TransitUnwrap) {
				t.Error("wrong unwrap binding")
				w.WriteHeader(400)
				return
			}
			wrapped, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(body.Ciphertext, prefix))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			plain, err := kek.Unwrap(r.Context(), ref, wrapped)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer wipe(plain)
			data = map[string]any{"plaintext": plain}
		default:
			t.Error("unexpected key path")
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return TransitConfig{Endpoint: srv.URL, Installation: "installation_test", KeyName: "evidence-key", Key: ref, KeyVersion: version, CAPEM: ca, CASHA256: hash(ca)}, &calls, &denied
}

func keyringCredentials(revoked *atomic.Bool, calls *atomic.Int32) TransitCredentials {
	return transitCredentialFunc(func(_ context.Context, ref KeyRef, op TransitOperation) (TransitCredential, error) {
		calls.Add(1)
		if revoked.Load() {
			return TransitCredential{}, errors.New("private credential failure")
		}
		return TransitCredential{Key: ref, Installation: "installation_test", Operation: op, Secret: []byte(op), ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
}

func TestTransitKeyringRotationRetainsEvidence(t *testing.T) {
	ctx := context.Background()
	oldRef := KeyRef{strings.Repeat("b", 64), "old-ref"}
	newRef := KeyRef{strings.Repeat("c", 64), "new-ref"}
	oldConfig, oldCalls, oldDenied := keyringProvider(t, oldRef, 1, 11)
	newConfig, newCalls, _ := keyringProvider(t, newRef, 2, 22)
	var revoked atomic.Bool
	var credentialCalls atomic.Int32
	creds := keyringCredentials(&revoked, &credentialCalls)
	before, err := NewTransitKeyring("installation_test", []TransitConfig{oldConfig}, &oldRef, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	seed, plain, _, _ := fixture(t, int(ChunkSize)+29)
	var oldObject bytes.Buffer
	prepared, err := Prepare(ctx, seed.Manifest().Identity, oldRef, source(plain), testRedactor{}, before, &oldObject)
	if err != nil {
		t.Fatal(err)
	}
	configs := []TransitConfig{oldConfig, newConfig}
	active := newRef
	after, err := NewTransitKeyring("installation_test", configs, &active, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	// Mutating caller-owned configuration cannot retarget this snapshot.
	active = oldRef
	configs[0].Key = newRef
	configs[1].KeyVersion = 99
	for i := range configs[0].CAPEM {
		configs[0].CAPEM[i] = 0
	}
	ref := Ref{strings.Repeat("d", 64), "store-v1", "root/object", "object-v1"}
	store := &testStore{data: oldObject.Bytes(), present: true, info: ObjectInfo{Version: ref.ImmutableVersion}}
	start, end := ChunkSize-5, ChunkSize+8
	got, err := OpenRange(ctx, prepared.Manifest(), ref, store, after, start, end)
	if err != nil || !bytes.Equal(got, plain[start:end+1]) {
		t.Fatalf("old evidence after rotation: %v", err)
	}
	wipe(got)
	var newObject bytes.Buffer
	newPrepared, err := Prepare(ctx, seed.Manifest().Identity, newRef, source(plain), testRedactor{}, after, &newObject)
	if err != nil {
		t.Fatal(err)
	}
	store.data = newObject.Bytes()
	got, err = OpenRange(ctx, newPrepared.Manifest(), ref, store, after, start, end)
	if err != nil || !bytes.Equal(got, plain[start:end+1]) {
		t.Fatalf("new evidence: %v", err)
	}
	wipe(got)
	baseline := credentialCalls.Load()
	for _, key := range []KeyRef{oldRef, {oldRef.Identity, "unknown"}, {strings.Repeat("e", 64), newRef.Version}} {
		if _, err := after.Wrap(ctx, key, bytes.Repeat([]byte{3}, 32)); err != ErrKey {
			t.Fatal("historical/unknown wrap allowed")
		}
	}
	if credentialCalls.Load() != baseline {
		t.Fatal("rejected wrap reached credential service")
	}
	store.data = oldObject.Bytes()
	newBaseline := newCalls.Load()
	oldDenied.Store(true)
	if _, err := OpenRange(ctx, prepared.Manifest(), ref, store, after, start, end); err != ErrKey {
		t.Fatalf("old key failure: %v", err)
	}
	if newCalls.Load() != newBaseline {
		t.Fatal("fallback to current key")
	}
	oldDenied.Store(false)
	providerBaseline := oldCalls.Load()
	revoked.Store(true)
	if _, err := OpenRange(ctx, prepared.Manifest(), ref, store, after, start, end); err != ErrKey {
		t.Fatalf("revoked credential: %v", err)
	}
	if oldCalls.Load() != providerBaseline {
		t.Fatal("cached credential used after revocation")
	}
	revoked.Store(false)
	got, err = OpenRange(ctx, prepared.Manifest(), ref, store, after, start, end)
	if err != nil {
		t.Fatal(err)
	}
	wipe(got)
}

func TestTransitKeyringAdmissionAndReadOnly(t *testing.T) {
	key := KeyRef{strings.Repeat("b", 64), "old-ref"}
	c, calls, _ := keyringProvider(t, key, 1, 11)
	var revoked atomic.Bool
	var resolves atomic.Int32
	creds := keyringCredentials(&revoked, &resolves)
	unknown := KeyRef{key.Identity, "unknown"}
	bad := c
	bad.KeyVersion = 0
	bad.Key.Version = "bad-ref"
	cross := c
	cross.Installation = "installation_other"
	cases := []struct {
		name, installation string
		configs            []TransitConfig
		active             *KeyRef
		creds              TransitCredentials
	}{
		{"empty", "installation_test", nil, nil, creds},
		{"invalid-installation", "", []TransitConfig{c}, &key, creds},
		{"missing-writer", "installation_test", []TransitConfig{c}, &unknown, creds},
		{"invalid-writer", "installation_test", []TransitConfig{c}, &KeyRef{}, creds},
		{"duplicate", "installation_test", []TransitConfig{c, c}, &key, creds},
		{"cross-installation", "installation_test", []TransitConfig{cross}, nil, creds},
		{"invalid-provider", "installation_test", []TransitConfig{c, bad}, nil, creds},
		{"no-credentials", "installation_test", []TransitConfig{c}, &key, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := NewTransitKeyring(tc.installation, tc.configs, tc.active, tc.creds); err != ErrKey || r != nil {
				t.Fatal("invalid mapping admitted")
			}
		})
	}
	if calls.Load() != 0 || resolves.Load() != 0 {
		t.Fatal("constructor performed provider work")
	}
	writer, err := NewTransitKeyring("installation_test", []TransitConfig{c}, &key, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := NewTransitKeyring("installation_test", []TransitConfig{c}, nil, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, err := writer.Wrap(context.Background(), key, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Unwrap(context.Background(), key, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatal("read-only unwrap failed", err)
	}
	wipe(got)
	baseline := resolves.Load()
	var zero TransitKeyring
	var nilRing *TransitKeyring
	for _, ring := range []*TransitKeyring{reader, &zero, nilRing} {
		if _, err := ring.Wrap(context.Background(), key, dek); err != ErrKey {
			t.Fatal("disabled wrap allowed")
		}
		if _, err := ring.Unwrap(context.Background(), unknown, wrapped); err != ErrKey {
			t.Fatal("unknown ref allowed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writer.Wrap(ctx, key, dek); err != ErrKey {
		t.Fatal("canceled wrap allowed")
	}
	if _, err := reader.Unwrap(ctx, key, wrapped); err != ErrKey {
		t.Fatal("canceled unwrap allowed")
	}
	if resolves.Load() != baseline {
		t.Fatal("rejected operation reached resolver")
	}
	nilRing.Close()
}
