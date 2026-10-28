package systembackupconfig

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Real local AES-GCM KEK wrapping is a crypto test fixture, not runtime KMS,
// provider admission, or a reviewed deployment credential source.
type responseTestKeys struct {
	ref  ev.KeyRef
	gcm  cipher.AEAD
	fail bool
}

func newResponseTestKeys(t *testing.T, ref ev.KeyRef) *responseTestKeys {
	t.Helper()
	block, err := aes.NewCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &responseTestKeys{ref: ref, gcm: gcm}
}
func (k *responseTestKeys) Wrap(ctx context.Context, ref ev.KeyRef, plain []byte) ([]byte, error) {
	if k.fail || ref != k.ref || ctx.Err() != nil {
		return nil, errors.New("PRIVATE key provider rejected")
	}
	nonce := make([]byte, k.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(ref)
	return append(nonce, k.gcm.Seal(nil, nonce, plain, aad)...), nil
}
func (k *responseTestKeys) Unwrap(ctx context.Context, ref ev.KeyRef, sealed []byte) ([]byte, error) {
	if k.fail || ref != k.ref || ctx.Err() != nil || len(sealed) < k.gcm.NonceSize() {
		return nil, errors.New("PRIVATE key provider rejected")
	}
	aad, _ := json.Marshal(ref)
	return k.gcm.Open(nil, sealed[:k.gcm.NonceSize()], sealed[k.gcm.NonceSize():], aad)
}

type responseTestObject struct {
	data       []byte
	ref        ev.Ref
	info       ev.ObjectInfo
	badVersion bool
	ranges     int
}

func (s *responseTestObject) Range(_ context.Context, ref ev.Ref, offset, length int64) (io.ReadCloser, error) {
	s.ranges++
	if ref != s.ref || offset < 0 || length < 1 || offset+length > int64(len(s.data)) {
		return nil, errors.New("PRIVATE provider range error")
	}
	return io.NopCloser(bytes.NewReader(s.data[offset : offset+length])), nil
}
func (s *responseTestObject) Stat(_ context.Context, ref ev.Ref) (ev.ObjectInfo, error) {
	if ref != s.ref {
		return ev.ObjectInfo{}, errors.New("PRIVATE provider version error")
	}
	i := s.info
	if s.badVersion {
		i.Version = "unrelated-version"
	}
	return i, nil
}
func encryptResponseFixture(t *testing.T, c ConfigMutationResponseContent) (ev.Prepared, *responseTestObject, *responseTestKeys, ConfigMutationResponseReadScope) {
	t.Helper()
	keys := newResponseTestKeys(t, c.KEKReference())
	var dst bytes.Buffer
	p, err := c.Encrypt(context.Background(), responseContentAuthorityFixture{c}, keys, &dst)
	if err != nil {
		t.Fatal("real response framing", err)
	}
	m := p.Manifest()
	i := m.Identity
	ref := ev.Ref{Identity: c.StoreReference().IdentityHash, Version: c.StoreReference().Version, RelativeKey: "responses/" + i.Installation + "/system/" + i.OwnerID + "/" + i.ID + "/" + i.ContentHash + ".bin", ImmutableVersion: "immutable-v1"}
	store := &responseTestObject{data: append([]byte(nil), dst.Bytes()...), ref: ref, info: ev.ObjectInfo{Version: ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}
	now := time.Now().UTC()
	scope := ConfigMutationResponseReadScope{Installation: i.Installation, Actor: sec.RegistrationActor{UserID: 42, Subject: "user:42", Session: strings.Repeat("b", 64), SessionIssuedAt: now.Add(-time.Minute), SessionExpiresAt: now.Add(time.Hour)}, Now: now, ValidUntil: now.Add(time.Minute), Root: "responses", Store: ev.KeyRef{Identity: ref.Identity, Version: ref.Version}, KEK: c.KEKReference()}
	return p, store, keys, scope
}

func TestConfigMutationResponseEncryptsAndReadsEntireCanonicalResource(t *testing.T) {
	c := responseContent(t, true)
	p, store, keys, scope := encryptResponseFixture(t, c)
	if bytes.Contains(store.data, c.Bytes()) || p.Manifest().Identity.Type != "diagnostic" || p.Manifest().Identity.ContentSize <= 8192 {
		t.Fatal("body was truncated/padded or stored as plaintext/another evidence family")
	}
	if p.Manifest().Key != c.KEKReference() {
		t.Fatal("proposed KEK was used instead of current exact key")
	}
	raw, err := ReadPublishedConfigMutationResponse(context.Background(), scope, p.Manifest(), store.ref, store, keys)
	if err != nil || !bytes.Equal(raw, c.Bytes()) {
		t.Fatal("full resource round trip", err)
	}
	raw[0] = '!'
	again, err := ReadPublishedConfigMutationResponse(context.Background(), scope, p.Manifest(), store.ref, store, keys)
	if err != nil || !bytes.Equal(again, c.Bytes()) {
		t.Fatal("returned plaintext aliases immutable source", err)
	}
	if _, err = json.Marshal(c); err == nil {
		t.Fatal("internal content serialized")
	}
}

func TestConfigMutationResponseRejectsCorruptOrUnscopedReads(t *testing.T) {
	for _, name := range []string{"ciphertext", "version", "root", "store-identity", "kek-version", "actor", "expired", "key-provider"} {
		t.Run(name, func(t *testing.T) {
			c := responseContent(t, true)
			p, store, keys, scope := encryptResponseFixture(t, c)
			switch name {
			case "ciphertext":
				store.data[len(store.data)-1] ^= 1
			case "version":
				store.badVersion = true
			case "root":
				scope.Root = "other-root"
			case "store-identity":
				scope.Store.Identity = strings.Repeat("f", 64)
			case "kek-version":
				scope.KEK.Version = "unrelated-key"
			case "actor":
				scope.Actor.UserID = 7
				scope.Actor.Subject = "user:7"
			case "expired":
				scope.ValidUntil = scope.Now
			case "key-provider":
				keys.fail = true
			}
			if raw, err := ReadPublishedConfigMutationResponse(context.Background(), scope, p.Manifest(), store.ref, store, keys); err != sec.ErrRegistrationUnavailable || raw != nil {
				t.Fatal("invalid object returned plaintext or diagnostics", err)
			}
		})
	}
}
