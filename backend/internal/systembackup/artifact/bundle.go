// Package artifact implements a functional users/instances domain bundle. This
// is not the six-domain system-backup.v1 acceptance/catalog format. Publication
// is immutable, signed and source-independent; no key material is embedded.
package artifact

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"

	"clawreef/internal/systembackup/staging"
)

const Version = "users-instances-functional.v1alpha1"

var ErrArtifact = errors.New("artifact unavailable or integrity verification failed")
var name = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,95}$`)
var partName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var instancePart = regexp.MustCompile(`^instance-[1-9][0-9]*$`)

type WrappedKey struct {
	Version    string `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Part struct {
	ID      string          `json:"id"`
	Receipt staging.Receipt `json:"receipt"`
	Binding staging.Binding `json:"binding"`
	Key     WrappedKey      `json:"key"`
}
type Bundle struct {
	Version       string          `json:"version"`
	ID            string          `json:"id"`
	Purpose       string          `json:"purpose"`
	Scope         []string        `json:"scope"`
	PolicyVersion string          `json:"policy_version"`
	Users         int             `json:"users"`
	Instances     int             `json:"instances"`
	Parts         []Part          `json:"parts"`
	Contract      *DomainContract `json:"contract,omitempty"`
}
type Signed struct {
	Payload   Bundle `json:"payload"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}
type Keys interface {
	Unwrap(context.Context, staging.Binding, WrappedKey) ([]byte, error)
}

// SecretKeys is the functional-test external-secret variant. Production KMS
// implementations can implement Keys without exporting their wrapping key.
type SecretKeys map[string][]byte

func keyAAD(binding staging.Binding, version string) []byte {
	b, _ := json.Marshal(struct {
		Domain, Version string
		Binding         staging.Binding
	}{"clawmanager/domain-dek-wrap/v1", version, binding})
	return b
}
func (k SecretKeys) Wrap(ctx context.Context, b staging.Binding, version string, dek []byte) (WrappedKey, error) {
	if ctx.Err() != nil || len(k[version]) != 32 || len(dek) != 32 || !name.MatchString(version) {
		return WrappedKey{}, ErrArtifact
	}
	block, e := aes.NewCipher(k[version])
	if e != nil {
		return WrappedKey{}, ErrArtifact
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return WrappedKey{}, ErrArtifact
	}
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return WrappedKey{}, ErrArtifact
	}
	return WrappedKey{Version: version, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, dek, keyAAD(b, version))}, nil
}
func (k SecretKeys) Unwrap(ctx context.Context, b staging.Binding, w WrappedKey) ([]byte, error) {
	if ctx.Err() != nil || len(k[w.Version]) != 32 || len(w.Nonce) != 12 || len(w.Ciphertext) != 48 {
		return nil, ErrArtifact
	}
	block, e := aes.NewCipher(k[w.Version])
	if e != nil {
		return nil, ErrArtifact
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrArtifact
	}
	key, e := aead.Open(nil, w.Nonce, w.Ciphertext, keyAAD(b, w.Version))
	if e != nil {
		return nil, ErrArtifact
	}
	return key, nil
}

type Directory struct {
	Root               *os.Root
	Keys               Keys
	VerifyKeys         map[string]ed25519.PublicKey
	MaxCiphertextBytes int64
	MaxPlaintextBytes  int64
	// Authorize must consult the current control task/finalization intent on
	// publication, and artifact retention/read lease on every reader boundary.
	Authorize func(context.Context, string, string) error
}

func (d Directory) ready(ctx context.Context, id, action string) error {
	if ctx.Err() != nil || d.Root == nil || d.Keys == nil || !name.MatchString(id) || d.Authorize == nil || d.MaxCiphertextBytes <= 0 || d.MaxCiphertextBytes > 1<<40 || d.MaxPlaintextBytes <= 0 || d.MaxPlaintextBytes > 1<<40 {
		return ErrArtifact
	}
	if d.Authorize(ctx, id, action) != nil {
		return ErrArtifact
	}
	return nil
}
func validBundle(b Bundle) bool {
	extra := 0
	if b.Contract != nil {
		if !b.Contract.valid(b.Instances) {
			return false
		}
		if b.Contract.Assets {
			extra = 1
		}
	}
	if b.Version != Version || !name.MatchString(b.ID) || b.Purpose != "functional_test" || len(b.Scope) != 2 || b.Scope[0] != "users" || b.Scope[1] != "instances" || !name.MatchString(b.PolicyVersion) || b.Users < 1 || b.Instances < 0 || len(b.Parts) != b.Instances+1+extra || len(b.Parts) > 10000 {
		return false
	}
	seen := map[string]bool{}
	bindings := map[string]bool{}
	database := 0
	for _, p := range b.Parts {
		if !name.MatchString(p.ID) || !partName.MatchString(p.Receipt.Name) || seen[p.ID] || p.Receipt.Size <= 0 || len(p.Receipt.SHA256) != 64 || p.Binding.BackupID != b.ID || p.Binding.Attempt == "" || p.Binding.Path == "" || p.Binding.EnvelopeID == "" || len(p.Binding.CaptureContextHash) != 64 || !name.MatchString(p.Key.Version) || len(p.Key.Nonce) != 12 || len(p.Key.Ciphertext) != 48 {
			return false
		}
		if _, e := hex.DecodeString(p.Receipt.SHA256); e != nil {
			return false
		}
		if _, e := hex.DecodeString(p.Binding.CaptureContextHash); e != nil {
			return false
		}
		key, _ := json.Marshal(p.Binding)
		if bindings[string(key)] {
			return false
		}
		bindings[string(key)] = true
		if p.ID == "database" {
			database++
		} else if p.ID == "assets" && extra == 1 {
		} else if !instancePart.MatchString(p.ID) {
			return false
		}
		seen[p.ID] = true
	}
	if extra == 1 && !seen["assets"] {
		return false
	}
	if b.Contract != nil {
		for id := range b.Contract.RuntimePolicies {
			if !seen[id] {
				return false
			}
		}
	}
	return database == 1
}
func objectName(id, part string) string {
	sum := sha256.Sum256([]byte(id + "/" + part))
	return hex.EncodeToString(sum[:]) + ".part"
}
func signatureInput(b Bundle, key string) []byte {
	raw, _ := json.Marshal(struct {
		Domain, Key string
		Payload     Bundle
	}{"clawmanager/domain-bundle-signature/v1", key, b})
	return raw
}
func markerName(id string) string { return id + ".committed" }
func indexName(id string) string  { return id + ".bundle.json" }
func marker(index []byte) []byte {
	sum := sha256.Sum256(index)
	return []byte(hex.EncodeToString(sum[:]))
}

// PublishedBundle freezes the deterministic object names before external IO.
// Controllers persist this alongside the staging receipt names in their intent.
func PublishedBundle(b Bundle) (Bundle, error) {
	if !validBundle(b) {
		return Bundle{}, ErrArtifact
	}
	out := b
	out.Parts = append([]Part(nil), b.Parts...)
	for i, p := range out.Parts {
		out.Parts[i].Receipt.Name = objectName(b.ID, p.ID)
	}
	return out, nil
}

// Publish copies only sealed ciphertext, authenticates every copied part, then
// creates the signed index and commit marker. The controller must first close
// its cancellation window and persist this immutable finalization request.
// Retrying the exact bytes is safe; changed bytes never overwrite old objects.
func (d Directory) Publish(ctx context.Context, b Bundle, keyID string, signer ed25519.PrivateKey, open func(Part) (io.ReadCloser, error)) error {
	if d.ready(ctx, b.ID, "publish") != nil || !validBundle(b) || !name.MatchString(keyID) || len(signer) != ed25519.PrivateKeySize || open == nil || !bytes.Equal(signer.Public().(ed25519.PublicKey), d.VerifyKeys[keyID]) {
		return ErrArtifact
	}
	copyBundle := b
	copyBundle.Parts = append([]Part(nil), b.Parts...)
	var total int64
	for i, p := range b.Parts {
		if d.ready(ctx, b.ID, "publish") != nil {
			return ErrArtifact
		}
		if p.Receipt.Size > d.MaxCiphertextBytes-total {
			return ErrArtifact
		}
		total += p.Receipt.Size
		source, e := open(p)
		if e != nil {
			return ErrArtifact
		}
		destination := objectName(b.ID, p.ID)
		e = d.put(ctx, destination, source, p.Receipt.Size, p.Receipt.SHA256)
		source.Close()
		if e != nil {
			return e
		}
		copyBundle.Parts[i].Receipt.Name = destination
		if d.ready(ctx, b.ID, "publish") != nil || d.checkPart(ctx, copyBundle.Parts[i]) != nil {
			return ErrArtifact
		}
	}
	signed := Signed{Payload: copyBundle, KeyID: keyID, Signature: ed25519.Sign(signer, signatureInput(copyBundle, keyID))}
	index, e := json.Marshal(signed)
	if e != nil || len(index) > 4<<20 {
		return ErrArtifact
	}
	for _, object := range []struct {
		name string
		data []byte
	}{{indexName(b.ID), index}, {markerName(b.ID), marker(index)}} {
		if d.ready(ctx, b.ID, "publish") != nil {
			return ErrArtifact
		}
		sum := sha256.Sum256(object.data)
		if d.put(ctx, object.name, bytes.NewReader(object.data), int64(len(object.data)), hex.EncodeToString(sum[:])) != nil {
			return ErrArtifact
		}
	}
	return nil
}
func (d Directory) put(ctx context.Context, name string, src io.Reader, size int64, checksum string) error {
	if size < 1 || size > d.MaxCiphertextBytes {
		return ErrArtifact
	}
	// Use exclusive creation. An unresolved partial remains owned by
	// the original attempt; do not delete it or restart an ambiguous publication.
	f, e := d.Root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if errors.Is(e, os.ErrExist) {
		return d.checkObject(ctx, name, size, checksum)
	}
	if e != nil {
		return ErrArtifact
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, src}, size+1))
	if e != nil || n != size || hex.EncodeToString(h.Sum(nil)) != checksum || ctx.Err() != nil || f.Sync() != nil || f.Close() != nil || syncRoot(d.Root) != nil {
		return ErrArtifact
	}
	return nil
}
func (d Directory) checkObject(ctx context.Context, name string, size int64, checksum string) error {
	f, e := d.Root.Open(name)
	if e != nil {
		return ErrArtifact
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() != size || ctx.Err() != nil {
		return ErrArtifact
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(contextReader{ctx, f}, size+1)); e != nil || hex.EncodeToString(h.Sum(nil)) != checksum {
		return ErrArtifact
	}
	return ctx.Err()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}
func (d Directory) checkPart(ctx context.Context, p Part) error {
	if d.checkObject(ctx, p.Receipt.Name, p.Receipt.Size, p.Receipt.SHA256) != nil {
		return ErrArtifact
	}
	key, e := d.Keys.Unwrap(ctx, p.Binding, p.Key)
	if e != nil {
		return ErrArtifact
	}
	defer clear(key)
	f, e := d.Root.Open(p.Receipt.Name)
	if e != nil {
		return ErrArtifact
	}
	defer f.Close()
	return staging.Open(ctx, f, io.Discard, key, p.Binding, d.MaxPlaintextBytes)
}
func (d Directory) Read(ctx context.Context, id string) (Bundle, error) {
	if d.ready(ctx, id, "read") != nil {
		return Bundle{}, ErrArtifact
	}
	raw, e := d.readSmall(indexName(id), 4<<20)
	if e != nil {
		return Bundle{}, e
	}
	commit, e := d.readSmall(markerName(id), 64)
	if e != nil || !bytes.Equal(commit, marker(raw)) {
		return Bundle{}, ErrArtifact
	}
	var signed Signed
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&signed) != nil {
		return Bundle{}, ErrArtifact
	}
	canonical, _ := json.Marshal(signed)
	if !bytes.Equal(raw, canonical) {
		return Bundle{}, ErrArtifact
	}
	b := signed.Payload
	public := d.VerifyKeys[signed.KeyID]
	if b.ID != id || !validBundle(b) || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, signatureInput(b, signed.KeyID), signed.Signature) {
		return Bundle{}, ErrArtifact
	}
	total := int64(0)
	for _, p := range b.Parts {
		if p.Receipt.Name != objectName(id, p.ID) || p.Receipt.Size > d.MaxCiphertextBytes-total {
			return Bundle{}, ErrArtifact
		}
		total += p.Receipt.Size
		if d.ready(ctx, id, "read") != nil || d.checkPart(ctx, p) != nil {
			return Bundle{}, ErrArtifact
		}
	}
	return b, nil
}
func (d Directory) readSmall(name string, max int64) ([]byte, error) {
	f, e := d.Root.Open(name)
	if e != nil {
		return nil, ErrArtifact
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > max {
		return nil, ErrArtifact
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrArtifact
	}
	return b, nil
}
