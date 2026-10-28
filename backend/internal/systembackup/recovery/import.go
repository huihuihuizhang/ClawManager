package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

type Catalog struct {
	Store Reader
	Trust Trust
	Now   func() int64
}

func readObject(ctx context.Context, store Reader, o Object) ([]byte, error) {
	if store == nil || !o.valid() || o.Size > MaxDocument {
		return nil, ErrContract
	}
	f, e := store.Open(ctx, o)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, o.Size+1))
	if e != nil {
		return nil, ErrUnavailable
	}
	if int64(len(b)) != o.Size || Hash(b) != o.SHA256 {
		return nil, ErrConflict
	}
	return b, nil
}
func (c Catalog) ReadRecord(ctx context.Context, key, expected string) (Record, Object, error) {
	if c.Store == nil || c.Now == nil || !safeKey(key) || expected != "" && !digest(expected) {
		return Record{}, Object{}, ErrContract
	}
	o, e := c.Store.Observe(ctx, key)
	if e != nil || !o.decisive(key, c.Now()) || o.State != "present" {
		return Record{}, Object{}, ErrUnavailable
	}
	b, e := readObject(ctx, c.Store, o.Object)
	if e != nil {
		return Record{}, Object{}, e
	}
	if expected != "" && Hash(b) != expected {
		return Record{}, Object{}, ErrConflict
	}
	var r Record
	if _, e = c.Trust.Open(b, CatalogPurpose, &r); e != nil {
		return r, Object{}, e
	}
	k, e := r.Key()
	if e != nil || key != k {
		return r, Object{}, ErrContract
	}
	return r, o.Object, nil
}
func (c Catalog) CheckNotDeleted(ctx context.Context, r Record, hash string) error {
	if r.Type != "artifact_registered" || r.Registration == nil || !digest(hash) || c.Store == nil || c.Now == nil {
		return ErrContract
	}
	key := "tombstones/" + r.ID + ".json"
	o, e := c.Store.Observe(ctx, key)
	if e != nil || !o.decisive(key, c.Now()) {
		return ErrUnavailable
	}
	if o.State == "absent" {
		return nil
	}
	b, e := readObject(ctx, c.Store, o.Object)
	if e != nil {
		return e
	}
	var tomb Record
	if _, e = c.Trust.Open(b, CatalogPurpose, &tomb); e != nil {
		return e
	}
	k, e := tomb.Key()
	if e != nil || k != key || tomb.Deletion == nil || tomb.Deletion.RegistrationSHA256 != hash || tomb.Deletion.Locator != r.Registration.Locator || tomb.Deletion.Core != r.Registration.Core {
		return ErrConflict
	}
	return ErrTombstoned
}

// Authenticate must authenticate EVERY encrypted frame and verify the format's
// final record (not just ciphertext checksums). It receives no target writer.
type Authenticator interface {
	Authenticate(context.Context, Manifest, Object, io.Reader) error
}
type Importer struct {
	Catalog Catalog
	Resolve func(context.Context, Locator, Bootstrap) (Reader, Authenticator, error)
}
type Imported struct {
	RecordID, SHA256 string
	Manifest         Manifest
	VerifiedAt       int64
}

func verifyCore(ctx context.Context, store Reader, auth Authenticator, trust Trust, r Registration) (Manifest, error) {
	if !r.Core.valid() || auth == nil {
		return Manifest{}, ErrContract
	}
	manifest, e := readObject(ctx, store, r.Core.Manifest)
	if e != nil {
		return Manifest{}, e
	}
	var m Manifest
	if _, e = trust.Open(manifest, ManifestPurpose, &m); e != nil {
		return m, e
	}
	idx, e := readObject(ctx, store, r.Core.Index)
	if e != nil {
		return m, e
	}
	var index Index
	if decode(idx, &index) != nil || m.Validate(index) != nil || m.Index != r.Core.Index || m.Identity != r.Identity || m.Purpose != "acceptance" {
		return m, ErrContract
	}
	marker, e := readObject(ctx, store, r.Core.Marker)
	if e != nil {
		return m, e
	}
	var commit Marker
	if decode(marker, &commit) != nil || commit.Schema != Version || commit.Identity != m.Identity || commit.ManifestSHA256 != r.Core.Manifest.SHA256 || commit.IndexSHA256 != r.Core.Index.SHA256 {
		return m, ErrConflict
	}
	a, e := readObject(ctx, store, r.Core.Acceptance)
	if e != nil {
		return m, e
	}
	var acceptance Acceptance
	h, e := trust.Open(a, AcceptancePurpose, &acceptance)
	if e != nil {
		return m, e
	}
	key, e := trust.key(h)
	if e != nil || h.KeyID != r.AcceptanceKey.ID || h.KeyVersion != r.AcceptanceKey.Version || Hash(key) != r.AcceptanceKey.SHA256 {
		return m, ErrContract
	}
	expected, e := BuildAcceptance(m, index, manifest, marker, acceptance.Cleanup, acceptance.DecisionTime)
	if e != nil {
		return m, e
	}
	left, _ := Marshal(expected)
	right, _ := Marshal(acceptance)
	if !bytes.Equal(left, right) || !acceptance.LocalAcceptance || acceptance.DecisionTime > r.DecisionTime {
		return m, ErrContract
	}
	return m, authenticateIndex(ctx, store, auth, m, index)
}
func authenticateIndex(ctx context.Context, store Reader, auth Authenticator, m Manifest, index Index) error {
	if store == nil || auth == nil {
		return ErrUnavailable
	}
	for _, o := range index.Objects {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, e := store.Open(ctx, o)
		if e != nil {
			return ErrUnavailable
		}
		hash := sha256.New()
		limit := &io.LimitedReader{R: f, N: o.Size + 1}
		input := io.TeeReader(limit, hash)
		e = auth.Authenticate(ctx, m, o, input)
		// A verifier that only consumed a prefix cannot validate the object.
		var tail [1]byte
		n, readErr := input.Read(tail[:])
		f.Close()
		if e != nil || n != 0 || readErr != io.EOF || limit.N != 1 || hex.EncodeToString(hash.Sum(nil)) != o.SHA256 {
			return ErrConflict
		}
	}
	return nil
}

// Import needs only disaster bootstrap, catalog and immutable artifact versions.
// Source DB, cluster, Secrets and promotion state are not inputs.
func (i Importer) Import(ctx context.Context, id, hash string) (Imported, error) {
	if !validID(id) || !digest(hash) || i.Resolve == nil {
		return Imported{}, ErrContract
	}
	r, o, e := i.Catalog.ReadRecord(ctx, "registrations/"+id+".json", hash)
	if e != nil {
		return Imported{}, e
	}
	if r.Registration == nil {
		return Imported{}, ErrContract
	}
	if e = i.Catalog.CheckNotDeleted(ctx, r, o.SHA256); e != nil {
		return Imported{}, e
	}
	store, auth, e := i.Resolve(ctx, r.Registration.Locator, r.Registration.Bootstrap)
	if e != nil {
		return Imported{}, ErrUnavailable
	}
	m, e := verifyCore(ctx, store, auth, i.Catalog.Trust, *r.Registration)
	if e != nil {
		return Imported{}, e
	}
	if e = i.Catalog.CheckNotDeleted(ctx, r, o.SHA256); e != nil {
		return Imported{}, e
	}
	return Imported{r.ID, o.SHA256, m, i.Catalog.Now()}, nil
}
