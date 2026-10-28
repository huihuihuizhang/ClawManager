package systembackupevidence

import (
	"context"
	"errors"
	"io"
	"testing"
)

type closeFailureReadCloser struct{ io.ReadCloser }

func (r closeFailureReadCloser) Close() error {
	_ = r.ReadCloser.Close()
	return errors.New("provider delayed verification failure")
}

type closeFailureReader struct{ *testStore }

func (s closeFailureReader) Range(ctx context.Context, ref Ref, offset, length int64) (io.ReadCloser, error) {
	r, err := s.testStore.Range(ctx, ref, offset, length)
	if err != nil {
		return nil, err
	}
	return closeFailureReadCloser{r}, nil
}

type driftingVerifiedReader struct {
	*testStore
	stats int
}

func (s *driftingVerifiedReader) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	s.stats++
	info, err := s.testStore.Stat(ctx, ref)
	if s.stats > 1 {
		info.Version = "changed-version"
	}
	return info, err
}

func TestVerifyDetachedEvidenceFullObjectAndFailureBoundaries(t *testing.T) {
	// More than MaxResponse proves this verifier covers the whole object while
	// the HTTP range reader cannot return it in a single response.
	prepared, _, object, keys := fixture(t, int(MaxResponse+ChunkSize+37))
	m := prepared.Manifest()
	scope := DetachedEvidenceScope{Installation: m.Identity.Installation, Root: "evidence", Store: KeyRef{Identity: hash([]byte("store")), Version: "v1"}, KEK: m.Key}
	key, err := keyFor(scope.Root, m.Identity)
	if err != nil {
		t.Fatal(err)
	}
	ref := Ref{Identity: scope.Store.Identity, Version: scope.Store.Version, RelativeKey: key, ImmutableVersion: "immutable-v1"}
	newStore := func() *testStore {
		return &testStore{present: true, data: append([]byte(nil), object...), info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}
	}
	if err := VerifyDetachedEvidence(context.Background(), scope, m, ref, newStore(), keys); err != nil {
		t.Fatal("complete pinned object rejected", err)
	}
	closeFailure := closeFailureReader{newStore()}
	if err := VerifyDetachedEvidence(context.Background(), scope, m, ref, closeFailure, keys); err != ErrUnavailable {
		t.Fatal("detached verifier accepted provider close failure", err)
	}
	if _, err := OpenRange(context.Background(), m, ref, closeFailure, keys, 0, 20); err != ErrUnavailable {
		t.Fatal("range reader accepted provider close failure", err)
	}
	var absent *testStore
	if err := VerifyDetachedEvidence(context.Background(), scope, m, ref, absent, keys); err != ErrUnavailable {
		t.Fatal("typed nil provider accepted", err)
	}
	if _, err := OpenRange(context.Background(), m, ref, newStore(), keys, 0, m.Identity.ContentSize-1); err != ErrRange {
		t.Fatal("fixture did not exceed HTTP response bound", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*testStore, *Manifest, *Ref, *testKeys)
		want error
	}{
		{"tampered_frame", func(s *testStore, _ *Manifest, _ *Ref, _ *testKeys) { s.tamper = true }, ErrIntegrity},
		{"wrong_provider_checksum", func(s *testStore, _ *Manifest, _ *Ref, _ *testKeys) { s.info.SHA256 = hash([]byte("wrong")) }, ErrIntegrity},
		{"wrong_provider_size", func(s *testStore, _ *Manifest, _ *Ref, _ *testKeys) { s.info.Size-- }, ErrIntegrity},
		{"wrong_version", func(_ *testStore, _ *Manifest, r *Ref, _ *testKeys) { r.ImmutableVersion = "other-version" }, ErrIntegrity},
		{"missing_provider", func(s *testStore, _ *Manifest, _ *Ref, _ *testKeys) { s.present = false }, ErrUnavailable},
		{"missing_kek", func(_ *testStore, _ *Manifest, _ *Ref, k *testKeys) { k.fail = true }, ErrKey},
		{"wrong_manifest", func(_ *testStore, manifest *Manifest, _ *Ref, _ *testKeys) {
			manifest.Chunks[0].CipherHash = hash([]byte("wrong"))
		}, ErrIntegrity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, copyManifest, copyRef, copyKeys := newStore(), m, ref, keys
			copyManifest.Chunks = append([]Chunk(nil), m.Chunks...)
			tc.edit(s, &copyManifest, &copyRef, &copyKeys)
			if err := VerifyDetachedEvidence(context.Background(), scope, copyManifest, copyRef, s, copyKeys); err != tc.want {
				t.Fatal("wrong failure mapping", err, tc.want)
			}
		})
	}
	reader := &driftingVerifiedReader{testStore: newStore()}
	if err := VerifyDetachedEvidence(context.Background(), scope, m, ref, reader, keys); err != ErrIntegrity || reader.stats != 2 {
		t.Fatal("post-read provider drift accepted", err, reader.stats)
	}
	for _, tc := range []struct {
		name string
		edit func(*DetachedEvidenceScope, *Ref)
	}{
		{"installation", func(s *DetachedEvidenceScope, _ *Ref) { s.Installation = "installation_other" }},
		{"store", func(s *DetachedEvidenceScope, _ *Ref) { s.Store.Identity = hash([]byte("other-store")) }},
		{"store_version", func(s *DetachedEvidenceScope, _ *Ref) { s.Store.Version = "v2" }},
		{"kek", func(s *DetachedEvidenceScope, _ *Ref) { s.KEK.Identity = hash([]byte("other-kek")) }},
		{"object_key", func(_ *DetachedEvidenceScope, r *Ref) { r.RelativeKey = "evidence/other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			badScope, badRef := scope, ref
			tc.edit(&badScope, &badRef)
			s := newStore()
			if err := VerifyDetachedEvidence(context.Background(), badScope, m, badRef, s, keys); err != ErrIntegrity || s.reads != 0 {
				t.Fatal("unbound disaster reference reached provider", err, s.reads)
			}
		})
	}
}
