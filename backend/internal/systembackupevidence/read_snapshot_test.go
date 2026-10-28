package systembackupevidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestVerifiedReadsFreezeManifestBeforeProviderCallbacks(t *testing.T) {
	for _, mode := range []string{"detached", "range"} {
		for _, repair := range []bool{false, true} {
			name := "corrupt-caller-index"
			if repair {
				name = "repair-invalid-index"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				prepared, plaintext, object, keys := fixture(t, int(ChunkSize+17))
				m := prepared.Manifest()
				originalHash := m.Chunks[0].CipherHash
				wrongHash := hash([]byte("incorrect signed chunk hash"))
				if repair {
					m.Chunks[0].CipherHash = wrongHash
					m.ChunkRoot = hash(canonical(m.Chunks))
				}
				if validateManifest(m) != nil {
					t.Fatal("fixture must pass structural index validation")
				}
				scope := DetachedEvidenceScope{Installation: m.Identity.Installation, Root: "evidence", Store: KeyRef{Identity: hash([]byte("store")), Version: "v1"}, KEK: m.Key}
				key, err := keyFor(scope.Root, m.Identity)
				if err != nil {
					t.Fatal(err)
				}
				ref := Ref{Identity: scope.Store.Identity, Version: scope.Store.Version, RelativeKey: key, ImmutableVersion: "immutable-v1"}
				store := &testStore{present: true, data: object, info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}
				store.onRead = func() {
					if store.reads == 1 {
						// Synchronous mutation demonstrates ownership without a race.
						m.Chunks[0].CipherHash = wrongHash
						if repair {
							m.Chunks[0].CipherHash = originalHash
						}
					}
				}
				var result []byte
				if mode == "detached" {
					err = VerifyDetachedEvidence(context.Background(), scope, m, ref, store, keys)
				} else {
					result, err = OpenRange(context.Background(), m, ref, store, keys, 0, m.Identity.ContentSize-1)
				}
				if repair {
					if err != ErrIntegrity || result != nil {
						t.Fatal("provider repaired an invalid authenticated index", err)
					}
				} else if err != nil || mode == "range" && !bytes.Equal(result, plaintext) {
					t.Fatal("provider changed the frozen valid index", err)
				}
			})
		}
	}
}

type cancelFinalStatReader struct {
	*testStore
	cancel context.CancelFunc
	stats  int
}

func (s *cancelFinalStatReader) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	s.stats++
	if s.stats == 2 {
		s.cancel()
	}
	return s.testStore.Stat(ctx, ref)
}

func TestVerifyDetachedEvidenceRejectsCancellationDuringFinalStat(t *testing.T) {
	prepared, _, object, keys := fixture(t, 9000)
	m := prepared.Manifest()
	scope := DetachedEvidenceScope{Installation: m.Identity.Installation, Root: "evidence", Store: KeyRef{Identity: hash([]byte("store")), Version: "v1"}, KEK: m.Key}
	key, err := keyFor(scope.Root, m.Identity)
	if err != nil {
		t.Fatal(err)
	}
	ref := Ref{Identity: scope.Store.Identity, Version: scope.Store.Version, RelativeKey: key, ImmutableVersion: "immutable-v1"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &cancelFinalStatReader{testStore: &testStore{present: true, data: object, info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}, cancel: cancel}
	if err := VerifyDetachedEvidence(ctx, scope, m, ref, store, keys); err != ErrUnavailable || store.stats != 2 {
		t.Fatal("canceled final observation reported successful verification", err, store.stats)
	}
}

type cancelUnwrapKeys struct {
	testKeys
	cancel context.CancelFunc
	dek    []byte
}

func (k *cancelUnwrapKeys) Unwrap(ctx context.Context, ref KeyRef, wrapped []byte) ([]byte, error) {
	var err error
	k.dek, err = k.testKeys.Unwrap(ctx, ref, wrapped)
	k.cancel()
	return k.dek, err
}

func TestVerifiedReadsRejectCanceledUnwrapAndEraseDEK(t *testing.T) {
	for _, mode := range []string{"detached", "range"} {
		t.Run(mode, func(t *testing.T) {
			prepared, _, object, keys := fixture(t, 9000)
			m := prepared.Manifest()
			scope := DetachedEvidenceScope{Installation: m.Identity.Installation, Root: "evidence", Store: KeyRef{Identity: hash([]byte("store")), Version: "v1"}, KEK: m.Key}
			key, err := keyFor(scope.Root, m.Identity)
			if err != nil {
				t.Fatal(err)
			}
			ref := Ref{Identity: scope.Store.Identity, Version: scope.Store.Version, RelativeKey: key, ImmutableVersion: "immutable-v1"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelKeys := &cancelUnwrapKeys{testKeys: keys, cancel: cancel}
			store := &testStore{present: true, data: object, info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}
			var result []byte
			if mode == "detached" {
				err = VerifyDetachedEvidence(ctx, scope, m, ref, store, cancelKeys)
			} else {
				result, err = OpenRange(ctx, m, ref, store, cancelKeys, 0, 19)
			}
			if err != ErrUnavailable || result != nil || store.reads != 1 || len(cancelKeys.dek) != 32 {
				t.Fatal("canceled unwrap reached ciphertext frames or plaintext result", err, store.reads)
			}
			if !bytes.Equal(cancelKeys.dek, make([]byte, 32)) {
				t.Fatal("canceled unwrap retained plaintext DEK")
			}
		})
	}
}

type boundaryReadCloser struct{ closes int }

func (*boundaryReadCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (r *boundaryReadCloser) Close() error           { r.closes++; return nil }

type boundaryObjectReader struct {
	reader io.ReadCloser
	err    error
	calls  int
}

func (s *boundaryObjectReader) Range(context.Context, Ref, int64, int64) (io.ReadCloser, error) {
	s.calls++
	return s.reader, s.err
}

func TestReadExactRejectsTypedNilAndClosesErrorReader(t *testing.T) {
	var absent *boundaryReadCloser
	for _, tc := range []struct {
		name   string
		reader io.ReadCloser
		err    error
	}{
		{"typed-nil-reader", absent, nil},
		{"error-with-reader", &boundaryReadCloser{}, errors.New("provider failed after opening response")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &boundaryObjectReader{reader: tc.reader, err: tc.err}
			if result, err := readExact(context.Background(), store, Ref{}, 0, 1); err != ErrUnavailable || result != nil || store.calls != 1 {
				t.Fatal("invalid provider response accepted", err)
			}
			if reader, ok := tc.reader.(*boundaryReadCloser); ok && reader != nil && reader.closes != 1 {
				t.Fatal("provider error leaked its opened reader")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &boundaryObjectReader{}
	if _, err := readExact(ctx, store, Ref{}, 0, 1); err != ErrUnavailable || store.calls != 0 {
		t.Fatal("canceled read reached provider", err)
	}
}
