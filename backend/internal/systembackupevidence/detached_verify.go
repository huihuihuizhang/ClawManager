package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// VerifiedObjectReader exposes only the pinned read and authoritative object
// metadata needed by an offline verifier. The caller must first authenticate
// the manifest and Ref against a committed artifact; this function has no DB
// or source-installation dependency and grants no provider write capability.
type VerifiedObjectReader interface {
	ObjectReader
	Stat(context.Context, Ref) (ObjectInfo, error)
}

// DetachedEvidenceScope comes from trusted disaster bootstrap, never from an
// artifact or HTTP request. The immutable Ref is checked against this scope
// before either provider access or KEK unwrap.
type DetachedEvidenceScope struct {
	Installation string
	Root         string
	Store        KeyRef
	KEK          KeyRef
}

// VerifyDetachedEvidence checks the complete immutable object without
// returning plaintext or retaining more than one chunk. It never treats a
// missing/uncertain provider response as proof of absence or health.
func VerifyDetachedEvidence(ctx context.Context, scope DetachedEvidenceScope, m Manifest, ref Ref, source VerifiedObjectReader, keys Keys) error {
	var err error
	m, err = snapshotReadManifest(m)
	if err != nil || !ref.valid(true) {
		return ErrIntegrity
	}
	if ctx == nil || nilSystemAdapter(source) || nilSystemAdapter(keys) || ctx.Err() != nil ||
		!installationPattern.MatchString(scope.Installation) || !safeKey(scope.Root) || !scope.Store.valid() || !scope.KEK.valid() {
		return ErrUnavailable
	}
	key, err := keyFor(scope.Root, m.Identity)
	if err != nil || m.Identity.Installation != scope.Installation || m.Key != scope.KEK ||
		ref.Identity != scope.Store.Identity || ref.Version != scope.Store.Version || ref.RelativeKey != key {
		return ErrIntegrity
	}
	checkObject := func() error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		info, err := source.Stat(ctx, ref)
		if err != nil || ctx.Err() != nil {
			return ErrUnavailable
		}
		if info.Version != ref.ImmutableVersion || info.SHA256 != m.ObjectHash || info.Size != m.ObjectSize {
			return ErrIntegrity
		}
		return nil
	}
	if err := checkObject(); err != nil {
		return err
	}
	gcm, header, err := openEvidenceEnvelope(ctx, m, ref, source, keys)
	if err != nil {
		return err
	}
	objectHash, plainHash := sha256.New(), sha256.New()
	_, _ = objectHash.Write(header)
	for _, c := range m.Chunks {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		frame, err := readExact(ctx, source, ref, c.FrameOffset, c.FrameLength)
		if err != nil {
			return err
		}
		if hash(frame) != c.CipherHash || base64.RawURLEncoding.EncodeToString(frame[:12]) != c.Nonce || base64.RawURLEncoding.EncodeToString(frame[len(frame)-16:]) != c.Tag {
			wipe(frame)
			return ErrIntegrity
		}
		_, _ = objectHash.Write(frame)
		plain, err := gcm.Open(nil, frame[:12], frame[12:], aad(m, c))
		wipe(frame)
		if err != nil {
			return ErrIntegrity
		}
		if int64(len(plain)) != c.PlainLength || hash(plain) != c.PlainHash {
			wipe(plain)
			return ErrIntegrity
		}
		_, _ = plainHash.Write(plain)
		wipe(plain)
	}
	if hex.EncodeToString(objectHash.Sum(nil)) != m.ObjectHash || hex.EncodeToString(plainHash.Sum(nil)) != m.Identity.ContentHash {
		return ErrIntegrity
	}
	return checkObject()
}
