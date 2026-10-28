package systembackupconfig

import (
	"context"
	"strconv"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// Scope comes from current authenticated SQL/receipt admission and retained,
// purpose-specific evidence read/KEK mappings, never from the response body or
// manifest. The caller must recheck the exact SQL receipt/current authority
// after this provider work and before sending any returned bytes.
type ConfigMutationResponseReadScope struct {
	Installation    string
	Actor           sec.RegistrationActor
	Now, ValidUntil time.Time
	Root            string
	Store, KEK      ev.KeyRef
}

// ReadPublishedConfigMutationResponse verifies a complete immutable diagnostic
// object, decrypts the entire body with A's framing verifier, and validates the
// exact historical ConfigResource. It does not reconstruct it from current
// config or apply a new reason redaction that would change its saved checksum.
// This grants no SQL, provider or KEK authority; the supplied adapters must be
// the currently authorized exact historical read capabilities.
func ReadPublishedConfigMutationResponse(ctx context.Context, scope ConfigMutationResponseReadScope, m ev.Manifest, ref ev.Ref, store ev.VerifiedObjectReader, keys ev.Keys) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
	i := m.Identity
	if ctx == nil || ctx.Err() != nil || isNil(store) || isNil(keys) || !sessionAt(scope.Actor, scope.Now) || !scope.Now.Before(scope.ValidUntil) || !time.Now().Before(scope.ValidUntil) || i.Installation != scope.Installation || i.OwnerType != "system" || i.OwnerID != scope.Installation || i.Type != "diagnostic" || i.Media != "application/json" || i.Classification != "internal" || i.ContentSize <= 8192 || i.ContentSize > configMutationResponseMaxBytes || !evidenceIDPattern.MatchString(i.ID) || !hashPattern.MatchString(i.ContentHash) {
		return fail()
	}
	until := scope.ValidUntil
	if scope.Actor.SessionExpiresAt.Before(until) {
		until = scope.Actor.SessionExpiresAt
	}
	if !time.Now().Before(until) {
		return fail()
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	// Own the chunk slice before provider/key callbacks can mutate a caller's
	// buffer. Detached verification also freezes and validates every frame.
	m.Chunks = append([]ev.Chunk(nil), m.Chunks...)
	detached := ev.DetachedEvidenceScope{Installation: scope.Installation, Root: scope.Root, Store: scope.Store, KEK: scope.KEK}
	if ev.VerifyDetachedEvidence(ctx, detached, m, ref, store, keys) != nil {
		return fail()
	}
	raw, err := ev.OpenRange(ctx, m, ref, store, keys, 0, i.ContentSize-1)
	if err != nil || len(raw) != int(i.ContentSize) || registrationHash(string(raw)) != i.ContentHash {
		wipe(raw)
		return fail()
	}
	if _, _, _, err = decodeConfigMutationResponseResource(scope.Installation, strconv.FormatInt(scope.Actor.UserID, 10), raw); err != nil {
		wipe(raw)
		return fail()
	}
	info, err := store.Stat(ctx, ref)
	if err != nil || info.Version != ref.ImmutableVersion || info.SHA256 != m.ObjectHash || info.Size != m.ObjectSize || ctx.Err() != nil || !time.Now().Before(until) {
		wipe(raw)
		return fail()
	}
	return raw, nil
}
