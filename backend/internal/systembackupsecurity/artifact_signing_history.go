package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var errArtifactSigningHistory = errors.New("invalid artifact signing key history")

// ArtifactSigningPublicKey is a trust-registry observation, not an artifact
// field. Revoked keys remain in the snapshot so historical verification can
// reject their artifacts explicitly.
type ArtifactSigningPublicKey struct {
	InstallationID             string
	Purpose, KeyID, KeyVersion string
	PublicKey                  ed25519.PublicKey
	NotBefore, NotAfter        time.Time
	Revoked                    bool
}

// ArtifactSigningKeyHistory freezes all three artifact purposes together.
// The provider adapter must authenticate this input and keep referenced old
// versions; this value only enforces the local separation and copy boundary.
type ArtifactSigningKeyHistory struct {
	installationID string
	keys           map[string]ArtifactSigningPublicKey
}

// ArtifactSigningReference must come from a complete, authenticated artifact
// and catalog reference scan. A nil slice means the scan is unavailable;
// an empty non-nil slice means it completed and found no references.
type ArtifactSigningReference struct {
	Purpose, KeyID, KeyVersion string
}

type ArtifactSigningRetentionResult struct {
	DegradedReferences []ArtifactSigningReference
}

func artifactSigningIdentity(purpose, keyID, version string) string {
	raw, _ := json.Marshal([]string{purpose, keyID, version})
	return string(raw)
}

func artifactSigningPurpose(purpose string) bool {
	return purpose == "capture_certificate" || purpose == "acceptance_record" || purpose == "catalog_record"
}

func NewArtifactSigningKeyHistory(installationID string, keys []ArtifactSigningPublicKey) (*ArtifactSigningKeyHistory, error) {
	if !providerBoundedString(installationID) || len(keys) < 3 || len(keys) > 1024 {
		return nil, errArtifactSigningHistory
	}
	history := &ArtifactSigningKeyHistory{installationID: installationID, keys: make(map[string]ArtifactSigningPublicKey, len(keys))}
	purposes := make(map[string]bool, 3)
	material := make(map[[ed25519.PublicKeySize]byte]bool, len(keys))
	for _, key := range keys {
		if key.InstallationID != installationID || !artifactSigningPurpose(key.Purpose) || !providerBoundedString(key.KeyID) ||
			!providerBoundedString(key.KeyVersion) || len(key.KeyID) > 256 || len(key.KeyVersion) > 128 ||
			len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || !key.NotAfter.After(key.NotBefore) {
			return nil, errArtifactSigningHistory
		}
		identity := artifactSigningIdentity(key.Purpose, key.KeyID, key.KeyVersion)
		if _, exists := history.keys[identity]; exists {
			return nil, errArtifactSigningHistory
		}
		var bytes [ed25519.PublicKeySize]byte
		copy(bytes[:], key.PublicKey)
		if material[bytes] {
			return nil, errArtifactSigningHistory
		}
		material[bytes] = true
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		history.keys[identity] = key
		purposes[key.Purpose] = true
	}
	if len(purposes) != 3 {
		return nil, errArtifactSigningHistory
	}
	return history, nil
}

// PurposeKeys returns owned copies, including revoked and expired historical
// versions. Consumers apply their own artifact-time and current-revocation
// policy and must not infer authorization from mere key presence.
func (h *ArtifactSigningKeyHistory) PurposeKeys(purpose string) []ArtifactSigningPublicKey {
	if h == nil || !artifactSigningPurpose(purpose) {
		return nil
	}
	out := make([]ArtifactSigningPublicKey, 0)
	for _, key := range h.keys {
		if key.Purpose == purpose {
			key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KeyID != out[j].KeyID {
			return out[i].KeyID < out[j].KeyID
		}
		return out[i].KeyVersion < out[j].KeyVersion
	})
	return out
}

// VerifyAcceptanceCandidate routes the acceptance purpose through this
// immutable snapshot. It does not grant artifact reads or authenticate the
// source that populated the snapshot.
func (h *ArtifactSigningKeyHistory) VerifyAcceptanceCandidate(raw []byte, binding AcceptanceCandidateBinding) error {
	if h == nil || binding.OriginInstallationID != h.installationID {
		return errArtifactSigningHistory
	}
	return VerifyAcceptanceCandidate(raw, binding, h.PurposeKeys("acceptance_record"))
}

// ValidateArtifactSigningRetention rejects an update that would make a
// referenced signature unverifiable through key loss or material rebinding.
// Revocation is allowed so a compromised key can be disabled; its referenced
// artifacts must separately be reported degraded and require manual recovery.
func ValidateArtifactSigningRetention(previous, next *ArtifactSigningKeyHistory, references []ArtifactSigningReference) (ArtifactSigningRetentionResult, error) {
	result := ArtifactSigningRetentionResult{}
	if previous == nil || next == nil || previous.installationID != next.installationID || references == nil {
		return result, errArtifactSigningHistory
	}
	for identity, old := range previous.keys {
		if replacement, present := next.keys[identity]; present {
			if !bytes.Equal(replacement.PublicKey, old.PublicKey) ||
				replacement.NotBefore.After(old.NotBefore) || replacement.NotAfter.Before(old.NotAfter) ||
				old.Revoked && !replacement.Revoked {
				return result, errArtifactSigningHistory
			}
		}
	}
	degraded := map[string]bool{}
	for _, ref := range references {
		if !artifactSigningPurpose(ref.Purpose) || !providerBoundedString(ref.KeyID) || !providerBoundedString(ref.KeyVersion) {
			return ArtifactSigningRetentionResult{}, errArtifactSigningHistory
		}
		identity := artifactSigningIdentity(ref.Purpose, ref.KeyID, ref.KeyVersion)
		old, existed := previous.keys[identity]
		current, retained := next.keys[identity]
		if !existed || !retained || !bytes.Equal(old.PublicKey, current.PublicKey) {
			return ArtifactSigningRetentionResult{}, errArtifactSigningHistory
		}
		if current.Revoked && !degraded[identity] {
			degraded[identity] = true
			result.DegradedReferences = append(result.DegradedReferences, ref)
		}
	}
	sort.Slice(result.DegradedReferences, func(i, j int) bool {
		a, b := result.DegradedReferences[i], result.DegradedReferences[j]
		return artifactSigningIdentity(a.Purpose, a.KeyID, a.KeyVersion) < artifactSigningIdentity(b.Purpose, b.KeyID, b.KeyVersion)
	})
	return result, nil
}
