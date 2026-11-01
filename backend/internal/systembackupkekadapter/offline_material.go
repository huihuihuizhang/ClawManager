package systembackupkekadapter

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// InspectOriginalKEKMaterial reuses the importer and active-record validators.
// It performs no I/O, creates no PreparedMappingSource and admits no mapping.
// The exact bytes, issuer, installation, reference and revision must all be
// pinned independently; a signature alone does not prevent stale replay.
func InspectOriginalKEKMaterial(raw, signature []byte, issuer ed25519.PublicKey, digest, installation, revision string, ref reg.ReferencePin, now time.Time) error {
	sum := sha256.Sum256(raw)
	if !authorityHash.MatchString(digest) || hex.EncodeToString(sum[:]) != digest {
		return ErrAuthorityWrite
	}
	r, err := decodeOwnerRecord(raw, signature, issuer)
	if err != nil || r.Binding.InstallationID != installation || r.Binding.ConfigRef != ref || r.Revision != revision {
		return ErrAuthorityWrite
	}
	if _, err = authenticate(raw, signature, issuer, now); err != nil {
		return ErrAuthorityWrite
	}
	return nil
}
