package systembackupsecurity

import "time"

// BootstrapGrantFile is an offline deployment authorization document, mounted
// read-only and pinned outside the file. Removing/replacing it revokes retry
// authorization. Its digest is not a signature or a substitute for filesystem
// access control. Do not expose this loader through an HTTP request.
type BootstrapGrantFile struct {
	SchemaVersion string                `json:"schema_version"`
	NotBefore     time.Time             `json:"not_before"`
	ExpiresAt     time.Time             `json:"expires_at"`
	Grant         OfflineBootstrapGrant `json:"grant"`
}

func ReadBootstrapGrantFile(path, digest string) (OfflineBootstrapGrant, time.Time, time.Time, error) {
	var document BootstrapGrantFile
	raw, err := boundedFile(path, 16384)
	if err != nil || decodePinnedRegistry(raw, digest, &document) != nil || document.SchemaVersion != "system-backup-offline-bootstrap-grant.v1" || !validBootstrapGrant(document.Grant) || document.NotBefore.IsZero() || !document.ExpiresAt.After(document.NotBefore) {
		return OfflineBootstrapGrant{}, time.Time{}, time.Time{}, ErrRegistrationPermission
	}
	return document.Grant, document.NotBefore, document.ExpiresAt, nil
}
