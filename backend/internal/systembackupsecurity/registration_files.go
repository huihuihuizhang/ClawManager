package systembackupsecurity

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var registryVersionPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Content-addressed files are mounted read-only by deployment. A caller can
// never choose a filename: kind is closed, version/digest come from SQL config.
type RegistrationFiles struct{ RegistryDirectory, NonceDirectory string }

func (f RegistrationFiles) RegistryBytes(kind, version, digest string) ([]byte, error) {
	if !contains(bootstrapRegistryKinds, kind) || !registryVersionPath.MatchString(version) || strings.Contains(version, "..") || !providerHashPattern.MatchString(digest) {
		return nil, ErrRegistrationUnavailable
	}
	b, err := boundedFile(filepath.Join(f.RegistryDirectory, kind, version, digest+".json"), 262144)
	if err != nil || registrationHash(string(b)) != digest {
		return nil, ErrRegistrationUnavailable
	}
	return b, nil
}
func boundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrRegistrationUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrRegistrationUnavailable
	}
	return b, nil
}
func (f RegistrationFiles) NonceKeys(ctx context.Context, tx *sql.Tx, c RegistrationConfig, versions []string) (map[string][]byte, error) {
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs ORDER BY nonce_hmac_ref_version,nonce_hmac_identity_hash")
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer rows.Close()
	identities := map[string]string{}
	for rows.Next() {
		var version, identity string
		if rows.Scan(&version, &identity) != nil || !registryVersionPath.MatchString(version) || strings.Contains(version, "..") || !providerHashPattern.MatchString(identity) {
			return nil, ErrRegistrationUnavailable
		}
		if old, ok := identities[version]; ok && old != identity {
			return nil, ErrRegistrationUnavailable
		}
		identities[version] = identity
		if len(identities) > 10000 {
			return nil, ErrRegistrationUnavailable
		}
	}
	if rows.Err() != nil || identities[c.NonceKeyVersion] != c.NonceIdentityHash {
		return nil, ErrRegistrationUnavailable
	}
	result := map[string][]byte{}
	for _, version := range versions {
		identity, ok := identities[version]
		if !ok {
			return nil, ErrRegistrationUnavailable
		}
		b, err := boundedFile(filepath.Join(f.NonceDirectory, identity, version), 64)
		if err != nil || len(b) != 32 {
			return nil, ErrRegistrationUnavailable
		}
		result[version] = b
	}
	return result, nil
}
