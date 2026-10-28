// Package systembackupnoncebootstrap checks deployment-pinned, local nonce
// material. It does not grant bootstrap authority or consume a nonce.
package systembackupnoncebootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	sec "clawreef/internal/systembackupsecurity"
)

// Key is original controlled deployment mapping, not a request DTO. MaterialSHA256
// pins bytes; it is NEVER the resource identity. Do not put this mapping in logs.
// Only exact-version external_secret mounts are supported here. Kubernetes API
// identity/UID validation needs its own adapter and cannot be inferred from a file.
type Key struct {
	IdentityHash, Version, ProviderIdentityHash, ScopeHash         string
	DescriptorFile, DescriptorSHA256, MaterialFile, MaterialSHA256 string
	ProtectedUntil                                                 time.Time
}

type Binding struct {
	InstallationID, ServerUUID, Database, ConfigSHA256 string
	NotBefore, ExpiresAt                               time.Time
	Keys                                               []Key
}

type Validator struct {
	binding Binding
	now     func() time.Time
}
type check struct {
	validator         *Validator
	observed, expires time.Time
}

var _ sec.BootstrapResourceValidator = (*Validator)(nil)
var _ sec.BootstrapResourceCheck = (*check)(nil)

func (Key) String() string                      { return "BootstrapNonceKeyMapping" }
func (Key) GoString() string                    { return "BootstrapNonceKeyMapping" }
func (Key) MarshalJSON() ([]byte, error)        { return nil, sec.ErrRegistrationUnavailable }
func (Binding) String() string                  { return "BootstrapNonceBinding" }
func (Binding) GoString() string                { return "BootstrapNonceBinding" }
func (Binding) MarshalJSON() ([]byte, error)    { return nil, sec.ErrRegistrationUnavailable }
func (*Validator) String() string               { return "BootstrapNonceValidator" }
func (*Validator) GoString() string             { return "BootstrapNonceValidator" }
func (*Validator) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*check) String() string                   { return "BootstrapNonceCheck" }
func (*check) GoString() string                 { return "BootstrapNonceCheck" }
func (*check) MarshalJSON() ([]byte, error)     { return nil, sec.ErrRegistrationUnavailable }

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var installation = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var server = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var database = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// New validates closed composition only; it does not authenticate who supplied
// the original mapping or assert that deployment review has happened.
func New(b Binding) (*Validator, error) {
	bad := func() (*Validator, error) { return nil, sec.ErrRegistrationUnavailable }
	if !installation.MatchString(b.InstallationID) || !server.MatchString(b.ServerUUID) || !database.MatchString(b.Database) || !digest.MatchString(b.ConfigSHA256) || b.NotBefore.IsZero() || !b.ExpiresAt.After(b.NotBefore) || len(b.Keys) == 0 || len(b.Keys) > 10000 {
		return bad()
	}
	seen := map[string]bool{}
	for _, k := range b.Keys {
		if !digest.MatchString(k.IdentityHash) || !digest.MatchString(k.ProviderIdentityHash) || !digest.MatchString(k.ScopeHash) || !digest.MatchString(k.DescriptorSHA256) || !digest.MatchString(k.MaterialSHA256) || !version.MatchString(k.Version) || strings.Contains(k.Version, "..") || k.Version == "latest" || k.Version == "current" || k.Version == "default" || seen[k.Version] || k.ProtectedUntil.Before(b.ExpiresAt) {
			return bad()
		}
		seen[k.Version] = true
		for _, p := range []string{k.DescriptorFile, k.MaterialFile} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return bad()
			}
		}
	}
	b.Keys = append([]Key(nil), b.Keys...)
	return &Validator{b, time.Now}, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func readPinned(p, hash string, limit int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() < 1 || s.Size() > limit {
		return nil, sec.ErrRegistrationUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	h := sha256.Sum256(b)
	if e != nil || int64(len(b)) > limit || hex.EncodeToString(h[:]) != hash {
		wipe(b)
		return nil, sec.ErrRegistrationUnavailable
	}
	return b, nil
}
func (v *Validator) live(t time.Time) bool {
	return !t.IsZero() && !t.Before(v.binding.NotBefore) && t.Before(v.binding.ExpiresAt)
}
func (v *Validator) validateKey(k Key) error {
	b, e := readPinned(k.DescriptorFile, k.DescriptorSHA256, 16384)
	if e != nil {
		return sec.ErrRegistrationUnavailable
	}
	r, e := refs.DecodeSecurityReference(b, k.DescriptorSHA256)
	if e != nil || r.Kind() != "external_secret" || r.Purpose() != "strong_auth_nonce_hmac" || r.IdentityHash() != k.IdentityHash || r.Version() != k.Version || r.ProviderIdentity() != k.ProviderIdentityHash || r.ScopeHash() != k.ScopeHash {
		return sec.ErrRegistrationUnavailable
	}
	b, e = readPinned(k.MaterialFile, k.MaterialSHA256, 32)
	defer wipe(b)
	if e != nil || len(b) != 32 {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

func (v *Validator) Prepare(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	bad := func() (sec.BootstrapResourceCheck, error) { return nil, sec.ErrRegistrationUnavailable }
	if v == nil || ctx == nil || ctx.Err() != nil || v.now == nil || g.InstallationID != v.binding.InstallationID || g.ServerUUID != v.binding.ServerUUID || g.Database != v.binding.Database || g.ConfigSHA256 != v.binding.ConfigSHA256 || c.SHA256() != v.binding.ConfigSHA256 || len(c.CanonicalJSON()) == 0 {
		return bad()
	}
	start := v.now().UTC()
	if !v.live(start) {
		return bad()
	}
	active := 0
	for _, k := range v.binding.Keys {
		if ctx.Err() != nil || v.validateKey(k) != nil {
			return bad()
		}
		for _, p := range c.References() {
			if p.Purpose == "nonce_hmac" && p.IdentityHash == k.IdentityHash && p.Version == k.Version {
				active++
			}
		}
	}
	end := v.now().UTC()
	until := start.Add(30 * time.Second)
	if v.binding.ExpiresAt.Before(until) {
		until = v.binding.ExpiresAt
	}
	if active != 1 || ctx.Err() != nil || end.Before(start) || !end.Before(until) {
		return bad()
	}
	copy := *v
	copy.binding.Keys = append([]Key(nil), v.binding.Keys...)
	return &check{&copy, end, until}, nil
}

// Material returns an owned copy, for BootstrapAdmissionSources.NonceMaterial.
// It reads only the exact original mapping; callers must erase the result.
func (v *Validator) Material(identity, keyVersion string) ([]byte, error) {
	if v == nil || v.now == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	started := v.now().UTC()
	if !v.live(started) {
		return nil, sec.ErrRegistrationUnavailable
	}
	for _, k := range v.binding.Keys {
		if k.IdentityHash == identity && k.Version == keyVersion {
			if v.validateKey(k) != nil {
				return nil, sec.ErrRegistrationUnavailable
			}
			b, e := readPinned(k.MaterialFile, k.MaterialSHA256, 32)
			finished := v.now().UTC()
			if e != nil || len(b) != 32 || !v.live(finished) || finished.Before(started) {
				wipe(b)
				return nil, sec.ErrRegistrationUnavailable
			}
			return b, nil
		}
	}
	return nil, sec.ErrRegistrationUnavailable
}

func (c *check) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	bad := sec.ErrRegistrationUnavailable
	if c == nil || c.validator == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return bad
	}
	v := c.validator
	validTime := func(t time.Time) bool { return v.live(t) && !t.Before(c.observed) && t.Before(c.expires) }
	if !validTime(now) || !validTime(v.now().UTC()) {
		return bad
	}
	var sid, db string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&sid, &db) != nil || sid != v.binding.ServerUUID || db != v.binding.Database {
		return bad
	}
	// Read the complete persisted global identity set and retained ledger in the
	// caller's transaction. Missing material must not shrink the required set.
	rows, e := tx.QueryContext(ctx, `SELECT nonce_hmac_ref_version,nonce_hmac_identity_hash,NULL FROM system_backup_v2_configs
UNION SELECT nonce_hmac_key_version,NULL,MAX(retain_until) FROM system_backup_v2_strong_auth_nonces WHERE retain_until>? GROUP BY nonce_hmac_key_version`, now)
	if e != nil {
		return bad
	}
	keys := map[string]Key{}
	for _, k := range v.binding.Keys {
		keys[k.Version] = k
	}
	count := 0
	for rows.Next() {
		var ver string
		var identity sql.NullString
		var retained sql.NullTime
		if rows.Scan(&ver, &identity, &retained) != nil {
			rows.Close()
			return bad
		}
		k, ok := keys[ver]
		if !ok || (!identity.Valid && !retained.Valid) || (identity.Valid && identity.String != k.IdentityHash) || (retained.Valid && (!retained.Time.After(now) || retained.Time.After(k.ProtectedUntil))) {
			rows.Close()
			return bad
		}
		count++
		if count > 20000 {
			rows.Close()
			return bad
		}
	}
	err := rows.Err()
	closed := rows.Close()
	if err != nil || closed != nil {
		return bad
	}
	for _, k := range v.binding.Keys {
		if ctx.Err() != nil || v.validateKey(k) != nil {
			return bad
		}
	}
	if ctx.Err() != nil || !validTime(v.now().UTC()) {
		return bad
	}
	return nil
}
