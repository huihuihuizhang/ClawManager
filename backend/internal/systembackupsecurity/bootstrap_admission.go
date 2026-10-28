package systembackupsecurity

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// BootstrapResourceValidator is a deployment adapter, not a boolean supplied
// by an operator JSON document. Prepare must resolve the real resource and
// check its schema, immutable identity, purpose, TLS/SSRF policy, permissions
// and capability before transaction locks are acquired. Recheck must only use
// local immutable snapshots/transactional state; it must reject stale, revoked
// or changed observations and must not perform network I/O or commit the tx.
type BootstrapResourceValidator interface {
	Prepare(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error)
}

type BootstrapResourceCheck interface {
	Recheck(context.Context, *sql.Tx, time.Time) error
}

// BootstrapAdmissionSources deliberately has no allow-all implementation.
// Registry adapters are keyed by registry kind, ref adapters by config purpose.
// The cross-resource adapter checks disaster identity mappings, secret allowlist,
// signing/credential purpose separation and retention across the entire config.
// ReadGrant must read current deployment-owned authorization on EVERY attempt,
// including committed retries. It must never read authorization from HTTP input.
type BootstrapAdmissionSources struct {
	ReadGrant       func() (OfflineBootstrapGrant, time.Time, time.Time, error)
	RegistryBytes   func(kind, version, digest string) ([]byte, error)
	Registries      map[string]BootstrapResourceValidator
	References      map[string]BootstrapResourceValidator
	CrossResources  BootstrapResourceValidator
	NonceMaterial   func(identity, version string) ([]byte, error)
	ReserveMetadata func(context.Context, *sql.Tx, int64, int) error
}

// MissingBootstrapAdapters exposes only closed requirement names, never
// provider diagnostics, secret values or arbitrary user-controlled strings.
func MissingBootstrapAdapters(s BootstrapAdmissionSources) []string {
	missing := []string{}
	for _, kind := range bootstrapRegistryKinds {
		if candidateAuthorityNil(s.Registries[kind]) {
			missing = append(missing, "registry:"+kind)
		}
	}
	for _, purpose := range bootstrapReferencePurposes {
		if candidateAuthorityNil(s.References[purpose]) {
			missing = append(missing, "reference:"+purpose)
		}
	}
	for _, item := range []struct {
		name string
		ok   bool
	}{
		{"offline_grant", s.ReadGrant != nil}, {"registry_bytes", s.RegistryBytes != nil},
		{"cross_resources", !candidateAuthorityNil(s.CrossResources)}, {"nonce_material", s.NonceMaterial != nil},
		{"metadata_capacity", s.ReserveMetadata != nil},
	} {
		if !item.ok {
			missing = append(missing, item.name)
		}
	}
	return missing
}

type preparedBootstrapAdmission struct {
	grant   OfflineBootstrapGrant
	config  BootstrapConfig
	sources BootstrapAdmissionSources
	checks  []BootstrapResourceCheck
}

// PrepareBootstrapAdmission is the production orchestration boundary. A
// missing adapter is rejected before any provider work. Its return value is
// deliberately opaque: untrusted files cannot manufacture successful checks.
// Preparation is NOT activation and is not evidence of human MFA.
func PrepareBootstrapAdmission(ctx context.Context, g OfflineBootstrapGrant, raw []byte, s BootstrapAdmissionSources) (BootstrapAdmission, error) {
	if candidateAuthorityNil(ctx) || ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		return nil, err
	}
	if !validBootstrapGrant(g) || c.SHA256() != g.ConfigSHA256 || len(MissingBootstrapAdapters(s)) != 0 || len(s.Registries) != len(bootstrapRegistryKinds) || len(s.References) != len(bootstrapReferencePurposes) {
		return nil, ErrRegistrationUnavailable
	}
	// Callbacks cannot replace a later owner through the caller's map, either
	// during preparation or after this attempt has captured its sources.
	registries := make(map[string]BootstrapResourceValidator, len(s.Registries))
	for kind, validator := range s.Registries {
		registries[kind] = validator
	}
	references := make(map[string]BootstrapResourceValidator, len(s.References))
	for purpose, validator := range s.References {
		references[purpose] = validator
	}
	s.Registries, s.References = registries, references
	a := &preparedBootstrapAdmission{grant: g, config: c, sources: s}
	if err = a.authorize(g, c, time.Now().UTC()); err != nil {
		return nil, err
	}
	prepare := func(v BootstrapResourceValidator) error {
		if ctx.Err() != nil {
			return ErrRegistrationUnavailable
		}
		check, e := v.Prepare(ctx, g, c)
		if e != nil || candidateAuthorityNil(check) {
			return ErrRegistrationUnavailable
		}
		a.checks = append(a.checks, check)
		return nil
	}
	for _, r := range c.Registries() {
		b, e := s.RegistryBytes(r.Kind, r.Version, r.SHA256)
		if e != nil || len(b) == 0 || len(b) > 262144 || registrationHash(string(b)) != r.SHA256 {
			return nil, ErrRegistrationUnavailable
		}
		if err = prepare(s.Registries[r.Kind]); err != nil {
			return nil, err
		}
	}
	for _, r := range c.References() {
		if err = prepare(s.References[r.Purpose]); err != nil {
			return nil, err
		}
	}
	if err = prepare(s.CrossResources); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *preparedBootstrapAdmission) authorize(g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if g != a.grant || c.SHA256() != a.config.SHA256() || now.IsZero() {
		return ErrRegistrationUnavailable
	}
	current, notBefore, expires, err := a.sources.ReadGrant()
	if err != nil || current != g || notBefore.IsZero() || !expires.After(notBefore) || now.Before(notBefore) || !now.Before(expires) {
		return ErrRegistrationPermission
	}
	var rbac BootstrapRegistryRef
	for _, r := range c.Registries() {
		if r.Kind == "rbac_bindings" {
			rbac = r
		}
	}
	authority := PinnedRegistrationAuthority{InstallationID: g.InstallationID, RegistryBytes: a.sources.RegistryBytes}
	return authority.AuthorizeRole(RegistrationActor{UserID: g.UserID, Subject: "user:" + strconv.FormatInt(g.UserID, 10)}, RegistrationConfig{RBACRegistryVersion: rbac.Version, RBACRegistrySHA256: rbac.SHA256})
}

func (a *preparedBootstrapAdmission) Authorize(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if ctx.Err() != nil || tx == nil {
		return ErrRegistrationUnavailable
	}
	return a.authorize(g, c, now)
}

func (a *preparedBootstrapAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if err := a.Authorize(ctx, tx, g, c, now); err != nil {
		return err
	}
	for _, r := range c.Registries() {
		b, err := a.sources.RegistryBytes(r.Kind, r.Version, r.SHA256)
		if err != nil || len(b) == 0 || len(b) > 262144 || registrationHash(string(b)) != r.SHA256 {
			return ErrRegistrationUnavailable
		}
	}
	for _, check := range a.checks {
		if ctx.Err() != nil || check.Recheck(ctx, tx, now) != nil {
			return ErrRegistrationUnavailable
		}
	}
	for _, r := range c.References() {
		if r.Purpose == "nonce_hmac" {
			// The resolver transfers an owned copy. Never retain key material in
			// the prepared admission, and never hash the secret as its identity.
			key, err := a.sources.NonceMaterial(r.IdentityHash, r.Version)
			valid := err == nil && len(key) == 32
			wipeSecret(key)
			if !valid {
				return ErrRegistrationUnavailable
			}
		}
	}
	// Bootstrap rows/audits are charged conservatively; the same transaction
	// rolls the reservation back if any subsequent config/state write fails.
	if err := a.sources.ReserveMetadata(ctx, tx, c.numbers["control_metadata_capacity_bytes"], 8192); err != nil {
		return registrationBoundaryError(err)
	}
	return nil
}
