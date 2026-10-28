package systembackupbootstrapsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Issuers validates both public trust registries together, including separation
// of historical keys. It supplies each issuer-registry slot, not a typed signer
// reference, provider authorization, personnel MFA, or cross-resource admission.
type Issuers struct {
	directory string
	now       func() time.Time
}

func NewIssuers(directory string) *Issuers { return &Issuers{directory, time.Now} }

func (v *Issuers) Prepare(ctx context.Context, g sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || v.now == nil || !filepath.IsAbs(v.directory) || filepath.Clean(v.directory) != v.directory || !validGrant(g, config) {
		return nil, sec.ErrRegistrationUnavailable
	}
	c := &issuerCheck{files: sec.RegistrationFiles{RegistryDirectory: v.directory}, grant: g}
	for _, pin := range config.Registries() {
		switch pin.Kind {
		case "provider_proof_issuers":
			c.provider = pin
		case "strong_auth_issuers":
			c.strong = pin
		}
	}
	if c.provider.Kind == "" || c.strong.Kind == "" || c.validate(ctx, v.now().UTC()) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return c, nil
}

type issuerCheck struct {
	files            sec.RegistrationFiles
	grant            sec.OfflineBootstrapGrant
	provider, strong sec.BootstrapRegistryRef
}

func (*issuerCheck) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*issuerCheck) String() string               { return "BootstrapIssuerCheck" }
func (*issuerCheck) GoString() string             { return "BootstrapIssuerCheck" }

func (c *issuerCheck) validate(ctx context.Context, now time.Time) error {
	if c == nil || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return sec.ErrRegistrationUnavailable
	}
	raw, err := c.files.RegistryBytes(c.provider.Kind, c.provider.Version, c.provider.SHA256)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	provider, err := sec.DecodeProviderIssuerRegistry(raw, c.provider.Version, c.provider.SHA256, now)
	if err != nil || provider.Scope.InstallationID != c.grant.InstallationID {
		return sec.ErrRegistrationUnavailable
	}
	raw, err = c.files.RegistryBytes(c.strong.Kind, c.strong.Version, c.strong.SHA256)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	strong, err := sec.DecodeStrongAuthIssuerRegistry(raw, c.strong.Version, c.strong.SHA256, now)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	providerActive, totpActive := false, false
	for _, key := range provider.Keys {
		if !closedSet(key.TargetTypes, []string{"external_action", "backup_staging", "restore_resource"}) || !closedSet(key.ProofTypes, []string{"provider_presence", "provider_absence", "ownership"}) {
			return sec.ErrRegistrationUnavailable
		}
		// Every declared capability must have a compatible counterpart.
		for _, target := range key.TargetTypes {
			if (target == "external_action" && !has(key.ProofTypes, "provider_presence") && !has(key.ProofTypes, "provider_absence")) || (target != "external_action" && !has(key.ProofTypes, "ownership")) {
				return sec.ErrRegistrationUnavailable
			}
		}
		for _, proof := range key.ProofTypes {
			if (proof == "ownership" && !has(key.TargetTypes, "backup_staging") && !has(key.TargetTypes, "restore_resource")) || (proof != "ownership" && !has(key.TargetTypes, "external_action")) {
				return sec.ErrRegistrationUnavailable
			}
		}
		if !key.Revoked && !now.Before(key.NotBefore) && now.Add(5*time.Minute).Before(key.NotAfter) {
			providerActive = true
		}
		for _, other := range strong.Keys {
			if bytes.Equal(key.PublicKey, other.PublicKey) {
				return sec.ErrRegistrationUnavailable
			}
		}
	}
	for _, key := range strong.Keys {
		if !key.Revoked && !now.Before(key.NotBefore) && now.Add(5*time.Minute).Before(key.NotAfter) && has(key.Policy.Methods, "totp") && has(key.Policy.AMR, "otp") {
			totpActive = true
		}
	}
	// Match the existing registration runtime's five-minute key runway and its
	// real TOTP issuer. Historical-only trust must not pass initial admission.
	if !providerActive || !totpActive || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

func has(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func closedSet(values, allowed []string) bool {
	if len(values) == 0 || len(values) > len(allowed) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !has(allowed, value) {
			return false
		}
		seen[value] = true
	}
	return true
}

func (c *issuerCheck) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if c == nil || ctx == nil || ctx.Err() != nil || tx == nil || now.IsZero() {
		return sec.ErrRegistrationUnavailable
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != c.grant.ServerUUID || database != c.grant.Database {
		return sec.ErrRegistrationUnavailable
	}
	return c.validate(ctx, now.UTC())
}
