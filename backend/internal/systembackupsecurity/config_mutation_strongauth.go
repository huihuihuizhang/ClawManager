package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// ConfigMutationSecurityFiles loads verification material, never a write grant.
// Its absolute directories must be deployment-owned read-only mounts. Session,
// RBAC and nonce consumption remain in the caller's mutation transaction.
type ConfigMutationSecurityFiles struct {
	installation string
	database     DatabaseIdentity
	files        RegistrationFiles
}

func NewConfigMutationSecurityFiles(installation string, database DatabaseIdentity, registryDirectory, nonceDirectory string) (*ConfigMutationSecurityFiles, error) {
	if !configMutationInstallation.MatchString(installation) || !database.valid() || !filepath.IsAbs(registryDirectory) || !filepath.IsAbs(nonceDirectory) || filepath.Clean(registryDirectory) != registryDirectory || filepath.Clean(nonceDirectory) != nonceDirectory {
		return nil, ErrRegistrationUnavailable
	}
	return &ConfigMutationSecurityFiles{installation, database, RegistrationFiles{registryDirectory, nonceDirectory}}, nil
}

func (f *ConfigMutationSecurityFiles) StrongAuth(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, current ConfigValues, versions []string, now time.Time) (VerifyConfig, error) {
	fail := func() (VerifyConfig, error) { return VerifyConfig{}, ErrRegistrationUnavailable }
	if f == nil || ctx == nil || ctx.Err() != nil || tx == nil || installation != f.installation || len(current.CanonicalJSON()) < 2 || !configMutationSessionAt(actor, now) || actor.UserID < 1 || actor.Subject == "" || actor.Session == "" || len(versions) == 0 || len(versions) > 10000 {
		return fail()
	}
	if f.database.check(ctx, tx) != nil {
		return fail()
	}
	var provider, strong BootstrapRegistryRef
	for _, pin := range current.Registries() {
		switch pin.Kind {
		case "provider_proof_issuers":
			provider = pin
		case "strong_auth_issuers":
			strong = pin
		}
	}
	var nonce BootstrapSecretRef
	for _, pin := range current.References() {
		if pin.Purpose == "nonce_hmac" {
			nonce = pin
		}
	}
	// Independently compare the requested retained set to persisted facts. Do
	// not derive completeness from the subset whose secret files still exist.
	retained, err := retainedNonceVersions(ctx, tx, nonce.Version, now)
	if err != nil || len(retained) != len(versions) {
		return fail()
	}
	requested := map[string]bool{}
	for _, version := range versions {
		if requested[version] || !registryVersionPath.MatchString(version) || strings.Contains(version, "..") {
			return fail()
		}
		requested[version] = true
	}
	for _, version := range retained {
		if !requested[version] {
			return fail()
		}
	}
	prRaw, err := f.files.RegistryBytes(provider.Kind, provider.Version, provider.SHA256)
	if err != nil {
		return fail()
	}
	pr, err := DecodeProviderIssuerRegistry(prRaw, provider.Version, provider.SHA256, now)
	if err != nil || pr.Scope.InstallationID != installation {
		return fail()
	}
	srRaw, err := f.files.RegistryBytes(strong.Kind, strong.Version, strong.SHA256)
	if err != nil {
		return fail()
	}
	var sr StrongAuthIssuerRegistry
	if decodePinnedRegistry(srRaw, strong.SHA256, &sr) != nil || sr.SchemaVersion != "system-backup-strong-auth-issuers.draft.v1" || sr.Version != strong.Version || sr.Audience == "" || len(sr.Keys) == 0 || len(sr.Keys) > 128 {
		return fail()
	}
	sc := VerifyConfig{Now: now, MaxAge: time.Duration(current.snapshot.numbers["strong_auth_max_age_seconds"]) * time.Second, ClockSkew: time.Duration(current.snapshot.numbers["strong_auth_clock_skew_seconds"]) * time.Second,
		ExpectedAudience: sr.Audience, ExpectedSubject: actor.Subject, ExpectedSession: actor.Session,
		TrustedSigners: map[string]map[string]SignatureVerifier{}, TrustedIssuerPolicies: map[string]IssuerPolicy{}, ActiveNonceHMACKeyVersion: nonce.Version, RequiredNonceHMACKeyVersions: append([]string(nil), retained...)}
	seen := map[string]bool{}
	for _, key := range sr.Keys {
		if key.Issuer == "" || key.KeyID == "" || key.KeyVersion == "" || strings.ContainsRune(key.Issuer, 0) || strings.ContainsRune(key.KeyVersion, 0) || key.Purpose != "strong_auth_issuer" || len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.IsZero() || !key.NotAfter.After(key.NotBefore) || len(key.Policy.Methods) == 0 {
			return fail()
		}
		// Purpose isolation includes revoked/historical provider keys, not only
		// currently usable attestations. Reusing their bytes is still forbidden.
		for _, pk := range pr.Keys {
			if bytes.Equal(pk.PublicKey, key.PublicKey) {
				return fail()
			}
		}
		identity := key.Issuer + "\x00" + key.KeyVersion
		if seen[identity] {
			return fail()
		}
		seen[identity] = true
		if key.Revoked || now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
			continue
		}
		if policy, ok := sc.TrustedIssuerPolicies[key.Issuer]; ok {
			a, _ := json.Marshal(policy)
			b, _ := json.Marshal(key.Policy)
			if !bytes.Equal(a, b) {
				return fail()
			}
		}
		if sc.TrustedSigners[key.Issuer] == nil {
			sc.TrustedSigners[key.Issuer] = map[string]SignatureVerifier{}
		}
		sc.TrustedIssuerPolicies[key.Issuer] = key.Policy
		sc.TrustedSigners[key.Issuer][key.KeyVersion] = timedStrongAuthVerifier{Ed25519JWSVerifier{append(ed25519.PublicKey(nil), key.PublicKey...), key.KeyID, key.KeyVersion, key.Purpose}, key.NotBefore, key.NotAfter}
	}
	if len(sc.TrustedSigners) == 0 {
		return fail()
	}
	keys, err := f.files.NonceKeys(ctx, tx, RegistrationConfig{NonceKeyVersion: nonce.Version, NonceIdentityHash: nonce.IdentityHash}, append([]string(nil), retained...))
	defer func() {
		for _, key := range keys {
			wipeSecret(key)
		}
	}()
	if err != nil || len(keys) != len(retained) {
		return fail()
	}
	sc.NonceHMACKeys = map[string][]byte{}
	for _, version := range retained {
		if len(keys[version]) != 32 {
			return fail()
		}
		sc.NonceHMACKeys[version] = append([]byte(nil), keys[version]...)
	}
	return sc, nil
}
