package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// DecodeStrongAuthIssuerRegistry validates the same pinned public trust profile
// used by registration and bootstrap. Historical keys may remain, but active
// versions of an issuer must agree on policy. This does not contact a signer or
// establish that a person has completed MFA.
func DecodeStrongAuthIssuerRegistry(raw []byte, version, digest string, now time.Time) (StrongAuthIssuerRegistry, error) {
	var r StrongAuthIssuerRegistry
	fail := func() (StrongAuthIssuerRegistry, error) {
		return StrongAuthIssuerRegistry{}, ErrRegistrationUnavailable
	}
	if decodePinnedRegistry(raw, digest, &r) != nil || now.IsZero() || r.SchemaVersion != "system-backup-strong-auth-issuers.draft.v1" || r.Version != version || !providerBoundedString(r.Audience) || len(r.Keys) == 0 || len(r.Keys) > 128 {
		return fail()
	}
	seen := map[[2]string]bool{}
	policies := map[string][]byte{}
	for _, k := range r.Keys {
		if !providerBoundedString(k.Issuer) || !providerBoundedString(k.KeyID) || !providerBoundedString(k.KeyVersion) || k.Purpose != "strong_auth_issuer" || len(k.PublicKey) != ed25519.PublicKeySize || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) || !validRegistryIssuerPolicy(k.Policy) {
			return fail()
		}
		id := [2]string{k.Issuer, k.KeyVersion}
		if seen[id] {
			return fail()
		}
		seen[id] = true
		if k.Revoked || now.Before(k.NotBefore) || !now.Before(k.NotAfter) {
			continue
		}
		policy, _ := json.Marshal(k.Policy)
		if prior, ok := policies[k.Issuer]; ok && !bytes.Equal(prior, policy) {
			return fail()
		}
		policies[k.Issuer] = policy
	}
	return r, nil
}

func validRegistryIssuerPolicy(p IssuerPolicy) bool {
	if len(p.Methods) == 0 || len(p.Methods) > 3 || len(p.ACR) > 128 || len(p.AMR) > 128 {
		return false
	}
	for _, values := range [][]string{p.Methods, p.ACR, p.AMR} {
		seen := map[string]bool{}
		for _, value := range values {
			if !providerBoundedString(value) || seen[value] {
				return false
			}
			seen[value] = true
		}
	}
	for _, method := range p.Methods {
		if !contains([]string{"totp", "webauthn", "oidc_mfa"}, method) ||
			(method == "webauthn" && !contains(p.AMR, "webauthn")) ||
			(method == "oidc_mfa" && (len(p.ACR) == 0 || len(p.AMR) == 0)) {
			return false
		}
	}
	return true
}
