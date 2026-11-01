package systembackupsecurity

import (
	"strings"
	"time"
)

// InspectInstallationSigningMaterial checks public material without constructing
// a signer, token source or transport. It returns no authority. The caller must
// supply independently deployed pins and later recheck all live owner facts.
func InspectInstallationSigningMaterial(raw, signature []byte, pin InstallationSigningPin, now time.Time) error {
	r, h, err := authenticateInstallationSigning(raw, signature, pin, now)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	purposes, keys, roles, policies := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range r.Permissions {
		b := p.Binding
		key, ok := h.keys[artifactSigningIdentity(b.Purpose, b.KeyID, b.KeyVersion)]
		if !ok || b.InstallationID != pin.InstallationID || !artifactSigningPurpose(b.Purpose) || purposes[b.Purpose] ||
			!exactSigningEndpoint(b.Endpoint) || !safeTransitName(b.KeyName) || !canonicalProviderVersion(b.ProviderVersion) ||
			keys[b.Endpoint+"/"+b.KeyName] || !safeTransitName(p.AuthMount) || !safeTransitName(p.Role) || !safeTransitName(p.Policy) ||
			strings.EqualFold(p.Policy, "root") || strings.EqualFold(p.Policy, "default") || roles[p.AuthMount+"/"+p.Role] || policies[p.Policy] || !signingDigest.MatchString(p.CASHA256) ||
			key.Revoked || now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
			return ErrRegistrationUnavailable
		}
		purposes[b.Purpose], keys[b.Endpoint+"/"+b.KeyName], roles[p.AuthMount+"/"+p.Role], policies[p.Policy] = true, true, true, true
	}
	if len(purposes) != 3 {
		return ErrRegistrationUnavailable
	}
	return nil
}
