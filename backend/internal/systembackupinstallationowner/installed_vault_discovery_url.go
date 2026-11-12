package systembackupinstallationowner

import "net/url"

// The issuer is a token identity, not necessarily the network address of the
// authenticated API. Never fetch jwks_uri: keys are read through the existing
// Kubernetes REST client. An advertised alternate authority must match that
// client's exact HTTPS authority, including its port.
func installedVaultDiscoveryURL(issuerText, jwksText string, authenticatedKeysURL *url.URL) bool {
	issuer, err := url.Parse(issuerText)
	keys, keysErr := url.Parse(jwksText)
	ordinary := func(u *url.URL) bool {
		return u != nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
			u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == "" && u.RawPath == ""
	}
	if err != nil || keysErr != nil || !ordinary(issuer) || !ordinary(keys) || !ordinary(authenticatedKeysURL) ||
		keys.Path != "/openid/v1/jwks" || authenticatedKeysURL.Path != "/openid/v1/jwks" {
		return false
	}
	authority := func(u *url.URL) string {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return u.Hostname() + ":" + port
	}
	return authority(keys) == authority(issuer) || authority(keys) == authority(authenticatedKeysURL)
}
