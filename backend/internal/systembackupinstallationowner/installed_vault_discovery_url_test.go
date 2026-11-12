package systembackupinstallationowner

import (
	"net/url"
	"testing"
)

// URL binding checks only: no API, TLS session, JWT or provider is simulated.
func TestInstalledVaultDiscoveryAllowsIssuerIdentityAndAuthenticatedAPIAddress(t *testing.T) {
	issuer := "https://kubernetes.default.svc.cluster.local"
	api, _ := url.Parse("https://10.130.14.23:6443/openid/v1/jwks")
	for _, jwks := range []string{issuer + "/openid/v1/jwks", issuer + ":443/openid/v1/jwks", api.String()} {
		if !installedVaultDiscoveryURL(issuer, jwks, api) {
			t.Fatal("issuer identity or exact authenticated API address rejected")
		}
	}
}

func TestInstalledVaultDiscoveryRejectsUnboundAuthorityAndURLConfusion(t *testing.T) {
	issuer := "https://kubernetes.default.svc.cluster.local"
	api, _ := url.Parse("https://10.130.14.23:6443/openid/v1/jwks")
	for _, jwks := range []string{
		"https://unrelated.example/openid/v1/jwks", "https://10.130.14.23:6444/openid/v1/jwks",
		"http://10.130.14.23:6443/openid/v1/jwks", "https://user@10.130.14.23:6443/openid/v1/jwks",
		api.String() + "?token=untrusted", api.String() + "?", api.String() + "#fragment",
		"https://10.130.14.23:6443/other", "https://10.130.14.23:6443/openid/v1/%6awks",
	} {
		if installedVaultDiscoveryURL(issuer, jwks, api) {
			t.Fatal("unbound authority, redirect-like URL or credential-bearing URL accepted")
		}
	}
	for _, selected := range []*url.URL{nil, {Scheme: "http", Host: "10.130.14.23:6443", Path: "/openid/v1/jwks"}} {
		if installedVaultDiscoveryURL(issuer, api.String(), selected) {
			t.Fatal("missing or unauthenticated API address accepted")
		}
	}
}
