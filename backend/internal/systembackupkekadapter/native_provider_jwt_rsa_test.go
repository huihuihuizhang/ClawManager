package systembackupkekadapter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestRuntimeVaultJWTTrustReusesRSAIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	original := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	expected := VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", Algorithms: []string{"RS256"}, ValidationPublicKeys: []string{original}}
	body := func() map[string]any {
		return map[string]any{"bound_issuer": expected.Issuer, "jwt_supported_algs": expected.Algorithms, "jwt_validation_pubkeys": []string{strings.TrimSpace(original)}, "default_role": "", "jwks_url": "", "jwks_ca_pem": ""}
	}
	check := func(v map[string]any) error { raw, _ := json.Marshal(v); return validateVaultJWTTrust(raw, expected) }
	// The installed provider returns450 PEM bytes; the original API reader451.
	if err := check(body()); err != nil {
		t.Fatal("same RSA key with omitted final newline rejected", err)
	}
	for _, value := range []string{strings.ReplaceAll(original, "\n", "\r\n"), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))} {
		v := body()
		v["jwt_validation_pubkeys"] = []string{value}
		if err := check(v); err != nil {
			t.Fatal("equivalent RSA encoding rejected", err)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))
	cases := map[string]func(map[string]any){
		"different key": func(v map[string]any) { v["jwt_validation_pubkeys"] = []string{otherPEM} },
		"duplicate key": func(v map[string]any) { v["jwt_validation_pubkeys"] = []string{original, strings.TrimSpace(original)} },
		"missing key":   func(v map[string]any) { v["jwt_validation_pubkeys"] = []string{} },
		"issuer":        func(v map[string]any) { v["bound_issuer"] = "https://other.invalid" },
		"algorithm":     func(v map[string]any) { v["jwt_supported_algs"] = []string{"ES256"} },
		"default role":  func(v map[string]any) { v["default_role"] = "other" },
		"jwks":          func(v map[string]any) { v["jwks_url"] = "https://other.invalid/keys" },
		"oidc":          func(v map[string]any) { v["oidc_discovery_url"] = "https://other.invalid" },
		"issuer alias":  func(v map[string]any) { v["Bound_Issuer"] = expected.Issuer },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := body()
			mutate(v)
			if check(v) == nil {
				t.Fatal("changed trust admitted")
			}
		})
	}
	// Keep the already supported JWKS profile on its exact field checks.
	jwks := VaultJWTTrust{Issuer: expected.Issuer, JWKSURL: "https://api.invalid/keys", JWKSCAPEM: "original-ca", Algorithms: []string{"RS256"}}
	raw, _ := json.Marshal(map[string]any{"bound_issuer": jwks.Issuer, "jwt_supported_algs": jwks.Algorithms, "jwks_url": jwks.JWKSURL, "jwks_ca_pem": jwks.JWKSCAPEM, "default_role": ""})
	if err := validateVaultJWTTrust(raw, jwks); err != nil {
		t.Fatal("unchanged JWKS profile rejected", err)
	}
}
