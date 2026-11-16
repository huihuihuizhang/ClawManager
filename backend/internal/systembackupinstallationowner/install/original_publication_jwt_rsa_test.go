package install

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestOriginalPublicationJWTTrustReusesRSAIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	original := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	wanted := map[string]any{"bound_issuer": "https://kubernetes.default.svc.cluster.local", "jwt_supported_algs": []string{"RS256"}, "jwt_validation_pubkeys": []string{original}, "default_role": ""}
	expected, _ := json.Marshal(wanted)
	actual := func() map[string]any {
		return map[string]any{"bound_issuer": wanted["bound_issuer"], "jwt_supported_algs": []string{"RS256"}, "jwt_validation_pubkeys": []string{strings.TrimSpace(original)}, "default_role": "", "jwks_url": "", "oidc_discovery_url": ""}
	}
	check := func(v map[string]any) bool {
		raw, _ := json.Marshal(v)
		return originalPublicationJWTTrustSubset(raw, expected)
	}
	if !check(actual()) {
		t.Fatal("actual provider final-newline difference rejected before C1/signing")
	}
	for _, field := range []string{"bound_issuer", "default_role"} {
		v := actual()
		v[field] = "other"
		if check(v) {
			t.Fatal("changed trust admitted", field)
		}
	}
	v := actual()
	v["jwt_supported_algs"] = []string{"ES256"}
	if check(v) {
		t.Fatal("changed algorithm admitted")
	}
	v = actual()
	v["jwt_validation_pubkeys"] = []string{original, strings.TrimSpace(original)}
	if check(v) {
		t.Fatal("duplicate key admitted")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	v = actual()
	v["jwt_validation_pubkeys"] = []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))}
	if check(v) {
		t.Fatal("different RSA identity admitted")
	}
	raw, _ := json.Marshal(actual())
	duplicate := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(",\"jwt_validation_pubkeys\":[]}")...)
	if originalPublicationJWTTrustSubset(duplicate, expected) {
		t.Fatal("duplicate JSON member admitted")
	}
}
