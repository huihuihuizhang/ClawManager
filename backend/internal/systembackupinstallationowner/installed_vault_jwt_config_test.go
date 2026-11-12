package systembackupinstallationowner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestInstalledVaultJWTConfigNormalizesOnlyPublicKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	want := map[string]any{"bound_issuer": "https://issuer.invalid", "jwt_supported_algs": []string{"RS256"}, "default_role": "", "jwt_validation_pubkeys": []string{public}}
	expected, _ := json.Marshal(want)
	want["jwt_validation_pubkeys"] = []string{strings.TrimSpace(public)}
	actual, _ := json.Marshal(want)
	if !installedVaultJWTConfigMatches(actual, expected) {
		t.Fatal("equivalent key format rejected")
	}
	for name, value := range map[string]any{"bound_issuer": "https://other.invalid", "jwt_supported_algs": []string{"HS256"}, "default_role": "unexpected", "jwt_validation_pubkeys": []string{public, public}} {
		var changed map[string]any
		json.Unmarshal(actual, &changed)
		changed[name] = value
		raw, _ := json.Marshal(changed)
		if installedVaultJWTConfigMatches(raw, expected) {
			t.Fatal("changed trust accepted:", name)
		}
	}
	duplicate := append([]byte(`{"bound_issuer":"https://other.invalid",`), actual[1:]...)
	if installedVaultJWTConfigMatches(duplicate, expected) {
		t.Fatal("duplicate JSON field accepted")
	}
}
