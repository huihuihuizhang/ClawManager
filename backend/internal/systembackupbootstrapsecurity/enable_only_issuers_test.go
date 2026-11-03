package systembackupbootstrapsecurity

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"testing"
)

func TestEnableOnlyIssuerNativeCodecRetainsOriginalPurposeIsolation(t *testing.T) {
	for _, which := range []string{"valid", "cross_purpose", "no_totp", "revoked_provider"} {
		t.Run(which, func(t *testing.T) {
			f := newIssuerFixture(t, func(provider, strong map[string]any) {
				switch which {
				case "cross_purpose":
					firstKey(strong)["public_key_base64"] = firstKey(provider)["public_key_base64"]
				case "no_totp":
					policy(strong)["methods"] = []string{"webauthn"}
					policy(strong)["amr"] = []string{"webauthn"}
				case "revoked_provider":
					firstKey(provider)["revoked"] = true
				}
			}, nil)
			var provider, strong sec.BootstrapRegistryRef
			for _, pin := range f.config.Registries() {
				if pin.Kind == "provider_proof_issuers" {
					provider = pin
				}
				if pin.Kind == "strong_auth_issuers" {
					strong = pin
				}
			}
			e := validateEnableOnlyIssuerFiles(context.Background(), sec.RegistrationFiles{RegistryDirectory: f.v.directory}, f.grant.InstallationID, provider, strong, issuerNow)
			if (e == nil) != (which == "valid") {
				t.Fatal("wrong native paired-registry result", which, e)
			}
		})
	}
}
