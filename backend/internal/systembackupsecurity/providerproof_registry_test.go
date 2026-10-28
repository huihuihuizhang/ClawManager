package systembackupsecurity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRealProviderRegistryAndStrictWireShape(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/evidence/system-backup-provider-issuer-d-issuer-d7f0a14ec84d78927620d25f.registry.json")
	if err != nil {
		t.Fatal(err)
	}
	const version = "d-issuer-d7f0a14ec84d78927620d25f"
	const digest = "c1b76a352d37cee763235c645cf82ded5e4193cb66fb12614a83c4cb950ed4a8"
	now := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	if _, err = DecodeProviderIssuerRegistry(raw, version, digest, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"missing_revoked": func(s string) string { return strings.Replace(s, `"revoked":false,`, "", 1) },
		"null_revoked":    func(s string) string { return strings.Replace(s, `"revoked":false`, `"revoked":null`, 1) },
		"case_alias":      func(s string) string { return strings.Replace(s, `"revoked":false`, `"Revoked":false`, 1) },
		"case_override": func(s string) string {
			return strings.Replace(s, `"revoked":false`, `"revoked":true,"Revoked":false`, 1)
		},
		"null_scope": func(s string) string {
			return strings.Replace(s, `"audience":"system-backup-provider-proof"`, `"audience":null`, 1)
		},
		"duplicate_escaped": func(s string) string {
			return strings.Replace(s, `"revoked":false`, `"revoked":true,"\u0072evoked":false`, 1)
		},
		"null_array": func(s string) string {
			return strings.Replace(s, `"proof_types":["provider_presence","provider_absence","ownership"]`, `"proof_types":null`, 1)
		},
		"base64_newline": func(s string) string { return strings.Replace(s, `bicNqDLJ`, `bicN\nqDLJ`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := []byte(mutate(string(raw)))
			if string(bad) == string(raw) {
				t.Fatal("mutation did not apply")
			}
			if _, err := DecodeProviderIssuerRegistry(bad, version, registrationHash(string(bad)), now); err == nil {
				t.Fatal("malformed pinned registry accepted")
			}
		})
	}
}

func TestStrictRegistryPolicyRequiresLowercaseCompleteFields(t *testing.T) {
	var policy IssuerPolicy
	good := []byte(`{"methods":["totp"],"acr":[],"amr":["otp"]}`)
	if err := decodePinnedRegistry(good, registrationHash(string(good)), &policy); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`{"Methods":["totp"],"acr":[],"amr":["otp"]}`, `{"methods":["totp"],"amr":["otp"]}`, `{"methods":["totp"],"acr":null,"amr":["otp"]}`} {
		if decodePinnedRegistry([]byte(s), registrationHash(s), &policy) == nil {
			t.Fatal("incomplete policy accepted")
		}
	}
	b, _ := json.Marshal(policy)
	if strings.Contains(string(b), "Methods") {
		t.Fatal("incorrect JSON policy field")
	}
}

func TestStrongAndRBACRegistryRejectAliasesMissingAndNull(t *testing.T) {
	strong := `{"schema_version":"system-backup-strong-auth-issuers.draft.v1","version":"v1","audience":"strong-auth","keys":[{"issuer":"mfa","key_id":"mfa-key","key_version":"1","purpose":"strong_auth_issuer","public_key_base64":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","not_before":"2026-09-24T00:00:00Z","not_after":"2026-12-23T00:00:00Z","revoked":true,"policy":{"methods":["totp"],"acr":[],"amr":["otp"]}}]}`
	rbac := `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"v1","installation_id":"installation_test","bindings":[{"actor_id":"42","subject":"user:42","role":"security_admin"}]}`
	for _, tc := range []struct {
		name, raw, field string
		value            func() any
	}{
		{"strong", strong, `"revoked":true`, func() any { return &StrongAuthIssuerRegistry{} }},
		{"rbac", rbac, `"role":"security_admin"`, func() any { return &RegistrationRBACRegistry{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := decodePinnedRegistry([]byte(tc.raw), registrationHash(tc.raw), tc.value()); err != nil {
				t.Fatal("valid profile rejected", err)
			}
			alias := `"revoked":true,"Revoked":false`
			null := `"revoked":null`
			if tc.name == "rbac" {
				alias = `"role":"viewer","Role":"security_admin"`
				null = `"role":null`
			}
			for _, replacement := range []string{alias, null, ""} {
				bad := strings.Replace(tc.raw, tc.field, replacement, 1)
				bad = strings.ReplaceAll(bad, ",,", ",")
				bad = strings.ReplaceAll(bad, ",}", "}")
				if !json.Valid([]byte(bad)) {
					t.Fatal("invalid test mutation")
				}
				if decodePinnedRegistry([]byte(bad), registrationHash(bad), tc.value()) == nil {
					t.Fatal("unsafe pinned profile accepted", tc.name)
				}
			}
		})
	}
}
