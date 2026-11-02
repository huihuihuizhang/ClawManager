package systembackupkekadapter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

func TestVaultRuntimePlansKeepGenerateAndPublisherUnwrapSeparate(t *testing.T) {
	generate, err := VaultRuntimeACL(kms.Generate, "original-key", "7")
	unwrap, unwrapErr := VaultRuntimeACL(kms.Unwrap, "original-key", "7")
	if err != nil || unwrapErr != nil || strings.Count(generate, "path ") != 1 || !strings.Contains(generate, `path "transit/datakey/plaintext/original-key"`) || strings.Contains(generate, "decrypt/") || strings.Count(unwrap, "path ") != 1 || !strings.Contains(unwrap, `path "transit/decrypt/original-key"`) || strings.Contains(unwrap, "datakey/") || strings.Contains(generate+unwrap, `"create"`) || strings.Contains(generate+unwrap, `path "*"`) {
		t.Fatal("runtime crypto purposes or fixed paths broadened")
	}
	for _, version := range []string{"", "0", "01", "latest", "-1"} {
		if _, err := VaultRuntimeACL(kms.Generate, "original-key", version); err == nil {
			t.Fatal("nonfixed provider version admitted")
		}
	}
	if _, err := VaultRuntimeACL(kms.Generate, "key/*", "1"); err == nil {
		t.Fatal("wildcard provider path admitted")
	}
}

func TestVaultJWTRolePlansAndReadbackRejectDrift(t *testing.T) {
	worker := VaultPermissionRole{AuthMount: "backup-jwt", Role: "backup-worker", Policy: "backup-generate", Audience: "clawmanager-backup-worker", Namespace: "backup", ServiceAccountName: "worker", ServiceAccountUID: "actual-worker-sa-uid"}
	for _, tc := range []struct {
		name string
		role VaultPermissionRole
	}{{"dynamic_worker", worker}, {"fixed_publisher", VaultPermissionRole{AuthMount: "backup-jwt", Role: "backup-publisher", Policy: "backup-unwrap", Audience: "clawmanager-backup-publisher", Namespace: "backup", ServiceAccountName: "publisher", ServiceAccountUID: "actual-publisher-sa-uid", PodUID: "actual-publisher-pod-uid"}}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := VaultJWTAuthRole(tc.role)
			if err != nil || validateVaultRole(raw, tc.role) != nil {
				t.Fatal("exact desired role/readback contract disagrees", err)
			}
			for _, fault := range []struct {
				key   string
				value any
			}{{"token_type", "service"}, {"token_no_default_policy", false}, {"token_policies", []string{tc.role.Policy, "default"}}, {"policies", []string{"root"}}, {"bound_audiences", []string{"foreign"}}, {"bound_claims_type", "glob"}, {"bound_subject", "foreign"}, {"user_claim", "sub"}, {"token_ttl", 21}, {"groups_claim", "groups"}, {"clock_skew_leeway", 0}} {
				var changed map[string]any
				if json.Unmarshal(raw, &changed) != nil {
					t.Fatal("role fixture")
				}
				changed[fault.key] = fault.value
				bad, _ := json.Marshal(changed)
				if validateVaultRole(bad, tc.role) == nil {
					t.Fatal("changed actual provider role admitted", fault.key)
				}
			}
		})
	}
	observer, err := VaultObserverACL("original-key", worker, VaultPermissionRole{AuthMount: "backup-jwt", Role: "publisher", Policy: "publisher-unwrap"})
	if err != nil || strings.Contains(observer, "update") || strings.Contains(observer, "create") || strings.Contains(observer, "datakey/") || strings.Contains(observer, "transit/decrypt/") || !strings.Contains(observer, "auth/token/lookup-self") {
		t.Fatal("observer acquired crypto or write authority")
	}
}

func TestVaultJWTTrustRejectsAlternativeIssuerAndDefaultRole(t *testing.T) {
	trust := VaultJWTTrust{Issuer: "https://actual-cluster.invalid", ValidationPublicKeys: []string{"independent installation public key DATA"}, Algorithms: []string{"RS256"}}
	raw, err := VaultJWTAuthConfig(trust)
	if err != nil || validateVaultJWTTrust(raw, trust) != nil {
		t.Fatal("trust contract fixture", err)
	}
	for _, fault := range []struct {
		key   string
		value any
	}{{"bound_issuer", "https://foreign.invalid"}, {"default_role", "default"}, {"jwks_url", "https://foreign.invalid/keys"}, {"jwt_supported_algs", []string{"HS256"}}} {
		var changed map[string]any
		json.Unmarshal(raw, &changed)
		changed[fault.key] = fault.value
		bad, _ := json.Marshal(changed)
		if validateVaultJWTTrust(bad, trust) == nil {
			t.Fatal("changed current JWT trust admitted", fault.key)
		}
	}
	if _, err := (*ObservedVaultPermissions)(nil).Sign(kms.Generate, reg.SourceRecord{}, "r1", time.Time{}, nil); err == nil {
		t.Fatal("desired role configuration manufactured observed capability")
	}
}
