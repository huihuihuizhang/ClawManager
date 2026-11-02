package systembackupkekadapter

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	kms "clawreef/internal/systembackupkms"
)

func TestVaultPermissionObserverRejectsUnknownFieldsAndSyntheticSuccess(t *testing.T) {
	role := VaultPermissionRole{AuthMount: "backup-jwt", Role: "worker", Policy: "generate", Audience: "clawmanager-backup-worker", Namespace: "backup", ServiceAccountName: "worker", ServiceAccountUID: "actual-sa"}
	raw, err := VaultJWTAuthRole(role)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"token_type", "token_no_default_policy", "bound_claims", "claim_mappings", "token_ttl", "user_claim_json_pointer"} {
		var values map[string]json.RawMessage
		json.Unmarshal(raw, &values)
		delete(values, key)
		bad, _ := json.Marshal(values)
		if validateVaultRole(bad, role) == nil {
			t.Fatal("missing actual role fact admitted", key)
		}
	}
	var values map[string]json.RawMessage
	json.Unmarshal(raw, &values)
	values["Token_Type"] = []byte(`"service"`)
	bad, _ := json.Marshal(values)
	if validateVaultRole(bad, role) == nil {
		t.Fatal("case alias changed actual provider policy")
	}
	if vaultExactFields([]byte(`{"data":{},"Data":{}}`), []string{"data"}, []string{"data"}) {
		t.Fatal("ambiguous metadata envelope admitted")
	}
	if _, err := NewVaultPermissionObserver(VaultPermissionObserverConfig{}); err == nil {
		t.Fatal("empty source manufactured observer")
	}
	if _, err := (*VaultPermissionObserver)(nil).Observe(context.Background()); err == nil {
		t.Fatal("nil source manufactured real observation")
	}
	if payloadEncoding := VaultTransitKeyPayload(); !strings.Contains(string(payloadEncoding), `"derived":true`) {
		t.Fatal("installation key lost derived context")
	}
}

// The operator opts in with an ACTUAL installed, persistent, SAN/TLS Vault and
// independently prepared read-only observer material. This performs no SQL,
// signing, Generate, Unwrap, policy writes or bootstrap admission. Passing this
// test proves real permission metadata observation only, never a backup task.
func TestVaultPermissionObserverInstalledProvider(t *testing.T) {
	path := os.Getenv("A_VAULT_PERMISSION_OBSERVER_CONFIG")
	if path == "" {
		t.Skip("requires real installation-owned Vault observer material")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 262144 {
		t.Fatal("private actual Vault observer config unavailable")
	}
	var cfg VaultPermissionObserverConfig
	if strictPermitIssuerJSON(raw, &cfg) != nil {
		t.Fatal("actual Vault observer config invalid")
	}
	observer, err := NewVaultPermissionObserver(cfg)
	if err != nil {
		t.Fatal("actual Vault observer constructor rejected")
	}
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	actual, err := observer.Observe(ctx)
	if err != nil || actual == nil || actual.generate.Operation != kms.Generate || actual.unwrap.Operation != kms.Unwrap || actual.generate.Permission.ControllerVerifier != nil || actual.unwrap.Permission.ControllerVerifier == nil {
		t.Fatal("actual installed Vault permission readback rejected")
	}
}
