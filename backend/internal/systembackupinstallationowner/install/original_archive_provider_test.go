package install

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	adapter "clawreef/internal/systembackupkekadapter"
)

// Native response parser regressions only; these do not authenticate Installer,
// SQL gate, Kubernetes, provider permissions, a physical hold or a field copy.
func originalArchiveTokenFixture() map[string]any {
	return map[string]any{"auth": map[string]any{
		"client_token": "native-batch-token-model-1234567890", "token_type": "batch",
		"renewable": false, "lease_duration": int64(5), "policies": []string{"original-evidence-wrap"},
		"token_policies": []string{"original-evidence-wrap"}, "identity_policies": []string{},
		"metadata": map[string]any{"role": "original-wrap"}}}
}

func TestOriginalArchiveProviderRejectsExpandedNativeToken(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(map[string]any)
	}{
		{"renewable", func(a map[string]any) { a["renewable"] = true }},
		{"null-renewable", func(a map[string]any) { a["renewable"] = nil }},
		{"default-policy", func(a map[string]any) { a["policies"] = []string{"original-evidence-wrap", "default"} }},
		{"identity-policy", func(a map[string]any) { a["identity_policies"] = []string{"added-permission"} }},
		{"service-token", func(a map[string]any) { a["token_type"] = "service" }},
		{"long-ttl", func(a map[string]any) { a["lease_duration"] = 21 }},
		{"different-role", func(a map[string]any) { a["metadata"] = map[string]any{"role": "other"} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			body := originalArchiveTokenFixture()
			change.apply(body["auth"].(map[string]any))
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			secret, _, err := originalArchiveBatchToken(raw, "original-wrap", "original-evidence-wrap")
			defer clear(secret)
			if err == nil {
				t.Fatal("expanded/ambiguous native token accepted")
			}
		})
	}
}

func TestOriginalArchiveProviderPreservesOnlyExactBatchRole(t *testing.T) {
	raw, err := json.Marshal(originalArchiveTokenFixture())
	if err != nil {
		t.Fatal(err)
	}
	secret, ttl, err := originalArchiveBatchToken(raw, "original-wrap", "original-evidence-wrap")
	defer clear(secret)
	if err != nil || string(secret) != "native-batch-token-model-1234567890" || ttl != 5*time.Second {
		t.Fatal("exact native batch response rejected")
	}
	duplicate := strings.Replace(string(raw), `"renewable":false`, `"renewable":true,"renewable":false`, 1)
	if _, _, err := originalArchiveBatchToken([]byte(duplicate), "original-wrap", "original-evidence-wrap"); err == nil {
		t.Fatal("duplicate privilege field accepted")
	}
}

func TestOriginalArchiveProviderStopWaitsForActualCopyReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &OriginalAdoptionArchiveProvider{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	p.origin = p
	p.used.Store(true)
	bounded, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if p.Stop(bounded) == nil {
		t.Fatal("pending copy was acknowledged stopped")
	}
	if ctx.Err() == nil {
		t.Fatal("original copy cancellation not dispatched")
	}
	close(p.done)
	if p.Stop(context.Background()) != nil {
		t.Fatal("actual completed copy was not acknowledged")
	}
}

func TestOriginalArchiveProviderNativeLoginBindsActualPodAndSA(t *testing.T) {
	body := originalArchiveTokenFixture()
	metadata := body["auth"].(map[string]any)["metadata"].(map[string]any)
	metadata["pod_uid"], metadata["namespace"], metadata["service_account_uid"] = "original-pod", "original-system", "original-sa"
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	role := adapter.VaultPermissionRole{Role: "original-wrap", Namespace: "original-system", ServiceAccountUID: "original-sa"}
	if originalArchiveLoginIdentity(raw, "original-pod", role) != nil {
		t.Fatal("exact mapped original identity rejected")
	}
	if originalArchiveLoginIdentity(raw, "replacement-pod", role) == nil {
		t.Fatal("replacement Pod could borrow original token")
	}
	role.ServiceAccountUID = "replacement-sa"
	if originalArchiveLoginIdentity(raw, "original-pod", role) == nil {
		t.Fatal("replacement SA could borrow original token")
	}
}
