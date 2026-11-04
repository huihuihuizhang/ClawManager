package install

import (
	"encoding/json"
	"testing"
)

func TestOriginalC1DedicatedKeyRejectsMissingOrExpandedNativeMetadata(t *testing.T) {
	model := func() map[string]any {
		return map[string]any{"name": "sbk-c1-evidence-model", "type": "aes256-gcm96", "derived": true, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "convergent_encryption": false, "latest_version": 1, "min_encryption_version": 0, "min_decryption_version": 1, "keys": map[string]any{"1": 1700000000}}
	}
	raw, _ := json.Marshal(model())
	if !originalC1DedicatedKey(raw, "sbk-c1-evidence-model") {
		t.Fatal("exact model refused")
	}
	for _, field := range []string{"derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "convergent_encryption", "latest_version", "min_encryption_version", "min_decryption_version", "keys"} {
		missing := model()
		delete(missing, field)
		raw, _ := json.Marshal(missing)
		if originalC1DedicatedKey(raw, "sbk-c1-evidence-model") {
			t.Fatal("missing provider field accepted", field)
		}
	}
	for _, field := range []string{"exportable", "allow_plaintext_backup", "deletion_allowed", "convergent_encryption"} {
		bad := model()
		bad[field] = true
		raw, _ := json.Marshal(bad)
		if originalC1DedicatedKey(raw, "sbk-c1-evidence-model") {
			t.Fatal("expanded key accepted", field)
		}
	}
	bad := model()
	bad["keys"] = map[string]any{"1": 1, "2": 2}
	raw, _ = json.Marshal(bad)
	if originalC1DedicatedKey(raw, "sbk-c1-evidence-model") {
		t.Fatal("foreign version accepted")
	}
}
