package systembackupbootstrapsecurity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The expected set comes from the existing independent SecretRef schema,
// not the decoder's capability table. This checks descriptor syntax only;
// successful decoding grants no deployment or resource authority.
func TestSecurityReferenceCombinedEvidenceCapabilitiesFollowExistingSchema(t *testing.T) {
	type constraint struct {
		Const string   `json:"const"`
		Enum  []string `json:"enum"`
	}
	type node struct {
		Properties map[string]constraint `json:"properties"`
		AllOf      []struct {
			If struct {
				Properties map[string]constraint `json:"properties"`
			} `json:"if"`
			Then struct {
				Properties map[string]constraint `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
	}
	var schema struct {
		Definitions map[string]struct {
			AllOf []json.RawMessage `json:"allOf"`
		} `json:"$defs"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "secret-ref.schema.json"))
	if err != nil || json.Unmarshal(raw, &schema) != nil {
		t.Fatal("original SecretRef contract unavailable", err)
	}
	var body node
	bodies := 0
	for _, raw := range schema.Definitions["ProviderCredentialRef"].AllOf {
		var candidate node
		if json.Unmarshal(raw, &candidate) != nil {
			t.Fatal("original credential contract malformed")
		}
		if len(candidate.Properties["credential_capability"].Enum) != 0 {
			body = candidate
			bodies++
		}
	}
	if bodies != 1 {
		t.Fatal("original credential capability definition changed")
	}
	contains := func(values []string, want string) bool {
		for _, value := range values {
			if value == want {
				return true
			}
		}
		return false
	}
	allows := func(c constraint, value string) bool {
		return c.Const != "" && c.Const == value || contains(c.Enum, value)
	}
	capabilities := body.Properties["credential_capability"].Enum
	expected := make(map[string]bool, len(capabilities))
	for _, capability := range capabilities {
		expected[capability] = true
	}
	clauses := 0
	for _, clause := range body.AllOf {
		if !allows(clause.If.Properties["purpose"], "evidence_read_write") {
			continue
		}
		limit, exists := clause.Then.Properties["credential_capability"]
		if !exists {
			continue
		}
		clauses++
		for capability, allowed := range expected {
			expected[capability] = allowed && allows(limit, capability)
		}
	}
	accepted := 0
	for _, allowed := range expected {
		if allowed {
			accepted++
		}
	}
	if clauses == 0 || accepted == 0 || accepted == len(capabilities) {
		t.Fatal("original combined-evidence restriction missing or vacuous")
	}
	for _, capability := range capabilities {
		t.Run(capability, func(t *testing.T) {
			fields := refFixture()
			delete(fields, "read_mode")
			fields["ref_kind"] = "evidence_credential"
			fields["purpose"] = "evidence_read_write"
			fields["provider_role"] = "evidence"
			fields["credential_capability"] = capability
			input := refBytes(t, fields)
			ref, err := DecodeSecurityReference(input, sha(input))
			if (err == nil) != expected[capability] {
				t.Fatalf("combined evidence capability %q differs from original schema: accepted=%t expected=%t", capability, err == nil, expected[capability])
			}
			if err == nil && ref.Capability() != capability {
				t.Fatal("decoder changed the original capability")
			}
		})
	}
}
