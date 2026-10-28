package systembackupsecurity

import (
	"encoding/json"
	"testing"
	"time"
)

func testCapability(t *testing.T) (CapabilityEvidence, CapabilityPolicy) {
	t.Helper()
	var examples struct {
		Evidence CapabilityEvidence `json:"capability_evidence"`
	}
	if err := json.Unmarshal(readContractFixture(t, "a-owned-redacted-examples.json"), &examples); err != nil {
		t.Fatal(err)
	}
	e := examples.Evidence
	return e, CapabilityPolicy{Now: time.Date(2026, 9, 20, 1, 11, 0, 0, time.UTC), MaxValidity: 5 * time.Minute, ValidUntil: time.Date(2026, 9, 20, 1, 15, 0, 0, time.UTC), Role: e.Role, IdentityHash: e.IdentityHash, RefVersion: e.RefVersion, ScopeHash: e.ScopeHash}
}

func TestCapabilityRoleMappingAndExpiry(t *testing.T) {
	e, p := testCapability(t)
	if err := ValidateCapabilityEvidence(e, p); err != nil {
		t.Fatal(err)
	}
	var mapping struct {
		Codes map[string][]string `json:"codes_by_role"`
	}
	if err := json.Unmarshal(readContractFixture(t, "a-capability-role-mapping.json"), &mapping); err != nil {
		t.Fatal(err)
	}
	if len(mapping.Codes) != len(capabilityCodes) {
		t.Fatal("role set differs")
	}
	for role, codes := range mapping.Codes {
		if len(codes) != len(capabilityCodes[role]) {
			t.Fatal("code set differs", role)
		}
		for _, code := range codes {
			if !contains(capabilityCodes[role], code) {
				t.Fatal("code missing", role, code)
			}
			entry, policy := testCapability(t)
			entry.Role = role
			policy.Role = role
			entry.Capabilities = entry.Capabilities[:1]
			entry.Capabilities[0].Code = code
			if err := ValidateCapabilityEvidence(entry, policy); err != nil {
				t.Fatal(role, code, err)
			}
		}
	}
}

func TestCapabilityRejectsUntrustedOrStaleObservations(t *testing.T) {
	for _, kind := range []string{"duplicate", "wrong_role", "unknown_code", "expired", "expiry_equal_now", "extend_credential", "extend_ttl", "before_probe", "after_probe", "future_cleanup", "identity", "version", "scope", "raw_material", "cleanup_missing", "false_supported"} {
		t.Run(kind, func(t *testing.T) {
			e, p := testCapability(t)
			switch kind {
			case "duplicate":
				e.Capabilities = append(e.Capabilities, e.Capabilities[0])
			case "wrong_role":
				e.Capabilities[0].Code = "generate_data_key"
			case "unknown_code":
				e.Capabilities[0].Code = "unknown_capability"
			case "expired":
				e.Capabilities[0].ExpiresAt = "2026-09-20T01:10:59Z"
			case "expiry_equal_now":
				e.Capabilities[0].ExpiresAt = "2026-09-20T01:11:00Z"
			case "extend_credential":
				p.ValidUntil = p.ValidUntil.Add(-time.Second)
			case "extend_ttl":
				p.MaxValidity = time.Minute
			case "before_probe":
				e.Capabilities[0].CheckedAt = "2026-09-20T01:09:59Z"
			case "after_probe":
				e.Capabilities[0].CheckedAt = "2026-09-20T01:10:05Z"
			case "future_cleanup":
				e.Cleanup.VerifiedAt = "2026-09-20T01:11:01Z"
			case "identity":
				p.IdentityHash = testHash
			case "version":
				p.RefVersion = "different-version"
			case "scope":
				p.ScopeHash = testHash
			case "raw_material":
				e.Redaction.RawMaterial = true
			case "cleanup_missing":
				e.Cleanup.Removed = false
			case "false_supported":
				e.Capabilities[0].Reason = "probe_failed"
			}
			if err := ValidateCapabilityEvidence(e, p); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestCapabilityStatusReasonMatrix(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Status string `json:"status"`
			Reason string `json:"reason_code"`
			Valid  bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readContractFixture(t, "a-capability-status-reason-vectors.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 27 {
		t.Fatal("incomplete status/reason matrix")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Status+"/"+tc.Reason, func(t *testing.T) {
			e, p := testCapability(t)
			e.Capabilities[0].Status, e.Capabilities[0].Reason = tc.Status, tc.Reason
			if err := ValidateCapabilityEvidence(e, p); (err == nil) != tc.Valid {
				t.Fatalf("valid=%v, got %v", tc.Valid, err)
			}
		})
	}
}
