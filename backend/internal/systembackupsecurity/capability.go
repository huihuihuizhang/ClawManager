package systembackupsecurity

import (
	"errors"
	"regexp"
	"time"
)

type CapabilityObservation struct {
	Code              string  `json:"capability_code"`
	Status            string  `json:"status"`
	Reason            string  `json:"reason_code"`
	RequestScopeHash  string  `json:"request_scope_hash"`
	ResponseShapeHash *string `json:"response_shape_hash"`
	CheckedAt         string  `json:"checked_at"`
	ExpiresAt         string  `json:"expires_at"`
}

type CapabilityEvidence struct {
	SchemaVersion   string                  `json:"schema_version"`
	Role            string                  `json:"provider_role"`
	IdentityHash    string                  `json:"provider_identity_hash"`
	RefVersion      string                  `json:"provider_ref_version"`
	ObservedVersion *string                 `json:"observed_provider_version"`
	StartedAt       string                  `json:"probe_started_at"`
	FinishedAt      string                  `json:"probe_finished_at"`
	ScopeHash       string                  `json:"probe_scope_hash"`
	Capabilities    []CapabilityObservation `json:"capabilities"`
	Redaction       struct {
		Applied     bool     `json:"applied"`
		Removed     []string `json:"removed_field_classes"`
		RawMaterial bool     `json:"raw_material_present"`
	} `json:"redaction"`
	Cleanup struct {
		RunID      string `json:"run_id"`
		Owner      string `json:"owner_marker"`
		Removed    bool   `json:"temporary_artifacts_removed"`
		VerifiedAt string `json:"verified_at"`
	} `json:"cleanup"`
}

// These bindings and expiry bounds come from trusted platform/config state,
// never from the submitted evidence. ValidUntil includes credential/provider
// expiry. D revalidates at persistence time and supplies registered evidence.
type CapabilityPolicy struct {
	Now                                       time.Time
	MaxValidity                               time.Duration
	ValidUntil                                time.Time
	Role, IdentityHash, RefVersion, ScopeHash string
}

var capabilityCodes = map[string][]string{
	"artifact": {"conditional_create", "checksum_bound_request", "scoped_upload_credential", "scoped_read_credential", "scoped_delete_credential", "multipart_resume", "object_checksum", "version_listing", "delete_marker_listing", "strong_read_after_write", "tls_verified"},
	"catalog":  {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_append_credential", "strong_read_after_write", "provider_snapshot_listing", "inventory_manifest_listing", "versioned_absence_proof", "tls_verified"},
	"evidence": {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_write_credential", "scoped_delete_credential", "object_checksum", "strong_read_after_write", "versioned_absence_proof", "tls_verified"},
	"kms":      {"generate_data_key", "unwrap_data_key", "identity_scope", "identity_revocation", "version_retention"},
	"secret":   {"exact_version_read", "resource_version_guard", "uid_guard", "aes256_kw", "identity_revocation"},
	"signing":  {"purpose_key_separation", "historic_verification", "key_rotation", "scoped_signer", "policy_separation"},
}

// A changed version alone does not prove deterministic API incompatibility.
// Adapters use unsupported_api only after establishing that incompatibility.
var capabilityReasons = map[string][]string{
	"supported":   {"none"},
	"unsupported": {"unsupported_api"},
	"degraded":    {"probe_failed", "provider_unavailable", "credential_unavailable", "permission_denied", "response_invalid", "version_drift", "internal"},
}

// ValidateCapabilityEvidence checks a bounded spike result. Success is not a
// signature verification, health conclusion, provider row or evidence receipt.
// Authentication of the submitting probe remains the integration owner's job.
func ValidateCapabilityEvidence(e CapabilityEvidence, p CapabilityPolicy) error {
	invalid := errors.New("capability_evidence_invalid")
	if e.SchemaVersion != "system-backup-capability-evidence.v1" || len(capabilityCodes[e.Role]) == 0 ||
		e.Role != p.Role || e.IdentityHash != p.IdentityHash || e.RefVersion != p.RefVersion || e.ScopeHash != p.ScopeHash ||
		!providerHashPattern.MatchString(e.IdentityHash) || !providerHashPattern.MatchString(e.ScopeHash) ||
		!boundedText(e.RefVersion, 1, 128) || p.Now.IsZero() || p.ValidUntil.IsZero() || p.MaxValidity <= 0 ||
		len(e.Capabilities) == 0 || len(e.Capabilities) > 64 || !e.Redaction.Applied || e.Redaction.RawMaterial || !e.Cleanup.Removed {
		return invalid
	}
	if e.ObservedVersion != nil && !boundedText(*e.ObservedVersion, 0, 128) {
		return invalid
	}
	started, err1 := time.Parse(time.RFC3339, e.StartedAt)
	finished, err2 := time.Parse(time.RFC3339, e.FinishedAt)
	cleaned, err3 := time.Parse(time.RFC3339, e.Cleanup.VerifiedAt)
	if err1 != nil || err2 != nil || err3 != nil || started.After(finished) || finished.After(cleaned) || cleaned.After(p.Now) ||
		!regexp.MustCompile(`^cap-[A-Za-z0-9._:-]{8,96}$`).MatchString(e.Cleanup.RunID) || !regexp.MustCompile(`^A:[A-Za-z0-9._:-]{4,96}$`).MatchString(e.Cleanup.Owner) {
		return invalid
	}
	removed := map[string]bool{}
	for _, class := range e.Redaction.Removed {
		if !contains([]string{"credential", "secret", "token", "private_key", "uri", "raw_response", "raw_log"}, class) || removed[class] {
			return invalid
		}
		removed[class] = true
	}
	seen := map[string]bool{}
	for _, cap := range e.Capabilities {
		checked, err1 := time.Parse(time.RFC3339, cap.CheckedAt)
		expires, err2 := time.Parse(time.RFC3339, cap.ExpiresAt)
		if !contains(capabilityCodes[e.Role], cap.Code) || seen[cap.Code] ||
			!contains(capabilityReasons[cap.Status], cap.Reason) || !providerHashPattern.MatchString(cap.RequestScopeHash) ||
			err1 != nil || err2 != nil || checked.Before(started) || checked.After(finished) || !expires.After(checked) ||
			!expires.After(p.Now) || expires.After(checked.Add(p.MaxValidity)) || expires.After(p.ValidUntil) {
			return invalid
		}
		if cap.ResponseShapeHash != nil && !providerHashPattern.MatchString(*cap.ResponseShapeHash) {
			return invalid
		}
		seen[cap.Code] = true
	}
	return nil
}
