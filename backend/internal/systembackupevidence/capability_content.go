package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	"clawreef/internal/systembackupsecurity"
)

const MaxCapabilityContent int64 = 64 << 10

// CapabilityContentPolicy comes from the authenticated probe/registry and
// immutable task configuration. It must never be inferred from the document
// being validated. This content validator does not authenticate the producer,
// issue capability approval, or replace D's transaction-time expiry checks.
type CapabilityContentPolicy struct {
	Installation, EvidenceID, Classification           string
	Role, ProviderIdentity, ProviderVersion, ScopeHash string
	RunID, OwnerMarker                                 string
	ObservedVersion                                    *string
	MaxValidity                                        time.Duration
	ValidUntil                                         time.Time
}

// CapabilityRedactor validates already-redacted, closed-schema content; it does
// not mutate the bytes or strip unknown fields and then claim the proof valid.
// Other evidence types need their own validators and are rejected here.
type CapabilityRedactor struct{ policy CapabilityContentPolicy }

var _ Redactor = (*CapabilityRedactor)(nil)

func NewCapabilityRedactor(p CapabilityContentPolicy) (*CapabilityRedactor, error) {
	if !installationPattern.MatchString(p.Installation) || !idPattern.MatchString(p.EvidenceID) ||
		!oneOf(p.Classification, "public", "internal", "confidential", "sensitive") ||
		!oneOf(p.Role, "artifact", "catalog", "evidence", "kms", "secret", "signing") ||
		!digestPattern.MatchString(p.ProviderIdentity) || !versionPattern.MatchString(p.ProviderVersion) || !digestPattern.MatchString(p.ScopeHash) ||
		!regexp.MustCompile(`^cap-[A-Za-z0-9._:-]{8,96}$`).MatchString(p.RunID) || !regexp.MustCompile(`^A:[A-Za-z0-9._:-]{4,96}$`).MatchString(p.OwnerMarker) ||
		p.MaxValidity <= 0 || !time.Now().Before(p.ValidUntil) ||
		p.ObservedVersion != nil && !versionPattern.MatchString(*p.ObservedVersion) {
		return nil, ErrRedaction
	}
	if p.ObservedVersion != nil {
		version := *p.ObservedVersion
		p.ObservedVersion = &version
	}
	return &CapabilityRedactor{policy: p}, nil
}

func (v *CapabilityRedactor) Validate(ctx context.Context, i Identity, src io.Reader) error {
	if v == nil || src == nil || ctx.Err() != nil || !i.validExternal() || i.Type != "capability_snapshot" || i.Media != "application/json" ||
		i.Installation != v.policy.Installation || i.ID != v.policy.EvidenceID || i.Classification != v.policy.Classification ||
		i.ContentSize > MaxCapabilityContent {
		return ErrRedaction
	}
	raw, e := io.ReadAll(io.LimitReader(src, MaxCapabilityContent+1))
	defer wipe(raw)
	if e != nil || ctx.Err() != nil || int64(len(raw)) != i.ContentSize || hash(raw) != i.ContentHash || !utf8.Valid(raw) {
		return ErrRedaction
	}
	content, e := decodeCapabilityContent(raw)
	if e != nil {
		return ErrRedaction
	}
	p := v.policy
	if content.Cleanup.RunID != p.RunID || content.Cleanup.Owner != p.OwnerMarker ||
		(content.ObservedVersion == nil) != (p.ObservedVersion == nil) ||
		content.ObservedVersion != nil && *content.ObservedVersion != *p.ObservedVersion {
		return ErrRedaction
	}
	policy := systembackupsecurity.CapabilityPolicy{Now: time.Now().UTC(), MaxValidity: p.MaxValidity, ValidUntil: p.ValidUntil,
		Role: p.Role, IdentityHash: p.ProviderIdentity, RefVersion: p.ProviderVersion, ScopeHash: p.ScopeHash}
	if systembackupsecurity.ValidateCapabilityEvidence(content, policy) != nil {
		return ErrRedaction
	}
	return nil
}

// Exact field sets enforce required nullable fields and case-sensitive JSON
// names, which decoding directly into a Go struct would not enforce. The
// shared object parser rejects duplicate fields and trailing JSON at each level.
func capabilityFields(raw []byte, names []string, nullable string) (map[string]json.RawMessage, error) {
	fields, e := transitObject(raw)
	if e != nil {
		return nil, ErrRedaction
	}
	if len(fields) != len(names) {
		wipeTransitFields(fields)
		return nil, ErrRedaction
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || name != nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			wipeTransitFields(fields)
			return nil, ErrRedaction
		}
	}
	return fields, nil
}

func decodeCapabilityContent(raw []byte) (systembackupsecurity.CapabilityEvidence, error) {
	var out systembackupsecurity.CapabilityEvidence
	root, e := capabilityFields(raw, []string{"schema_version", "provider_role", "provider_identity_hash", "provider_ref_version", "observed_provider_version", "probe_started_at", "probe_finished_at", "probe_scope_hash", "capabilities", "redaction", "cleanup"}, "observed_provider_version")
	if e != nil {
		return out, e
	}
	defer wipeTransitFields(root)
	redaction, e := capabilityFields(root["redaction"], []string{"applied", "removed_field_classes", "raw_material_present"}, "")
	if e != nil {
		return out, e
	}
	defer wipeTransitFields(redaction)
	cleanup, e := capabilityFields(root["cleanup"], []string{"run_id", "owner_marker", "temporary_artifacts_removed", "verified_at"}, "")
	if e != nil {
		return out, e
	}
	defer wipeTransitFields(cleanup)
	var observations []json.RawMessage
	e = json.Unmarshal(root["capabilities"], &observations)
	defer func() {
		for _, row := range observations {
			wipe(row)
		}
	}()
	if e != nil || len(observations) < 1 || len(observations) > 64 {
		return out, ErrRedaction
	}
	for _, row := range observations {
		fields, e := capabilityFields(row, []string{"capability_code", "status", "reason_code", "request_scope_hash", "response_shape_hash", "checked_at", "expires_at"}, "response_shape_hash")
		if e != nil {
			return out, e
		}
		wipeTransitFields(fields)
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, ErrRedaction
	}
	return out, nil
}
