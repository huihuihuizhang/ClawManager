package systembackupkekadapter

import (
	"bytes"
	"encoding/json"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// InspectProviderCapabilityMaterial authenticates an ORIGINAL observer's exact
// signed permission observation using the same validator as SQL preparation.
// It returns inert facts only, never PreparedCapability, a permit or an issuer.
func InspectProviderCapabilityMaterial(raw []byte, pin ProviderCapabilityPin, binding reg.Binding, operation kms.Operation, evidenceUntil, now time.Time) (ProviderCapabilityRecord, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return ProviderCapabilityRecord{}, ErrAuthorityWrite
	}
	var envelope SignedProviderCapabilityRecord
	if json.Unmarshal(raw, &envelope) != nil || !closedCapabilityMaterial(raw, envelope) {
		return ProviderCapabilityRecord{}, ErrAuthorityWrite
	}
	var record ProviderCapabilityRecord
	if json.Unmarshal(envelope.Record, &record) != nil || !closedCapabilityMaterial(envelope.Record, record) {
		return ProviderCapabilityRecord{}, ErrAuthorityWrite
	}
	return authenticateProviderCapability(capabilityEvidence{raw: raw, until: evidenceUntil}, pin, binding, operation, now)
}

func closedCapabilityMaterial(raw []byte, value any) bool {
	actual, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return false
	}
	roundtrip, err := json.Marshal(value)
	if err != nil {
		return false
	}
	expected, err := jsoncanonicalizer.Transform(roundtrip)
	return err == nil && bytes.Equal(actual, expected)
}
