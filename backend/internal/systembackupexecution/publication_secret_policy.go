package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
)

// Manifest inputs from the original independent policy and complete C reader.
// This DTO grants no source access and retains no Secret values.
type publicationSecretPolicySummary struct {
	RegistryVersion string `json:"registry_version"`
	RegistrySHA256  string `json:"registry_hash"`
	RequiredEntries int64  `json:"required_entries"`
	CapturedEntries int64  `json:"captured_entries"`
}

func publicationSecretPolicyFacts(capture publicationVerifiedCapture) (publicationSecretPolicySummary, error) {
	var zero publicationSecretPolicySummary
	if !capture.checked() {
		return zero, c.ErrExecutionRecord
	}
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(capture.Input.SourceSnapshot, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.Secrets.SecretPolicy == nil {
		return zero, c.ErrExecutionRecord
	}
	var part *publicationVerifiedPart
	for index := range capture.Parts {
		if capture.Parts[index].Operation == "capture-secret-bundle" {
			if part != nil {
				return zero, c.ErrExecutionRecord
			}
			part = &capture.Parts[index]
		}
	}
	if part == nil || part.RequestedPart != "secret_bundle" {
		return zero, c.ErrExecutionRecord
	}
	return derivePublicationSecretPolicySummary(capture.Input.ConfigSnapshot, metadata.Secrets, part.Counts)
}

// Pure consistency checks on inert parser observations. Only the wrapper above
// accepts the private complete-current-C receipt; this helper creates none.
func derivePublicationSecretPolicySummary(config []byte, spec worker.ResourceCaptureSpec, count ownedPayloadCounts) (publicationSecretPolicySummary, error) {
	var zero publicationSecretPolicySummary
	policy := spec.SecretPolicy
	version, sha, err := originalSecretPolicyConfigPin(config)
	if err != nil || policy == nil || spec.Part != "secret_bundle" || version != policy.Policy.RegistryVersion || sha != policy.SHA256 || policy.ValidateSelections(spec.Namespace, spec.Selections) != nil {
		return zero, c.ErrExecutionRecord
	}
	coverage := count.SecretPolicy
	if count.Version != "system-backup-inert-payload-counts.v1" || count.Kind != "kubernetes_captured_json_bytes" || !count.Complete || count.Items < 0 || count.Items > 10000 || count.ContentBytes < 0 || count.ArchiveEntries != 0 || len(count.SQLTables) != 0 || coverage == nil || coverage.Version != "system-backup-secret-policy-coverage.v1" || !coverage.Complete || coverage.RegistryVersion != version || coverage.RegistrySHA256 != sha || coverage.RequiredEntries != policy.RequiredEntries() || coverage.CapturedEntries != count.Items || coverage.CapturedEntries != int64(len(spec.Selections)) {
		return zero, c.ErrExecutionRecord
	}
	// Required entries were checked individually against selections before GET,
	// and each selected object was checked on capture AND full archive readback.
	// A count comparison alone cannot establish per-entry coverage.
	return publicationSecretPolicySummary{version, sha, coverage.RequiredEntries, coverage.CapturedEntries}, nil
}
