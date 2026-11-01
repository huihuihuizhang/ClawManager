package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Public bytes authenticated against the original complete capture. This is
// inert data, not a task claim or permission to send/sign. The current owner
// must separately authenticate the original evidence/native storage receipt.
type originalPublicationCaptureCertificate struct {
	bytes                 []byte
	sha256, captureSHA256 string
	issued, expires       time.Time
}

type originalCaptureCertificateEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature struct {
		Algorithm  string `json:"algorithm"`
		Purpose    string `json:"key_purpose"`
		KeyID      string `json:"key_id"`
		KeyVersion string `json:"key_version"`
		Domain     string `json:"domain_separator"`
		Header     string `json:"protected_header"`
		Value      string `json:"value"`
	} `json:"signature"`
}

// Checking a typed round trip rejects Go's case-insensitive JSON aliases and
// absent zero-valued fields. The authenticated ORIGINAL bytes are still kept;
// this reconstructed JSON is only compared, never substituted or returned.
func decodeOriginalCaptureCertificateEnvelope(raw []byte) (originalCaptureCertificateEnvelope, bool) {
	var envelope originalCaptureCertificateEnvelope
	if len(raw) == 0 || len(raw) > 16<<10 || decodeProviderDeploymentJSON(raw, &envelope) != nil {
		return envelope, false
	}
	canonical, err := ce.Canonical(envelope)
	return envelope, err == nil && bytes.Equal(canonical, raw)
}

// Validate an already signed ORIGINAL record for current forward use without
// regenerating its issued_at, expires_at, signing key, payload or signature.
// `now` and `original` must come from the caller's current original SQL guard.
// This does not recover a provider-unknown signature or authorize re-signing.
// Historical committed-artifact DR has a separate artifact-time policy; this
// forward-use expiry check must not be presented as a DR expiry rule.
func validateOriginalPublicationCaptureCertificate(raw []byte, capture publicationVerifiedCapture, original publicationCertificateSQLFacts, now time.Time, history *security.ArtifactSigningKeyHistory) (originalPublicationCaptureCertificate, error) {
	var zero originalPublicationCaptureCertificate
	jobs, checkpoints, err := publicationCertificateParts(capture)
	if err != nil || len(raw) == 0 || len(raw) > 16<<10 || history == nil || now.IsZero() || original.completed.IsZero() || original.completed.After(now) || original.ttl < 3600 || original.ttl > 86400 || original.stage.owner.Resource == "" || !formalCandidateDigest(original.locationHash) {
		return zero, c.ErrExecutionRecord
	}
	// Retain a detached copy of the exact authenticated bytes. Neither JSON
	// round-tripping nor a new canonical envelope replaces the original record.
	raw = bytes.Clone(raw)
	sum, err := history.VerifyPublicationRecord(raw, security.ArtifactSigningTask{BackupPublicID: capture.Input.TaskPublicID, AttemptNo: int64(capture.Input.CaptureAttemptNo)}, "capture_certificate")
	if err != nil || sum != hash(raw) {
		return zero, c.ErrExecutionRecord
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(raw)
	var payload publicationCaptureCertificatePayload
	if !closed || decodeProviderDeploymentJSON(envelope.Payload, &payload) != nil || payload.IssuedAt.Before(original.completed) || payload.IssuedAt.After(now) || !now.Before(payload.ExpiresAt) {
		return zero, c.ErrExecutionRecord
	}
	expected := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, Fence: strconv.FormatUint(capture.Input.CaptureEpoch, 10), Context: capture.CaptureContextSHA256, Jobs: jobs, Checkpoints: checkpoints, Stages: []publicationCertificateStage{{UID: original.stage.owner.Resource, Location: original.locationHash}}, CompletedAt: original.completed, IssuedAt: payload.IssuedAt, ExpiresAt: payload.IssuedAt.Add(time.Duration(original.ttl) * time.Second), SigningKey: payload.SigningKey}
	canonical, err := ce.Canonical(expected)
	if err != nil || !bytes.Equal(envelope.Payload, canonical) {
		return zero, c.ErrExecutionRecord
	}
	return originalPublicationCaptureCertificate{bytes: raw, sha256: sum, captureSHA256: capture.receipt.sha256, issued: payload.IssuedAt, expires: payload.ExpiresAt}, nil
}

func (record originalPublicationCaptureCertificate) checked(capture publicationVerifiedCapture, now time.Time) bool {
	return capture.checked() && len(record.bytes) > 0 && record.sha256 == hash(record.bytes) && record.captureSHA256 == capture.receipt.sha256 && !now.IsZero() && !now.Before(record.issued) && now.Before(record.expires)
}
