package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

// Explicitly named signature/mapping DATA. Local keys and a test-local capture
// receipt exercise public-byte validation only. They are not production signer,
// capture or SQL authority and establish no successful original task.
func TestOriginalCaptureCertificatePreservesSignedBytesData(t *testing.T) {
	now := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	for _, mode := range []string{"current", "context", "stage", "completion", "ttl", "future", "expired", "missing-field", "field-alias", "outer-alias", "signature-alias", "revoked", "signature", "mutated-source"} {
		t.Run(mode, func(t *testing.T) {
			capture := publicationCertificateMappingData(t)
			capture.Input.CaptureEpoch = 17
			capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			original := publicationCertificateSQLFacts{completed: now.Add(-time.Minute), ttl: 3600, locationHash: hash([]byte("named staging location DATA"))}
			original.stage.owner.Resource = "named-original-stage-DATA"
			jobs, checkpoints, err := publicationCertificateParts(capture)
			if err != nil {
				t.Fatal(err)
			}
			var keys []security.ArtifactSigningPublicKey
			var captureKey ed25519.PrivateKey
			for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { clear(private) })
				keys = append(keys, security.ArtifactSigningPublicKey{InstallationID: capture.Input.InstallationID, Purpose: purpose, KeyID: "named-" + purpose, KeyVersion: "named-r1", PublicKey: public, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(2 * time.Hour), Revoked: mode == "revoked" && purpose == "capture_certificate"})
				if purpose == "capture_certificate" {
					captureKey = private
				}
			}
			history, err := security.NewArtifactSigningKeyHistory(capture.Input.InstallationID, keys)
			if err != nil {
				t.Fatal(err)
			}
			payload := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, Fence: strconv.FormatUint(capture.Input.CaptureEpoch, 10), Context: capture.CaptureContextSHA256, Jobs: jobs, Checkpoints: checkpoints, Stages: []publicationCertificateStage{{UID: original.stage.owner.Resource, Location: original.locationHash}}, CompletedAt: original.completed, IssuedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(3570 * time.Second), SigningKey: security.PublicationSigningKey{Purpose: "capture_certificate", KeyID: "named-capture_certificate", KeyVersion: "named-r1"}}
			switch mode {
			case "context":
				payload.Context = hash([]byte("different original capture DATA"))
			case "stage":
				payload.Stages[0].UID += "-replacement"
			case "completion":
				payload.CompletedAt = payload.CompletedAt.Add(time.Microsecond)
			case "ttl":
				payload.ExpiresAt = payload.ExpiresAt.Add(time.Second)
			case "future":
				payload.IssuedAt = now.Add(time.Second)
				payload.ExpiresAt = payload.IssuedAt.Add(time.Hour)
			case "expired":
				original.completed = now.Add(-2 * time.Hour)
				payload.CompletedAt = original.completed
				payload.IssuedAt, payload.ExpiresAt = now.Add(-time.Hour), now
			}
			body, err := ce.Canonical(payload)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing-field" {
				var fields map[string]json.RawMessage
				json.Unmarshal(body, &fields)
				delete(fields, "fencing_token")
				body, _ = ce.Canonical(fields)
			} else if mode == "field-alias" {
				body = bytes.Replace(body, []byte(`"fencing_token"`), []byte(`"FENCING_TOKEN"`), 1)
				body, _ = ce.Canonical(json.RawMessage(body))
			}
			header, _ := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": "named-r1", "kid": "named-capture_certificate", "purpose": "capture_certificate", "typ": "clawmanager.system-backup.capture_certificate.v1"})
			protected := base64.RawURLEncoding.EncodeToString(header)
			input := []byte(protected + "." + base64.RawURLEncoding.EncodeToString(body))
			signature := ed25519.Sign(captureKey, input)
			if mode == "signature" {
				signature[0] ^= 1
			}
			raw, _ := ce.Canonical(map[string]any{"payload": json.RawMessage(body), "signature": map[string]string{"algorithm": "EdDSA", "key_purpose": "capture_certificate", "key_id": "named-capture_certificate", "key_version": "named-r1", "domain_separator": "clawmanager.system-backup.capture_certificate.v1", "protected_header": protected, "value": base64.RawURLEncoding.EncodeToString(signature)}})
			if mode == "outer-alias" {
				raw = bytes.Replace(raw, []byte(`"payload"`), []byte(`"PAYLOAD"`), 1)
				raw, _ = ce.Canonical(json.RawMessage(raw))
			} else if mode == "signature-alias" {
				raw = bytes.Replace(raw, []byte(`"algorithm"`), []byte(`"ALGORITHM"`), 1)
				raw, _ = ce.Canonical(json.RawMessage(raw))
			}
			if mode == "mutated-source" {
				capture.Parts[0].CipherSHA256 = hash([]byte("different C DATA"))
			}
			record, err := validateOriginalPublicationCaptureCertificate(raw, capture, original, now, history)
			if mode != "current" {
				if err == nil {
					t.Fatal("invalid historical signed DATA accepted", mode)
				}
				return
			}
			if err != nil || !record.checked(capture, now) || !bytes.Equal(record.bytes, raw) || record.sha256 != hash(raw) || !record.issued.Equal(payload.IssuedAt) || !record.expires.Equal(payload.ExpiresAt) {
				t.Fatal("original public bytes/times were recreated or refused", err)
			}
			if !originalCertificateMatchesPreparedPayload(raw, body) || originalCertificateMatchesPreparedPayload(raw, append(bytes.Clone(body), '\n')) {
				t.Fatal("known signed record did not bind the exact prepared payload bytes")
			}
			clear(raw)
			if !record.checked(capture, now) || record.checked(capture, payload.ExpiresAt) || record.checked(capture, payload.IssuedAt.Add(-time.Nanosecond)) {
				t.Fatal("original record copy/time bounds changed")
			}
			record.bytes[0] ^= 1
			if record.checked(capture, now) {
				t.Fatal("changed retained signed bytes accepted")
			}
		})
	}
}
