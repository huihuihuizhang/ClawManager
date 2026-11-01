package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

// Public signature/clock DATA only. SQL original facts are explicitly modeled,
// no production claim or remote C receipt is created by this fixture.
func postCCertificateClockData(t *testing.T) (publicationVerifiedCapture, originalPublicationCaptureCertificate, []security.ArtifactSigningPublicKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	capture := publicationCertificateMappingData(t)
	capture.Input.CaptureEpoch = 17
	capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
	original := publicationCertificateSQLFacts{completed: now.Add(-time.Hour), ttl: 3600, locationHash: hash([]byte("clock-only original stage DATA"))}
	original.stage.owner.Resource = "original-clock-stage-DATA"
	jobs, checkpoints, err := publicationCertificateParts(capture)
	if err != nil {
		t.Fatal(err)
	}
	var keys []security.ArtifactSigningPublicKey
	var signer ed25519.PrivateKey
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(private) })
		keys = append(keys, security.ArtifactSigningPublicKey{InstallationID: capture.Input.InstallationID, Purpose: purpose, KeyID: "clock-" + purpose, KeyVersion: "r1", PublicKey: public, NotBefore: now.Add(-3 * time.Hour), NotAfter: now.Add(3 * time.Hour)})
		if purpose == "capture_certificate" {
			signer = private
		}
	}
	issued := now.Add(-3599 * time.Second)
	payload := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, Fence: strconv.FormatUint(capture.Input.CaptureEpoch, 10), Context: capture.CaptureContextSHA256, Jobs: jobs, Checkpoints: checkpoints, Stages: []publicationCertificateStage{{UID: original.stage.owner.Resource, Location: original.locationHash}}, CompletedAt: original.completed, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), SigningKey: security.PublicationSigningKey{Purpose: "capture_certificate", KeyID: "clock-capture_certificate", KeyVersion: "r1"}}
	body, err := ce.Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	header, err := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": "r1", "kid": "clock-capture_certificate", "purpose": "capture_certificate", "typ": "clawmanager.system-backup.capture_certificate.v1"})
	if err != nil {
		t.Fatal(err)
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	envelope := originalCaptureCertificateEnvelope{Payload: body}
	envelope.Signature.Algorithm = "EdDSA"
	envelope.Signature.Purpose = "capture_certificate"
	envelope.Signature.KeyID = "clock-capture_certificate"
	envelope.Signature.KeyVersion = "r1"
	envelope.Signature.Domain = "clawmanager.system-backup.capture_certificate.v1"
	envelope.Signature.Header = protected
	envelope.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(protected+"."+base64.RawURLEncoding.EncodeToString(body))))
	raw, err := ce.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	history, err := security.NewArtifactSigningKeyHistory(capture.Input.InstallationID, keys)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := validateOriginalPublicationCaptureCertificate(raw, capture, original, now, history)
	if err != nil {
		t.Fatal("real public signature and original one-second remaining certificate DATA", err)
	}
	return capture, certificate, keys, now
}

func TestPostCManifestCertificateDeadlineAndSQLClockData(t *testing.T) {
	for _, mode := range []string{"certificate-earlier", "authority-earlier", "at-expiry", "after-expiry", "clock-rollback", "deadline-over-certificate", "deadline-over-authority", "zero-clock", "zero-deadline", "zero-authority", "changed-certificate-bytes", "missing-capture-data"} {
		t.Run(mode, func(t *testing.T) {
			capture, certificate, _, now := postCCertificateClockData(t)
			authority := now.Add(30 * time.Second)
			if mode == "authority-earlier" {
				authority = now.Add(500 * time.Millisecond)
			}
			deadline, err := postCManifestDeadline(authority, certificate)
			if err != nil {
				t.Fatal(err)
			}
			want := certificate.expires
			if authority.Before(want) {
				want = authority
			}
			if !deadline.Equal(want) {
				t.Fatal("deadline extended original authority or certificate")
			}
			original := bytes.Clone(certificate.bytes)
			floor := now
			switch mode {
			case "at-expiry":
				now = certificate.expires
			case "after-expiry":
				now = certificate.expires.Add(time.Microsecond)
			case "clock-rollback":
				now = now.Add(-time.Microsecond)
			case "deadline-over-certificate":
				deadline = certificate.expires.Add(time.Microsecond)
			case "deadline-over-authority":
				authority = now.Add(500 * time.Millisecond)
			case "zero-clock":
				now = time.Time{}
			case "zero-deadline":
				deadline = time.Time{}
			case "zero-authority":
				authority = time.Time{}
			case "changed-certificate-bytes":
				certificate.bytes = bytes.Clone(certificate.bytes)
				certificate.bytes[len(certificate.bytes)-1] ^= 1
			case "missing-capture-data":
				capture.receipt = nil
			}
			err = checkPostCManifestClock(now, floor, deadline, authority, certificate, capture)
			if (err == nil) != (mode == "certificate-earlier" || mode == "authority-earlier") {
				t.Fatal("SQL-clock publication boundary", mode, err)
			}
			if mode != "changed-certificate-bytes" && !bytes.Equal(original, certificate.bytes) {
				t.Fatal("clock check rewrote original signed bytes")
			}
		})
	}
}

func TestPostCManifestRechecksCurrentPublicSigningHistoryData(t *testing.T) {
	for _, mode := range []string{"current", "revoked", "replaced-key", "changed-bytes", "foreign-task", "unavailable-history"} {
		t.Run(mode, func(t *testing.T) {
			capture, certificate, keys, _ := postCCertificateClockData(t)
			task := security.ArtifactSigningTask{BackupPublicID: capture.Input.TaskPublicID, AttemptNo: int64(capture.Input.CaptureAttemptNo)}
			if mode == "revoked" {
				keys[0].Revoked = true
			}
			if mode == "replaced-key" {
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				keys[0].PublicKey = public
			}
			if mode == "changed-bytes" {
				certificate.bytes = bytes.Clone(certificate.bytes)
				certificate.bytes[len(certificate.bytes)-1] ^= 1
				certificate.sha256 = hash(certificate.bytes)
			}
			if mode == "foreign-task" {
				task.BackupPublicID = "sbk_22222222-2222-4222-8222-222222222222"
			}
			history, err := security.NewArtifactSigningKeyHistory(capture.Input.InstallationID, keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unavailable-history" {
				history = nil
			}
			err = checkPostCManifestCertificateHistory(certificate, task, history)
			if (err == nil) != (mode == "current") {
				t.Fatal("changed/revoked current public history accepted", mode, err)
			}
		})
	}
}
