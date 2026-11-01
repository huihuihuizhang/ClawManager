package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Exact public signed bytes in ORIGINAL immutable diagnostic evidence. This
// records a known signature; it does not authorize another signing operation
// when the provider result or a prior signing-input commit is unknown.
type originalCaptureCertificateDescriptor struct {
	Version, Installation, Backup, CaptureSHA256, CertificateSHA256 string
	Attempt                                                         uint64
	Bytes, Chunks                                                   int
}

type originalCaptureCertificateChunk struct {
	Version, Parent string
	Index, Count    int
	Data            []byte
}

const originalCaptureCertificateChunkBytes = 5600

func originalCaptureCertificateID(installation, backup string, attempt uint64) string {
	raw, _ := ce.Canonical([]any{"original-publication-capture-certificate.v1", installation, backup, attempt})
	return "sev_pub_cert_" + hash(raw)
}

func readOriginalCaptureCertificateBytes(ctx context.Context, tx *sql.Tx, capture publicationVerifiedCapture) ([]byte, error) {
	id := originalCaptureCertificateID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo)
	return readOriginalCertificateEvidenceBytes(ctx, tx, capture, id, "system-backup-original-publication-capture-certificate.v1")
}

func readOriginalCertificateEvidenceBytes(ctx context.Context, tx *sql.Tx, capture publicationVerifiedCapture, id, version string) ([]byte, error) {
	raw, err := loadPublicationMetadata(ctx, tx, capture.Input.TaskPublicID, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var prior uint64
			if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id IN (?,?,?,?)`, id, id+"_p0", id+"_p1", id+"_p2").Scan(&prior) != nil || prior != 0 {
				return nil, c.ErrExecutionRecord
			}
		}
		return nil, err
	}
	var root originalCaptureCertificateDescriptor
	if !capture.checked() || decodeProviderDeploymentJSON(raw, &root) != nil || root.Version != version || root.Installation != capture.Input.InstallationID || root.Backup != capture.Input.TaskPublicID || root.Attempt != capture.Input.CaptureAttemptNo || root.CaptureSHA256 != capture.receipt.sha256 || !formalCandidateDigest(root.CertificateSHA256) || root.Bytes < 1 || root.Bytes > 16<<10 || root.Chunks != (root.Bytes+originalCaptureCertificateChunkBytes-1)/originalCaptureCertificateChunkBytes {
		return nil, c.ErrExecutionRecord
	}
	canonical, err := ce.Canonical(root)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, c.ErrExecutionRecord
	}
	var body bytes.Buffer
	for index := 0; index < root.Chunks; index++ {
		raw, err := loadPublicationMetadata(ctx, tx, root.Backup, id+"_p"+strconv.Itoa(index))
		var part originalCaptureCertificateChunk
		remaining := root.Bytes - index*originalCaptureCertificateChunkBytes
		if remaining > originalCaptureCertificateChunkBytes {
			remaining = originalCaptureCertificateChunkBytes
		}
		if err != nil || decodeProviderDeploymentJSON(raw, &part) != nil || part.Version != "system-backup-original-publication-capture-certificate-chunk.v1" || part.Parent != id || part.Index != index || part.Count != root.Chunks || len(part.Data) != remaining {
			return nil, c.ErrExecutionRecord
		}
		canonical, err := ce.Canonical(part)
		if err != nil || !bytes.Equal(raw, canonical) {
			return nil, c.ErrExecutionRecord
		}
		body.Write(part.Data)
	}
	if body.Len() != root.Bytes || hash(body.Bytes()) != root.CertificateSHA256 {
		return nil, c.ErrExecutionRecord
	}
	return body.Bytes(), nil
}

// Query only. A missing known-signature record is not permission to prepare or
// sign again: the caller must first resolve its original signing-input/dispatch
// outcome. No new timestamp, key reference or signature is created here.
func (s *DeploymentService) loadOriginalPublicationCaptureCertificate(ctx context.Context, claim c.ClaimToken, attempt uint64, capture publicationVerifiedCapture) (originalPublicationCaptureCertificate, bool, error) {
	var zero originalPublicationCaptureCertificate
	if !capture.checked() || capture.Input.TaskPublicID != claim.Target.PublicID || capture.Input.CaptureAttemptNo != attempt {
		return zero, false, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, false, c.ErrExecutionAuthority
	}
	history, err := s.PublicationSigningHistory(ctx)
	if err != nil {
		return zero, false, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, false, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, false, err
	}
	original, err := s.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), capture, nil)
	if err != nil {
		return zero, false, err
	}
	raw, err := readOriginalCaptureCertificateBytes(ctx, tx, capture)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, guard.RecheckTx(ctx, tx)
	}
	if err != nil {
		return zero, false, err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return zero, false, c.ErrExecutionAuthority
	}
	record, err := validateOriginalPublicationCaptureCertificate(raw, capture, original, now, history)
	if err != nil || guard.RecheckTx(ctx, tx) != nil {
		return zero, false, c.ErrExecutionRecord
	}
	return record, true, nil
}

// The exact prepared business snapshot remains mandatory at the known-result
// write boundary. The caller has already completed the external Sign RPC;
// only bounded local signature checks and original SQL occur in this tx.
func (s *DeploymentService) storeOriginalPublicationCaptureCertificate(ctx context.Context, prepared *preparedPublicationCaptureCertificate, raw []byte) (originalPublicationCaptureCertificate, error) {
	var zero originalPublicationCaptureCertificate
	if s == nil || prepared == nil || prepared.service != s || prepared.access == nil || !prepared.capture.checked() || prepared.access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if !originalCertificateMatchesPreparedPayload(raw, prepared.payload) {
		return zero, c.ErrExecutionRecord
	}
	history, err := s.PublicationSigningHistory(ctx)
	if err != nil {
		return zero, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	guard, err := prepared.access.Bind(ctx, tx)
	if err != nil || guard.Facts() != prepared.facts {
		return zero, c.ErrExecutionAuthority
	}
	if _, err = s.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), prepared.capture, &prepared.original); err != nil {
		return zero, err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, prepared.facts.InstallationID, prepared.facts.ConfigVersion, prepared.facts.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(prepared.facts.TaskDeadline) {
		return zero, c.ErrExecutionAuthority
	}
	record, err := validateOriginalPublicationCaptureCertificate(raw, prepared.capture, prepared.original, now, history)
	if err != nil {
		return zero, err
	}
	id := originalCaptureCertificateID(prepared.facts.InstallationID, prepared.facts.BackupPublicID, prepared.capture.Input.CaptureAttemptNo)
	if err = s.stageOriginalCertificateEvidenceBytes(ctx, tx, prepared, id, "system-backup-original-publication-capture-certificate.v1", record.bytes, capacity, retention, now); err != nil {
		return zero, err
	}
	if _, err = s.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), prepared.capture, &prepared.original); err != nil {
		return zero, err
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	return record, nil
}

func originalCertificateMatchesPreparedPayload(raw, payload []byte) bool {
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(raw)
	return closed && len(payload) > 0 && len(payload) <= 16<<10 && bytes.Equal(envelope.Payload, payload)
}

// Both prepared public payloads and known signed records use the same bounded
// immutable evidence codec. Authorization, current facts and commit remain the
// caller's responsibility; this helper performs no provider operation.
func (s *DeploymentService) stageOriginalCertificateEvidenceBytes(ctx context.Context, tx *sql.Tx, prepared *preparedPublicationCaptureCertificate, id, version string, raw []byte, capacity, retention int64, now time.Time) error {
	if prepared == nil || !prepared.capture.checked() || len(raw) == 0 || len(raw) > 16<<10 || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(prepared.facts.TaskDeadline) {
		return c.ErrExecutionRecord
	}
	count := (len(raw) + originalCaptureCertificateChunkBytes - 1) / originalCaptureCertificateChunkBytes
	write := func(evidence string, body []byte) error {
		old, err := loadPublicationMetadata(ctx, tx, prepared.facts.BackupPublicID, evidence)
		if err == nil {
			if !bytes.Equal(old, body) {
				return errPublicationConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)) != nil {
			return c.ErrExecutionAuthority
		}
		return registerPublicationMetadata(ctx, tx, prepared.facts.InstallationID, prepared.facts.BackupPublicID, evidence, body, now.Add(time.Duration(retention)*time.Second))
	}
	for index := 0; index < count; index++ {
		end := (index + 1) * originalCaptureCertificateChunkBytes
		if end > len(raw) {
			end = len(raw)
		}
		body, err := ce.Canonical(originalCaptureCertificateChunk{Version: "system-backup-original-publication-capture-certificate-chunk.v1", Parent: id, Index: index, Count: count, Data: raw[index*originalCaptureCertificateChunkBytes : end]})
		if err != nil || len(body) > 8192 {
			return c.ErrExecutionRecord
		}
		if err = write(id+"_p"+strconv.Itoa(index), body); err != nil {
			return err
		}
	}
	body, err := ce.Canonical(originalCaptureCertificateDescriptor{Version: version, Installation: prepared.facts.InstallationID, Backup: prepared.facts.BackupPublicID, CaptureSHA256: prepared.capture.receipt.sha256, CertificateSHA256: hash(raw), Attempt: prepared.capture.Input.CaptureAttemptNo, Bytes: len(raw), Chunks: count})
	if err != nil {
		return err
	}
	if err = write(id, body); err != nil {
		return err
	}
	readback, err := readOriginalCertificateEvidenceBytes(ctx, tx, prepared.capture, id, version)
	if err != nil || !bytes.Equal(readback, raw) {
		return c.ErrExecutionRecord
	}
	return nil
}
