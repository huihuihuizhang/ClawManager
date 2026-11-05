package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

const originalCaptureCertificatePreparedVersion = "system-backup-original-publication-capture-certificate-prepared.v1"

// Business coordinates deliberately exclude the current publisher Pod, claim
// and clock. Changing any of them cannot create a second signing operation.
func originalCaptureCertificatePreparedID(capture publicationVerifiedCapture) string {
	return originalCaptureCertificateID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo) + "_prepared"
}

func lockOriginalCertificateTask(ctx context.Context, tx *sql.Tx, prepared *preparedPublicationCaptureCertificate) error {
	if prepared == nil || prepared.record == nil || tx == nil || ctx == nil || ctx.Err() != nil || !prepared.capture.checked() {
		return c.ErrExecutionAuthority
	}
	installation, err := prepared.record.SigningInstallationID()
	if err != nil || installation != prepared.facts.InstallationID || installation != prepared.capture.Input.InstallationID {
		return c.ErrExecutionAuthority
	}
	// Both Stage and original dispatch reach this shared entry before task X
	// and immutable evidence locks. This is synchronization, never authority.
	if err = prepared.record.LockSigningStatePrefix(ctx, tx); err != nil {
		return err
	}
	var version uint64
	if prepared == nil || tx == nil || tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status='validating' AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR UPDATE`, prepared.facts.InstallationID, prepared.facts.BackupPublicID, prepared.claim.Owner, prepared.claim.RowVersion).Scan(&version) != nil || version != prepared.claim.RowVersion {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (s *DeploymentService) originalCertificateCapacityTx(ctx context.Context, tx *sql.Tx, prepared *preparedPublicationCaptureCertificate) (int64, int64, time.Time, error) {
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, prepared.facts.InstallationID, prepared.facts.ConfigVersion, prepared.facts.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(prepared.facts.TaskDeadline) {
		return 0, 0, time.Time{}, c.ErrExecutionAuthority
	}
	return capacity, retention, now, nil
}

// A pre-existing immutable intent means preparation already happened. Neither
// absence of a signed result nor a different publisher may mint another clock.
// Legacy inner signing evidence without this business intent is also refused.
func originalCertificatePreparationAbsentTx(ctx context.Context, tx *sql.Tx, capture publicationVerifiedCapture) error {
	id := originalCaptureCertificateID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo)
	var count uint64
	// Count original business roots/chunks even when expired or unhealthy.
	// A missing root with retained children is not a fresh preparation either.
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND (LEFT(public_id,?)=? OR LEFT(public_id,10)='sev_asign_')`, capture.Input.TaskPublicID, len(id), id).Scan(&count) != nil {
		return c.ErrExecutionRecord
	}
	if count != 0 {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

type originalCaptureCertificateDispatch struct {
	Version, Installation, Backup, CaptureSHA256, PayloadSHA256 string
	Attempt                                                     uint64
}

// Commit a single send intent BEFORE invoking the external signer. Only this
// invocation's acknowledged new commit authorizes one RPC. Existing or unknown
// commits permit reads of known signed bytes and never another Sign call.
func (p *preparedPublicationCaptureCertificate) beginOriginalCertificateSign(ctx context.Context) error {
	if p == nil || p.service == nil || p.access == nil || !p.capture.checked() || len(p.payload) == 0 || p.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	s := p.service
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockOriginalCertificateTask(ctx, tx, p); err != nil {
		return err
	}
	guard, err := p.access.Bind(ctx, tx)
	if err != nil || guard.Facts() != p.facts {
		return c.ErrExecutionAuthority
	}
	if _, err = s.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), p.capture, &p.original); err != nil {
		return err
	}
	payload, err := readOriginalCertificateEvidenceBytes(ctx, tx, p.capture, originalCaptureCertificatePreparedID(p.capture), originalCaptureCertificatePreparedVersion)
	if err != nil || !bytes.Equal(payload, p.payload) {
		return c.ErrExecutionRecord
	}
	id := originalCaptureCertificateID(p.facts.InstallationID, p.facts.BackupPublicID, p.capture.Input.CaptureAttemptNo) + "_sent"
	_, err = loadPublicationMetadata(ctx, tx, p.facts.BackupPublicID, id)
	if err == nil {
		return c.ErrExecutionCommitUnknown
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var prior uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=? OR LEFT(public_id,?)=?`, id, len(id)+2, id+"_p").Scan(&prior) != nil {
		return c.ErrExecutionRecord
	}
	if prior != 0 {
		return c.ErrExecutionCommitUnknown
	}
	capacity, retention, now, err := s.originalCertificateCapacityTx(ctx, tx, p)
	if err != nil {
		return err
	}
	raw, err := ce.Canonical(originalCaptureCertificateDispatch{Version: "system-backup-original-publication-capture-certificate-dispatched.v1", Installation: p.facts.InstallationID, Backup: p.facts.BackupPublicID, CaptureSHA256: p.capture.receipt.sha256, PayloadSHA256: hash(p.payload), Attempt: p.capture.Input.CaptureAttemptNo})
	if err != nil {
		return c.ErrExecutionRecord
	}
	if err = s.stageOriginalCertificateEvidenceBytes(ctx, tx, p, id, "system-backup-original-publication-capture-certificate-dispatch-evidence.v1", raw, capacity, retention, now); err != nil {
		return err
	}
	if _, err = s.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), p.capture, &p.original); err != nil {
		return err
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
