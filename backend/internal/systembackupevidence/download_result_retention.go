package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const downloadResultRetentionKeySQL = `SELECT operation_id FROM system_backup_v2_download_result_receipts WHERE operation_id=? FOR UPDATE`
const downloadResultRetentionInsertSQL = `INSERT INTO system_backup_v2_download_result_receipts
(operation_id,origin_installation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,result_audit_id,result_size_bytes,result_sha256,result_at,retain_until)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`
const downloadResultRetentionReadSQL = `SELECT operation_id,origin_installation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,result_audit_id,result_size_bytes,result_sha256,result_at,retain_until
FROM system_backup_v2_download_result_receipts WHERE operation_id=? AND schema_version='system-backup-evidence-download-result.v1' FOR UPDATE`

// Lock the unique result slot at L3, before owner/ref and audit locks. A result
// is one independent attempt; even an existing identical row cannot be replayed.
func lockDownloadResultRetention(ctx context.Context, tx *sql.Tx, c *CommittedDownloadAdmission) error {
	var id int64
	if err := tx.QueryRowContext(ctx, downloadResultRetentionKeySQL, c.rows.operationID).Scan(&id); !errors.Is(err, sql.ErrNoRows) {
		return ErrAudit
	}
	return nil
}

type downloadResultRetention struct {
	operationID, evidenceID, intentID, resultID, size         int64
	installation, operationPublicID, evidencePublicID, digest string
	at, retain                                                time.Time
}

func resultRetention(c *CommittedDownloadAdmission, id int64, body []byte, at time.Time) downloadResultRetention {
	return downloadResultRetention{
		operationID: c.rows.operationID, evidenceID: c.rows.evidenceID, intentID: c.intentAuditID, resultID: id, size: int64(len(body)),
		installation: c.rows.receipt.Installation, operationPublicID: c.operationID, evidencePublicID: c.record.Manifest.Identity.ID,
		digest: hash(body), at: at, retain: c.rows.retainUntil,
	}
}

// This immutable link has FK RESTRICT anchors to both the exact admission
// retention group and the actual result audit INSERT ID. Generic audit GC can
// no longer delete a linked result while the group is retained. The separate
// reviewed group GC must check all later holds/refs before removing this link.
func (r downloadResultRetention) insert(ctx context.Context, tx *sql.Tx) error {
	if !downloadAdmissionOne(tx.ExecContext(ctx, downloadResultRetentionInsertSQL,
		r.operationID, r.installation, r.operationPublicID, r.evidenceID, r.evidencePublicID, r.intentID, r.resultID, r.size, r.digest, r.at, r.retain)) {
		return ErrAudit
	}
	return r.verify(ctx, tx)
}

func (r downloadResultRetention) verify(ctx context.Context, tx *sql.Tx) error {
	var stored downloadResultRetention
	if tx.QueryRowContext(ctx, downloadResultRetentionReadSQL, r.operationID).Scan(
		&stored.operationID, &stored.installation, &stored.operationPublicID, &stored.evidenceID, &stored.evidencePublicID,
		&stored.intentID, &stored.resultID, &stored.size, &stored.digest, &stored.at, &stored.retain) != nil ||
		stored.operationID != r.operationID || stored.installation != r.installation || stored.operationPublicID != r.operationPublicID ||
		stored.evidenceID != r.evidenceID || stored.evidencePublicID != r.evidencePublicID || stored.intentID != r.intentID ||
		stored.resultID != r.resultID || stored.size != r.size || stored.digest != r.digest || !stored.at.Equal(r.at) || !stored.retain.Equal(r.retain) {
		return ErrAudit
	}
	return nil
}
