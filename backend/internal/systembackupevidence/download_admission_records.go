package systembackupevidence

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
	"time"

	"clawreef/internal/systembackupsecurity"
)

const downloadAdmissionEvidenceAnchorSQL = `SELECT id,origin_installation_id,row_version,claim_owner,claim_expires_at,protected_until,storage_state FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE`
const downloadAdmissionOperationInsertSQL = `INSERT INTO system_backup_v2_operations
(public_id,origin_installation_id,operation_type,target_type,target_public_id,download_evidence_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,
external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,retryable,failure_category,http_status,row_version,deadline_at,started_at,finished_at,created_at,updated_at)
VALUES (?,?,'evidence_download_admission','evidence',?,?,'admin',?,'getSystemBackupEvidence',?,?,?,2,?,'succeeded',FALSE,'none',200,1,?,?,?,?,?)`
const downloadAdmissionOperationReadSQL = `SELECT id FROM system_backup_v2_operations WHERE id=? AND public_id=? AND origin_installation_id=? AND schema_version='system-backup-operation.v1'
AND operation_type='evidence_download_admission' AND target_type='evidence' AND target_public_id=? AND download_evidence_id=?
AND actor_type='admin' AND actor_id=? AND endpoint='getSystemBackupEvidence' AND idempotency_key=? AND request_hash=?
AND external_action_public_ids_canonical_json=? AND external_action_public_ids_size_bytes=2 AND external_action_public_ids_sha256=?
AND status='succeeded' AND retryable=FALSE AND failure_category='none' AND failure_message IS NULL AND http_status=200
AND result_resource_public_id IS NULL AND result_config_version IS NULL AND retry_of_operation_public_id IS NULL
AND redacted_response_evidence_id IS NULL AND redacted_response_sha256 IS NULL
AND claim_owner IS NULL AND claim_expires_at IS NULL AND next_reconcile_at IS NULL AND row_version=1
AND deadline_at=? AND started_at=? AND finished_at=? AND created_at=? AND updated_at=? FOR UPDATE`
const downloadAdmissionReceiptInsertSQL = `INSERT INTO system_backup_v2_download_admission_receipts
(operation_id,origin_installation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,
receipt_canonical_json,receipt_size_bytes,receipt_sha256,operation_canonical_json,operation_size_bytes,operation_sha256,
admitted_at,claim_expires_at,deadline_at,retain_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
const downloadAdmissionReceiptReadSQL = `SELECT receipt_canonical_json,receipt_size_bytes,receipt_sha256,operation_canonical_json,operation_size_bytes,operation_sha256
FROM system_backup_v2_download_admission_receipts WHERE operation_id=? AND origin_installation_id=? AND operation_public_id=?
AND evidence_id=? AND evidence_public_id=? AND intent_audit_id=? AND schema_version='system-backup-evidence-download-admission.v1'
AND admitted_at=? AND claim_expires_at=? AND deadline_at=? AND retain_until=? FOR UPDATE`

// DownloadAdmissionRecords anchors UNCOMMITTED SQL rows to the original key,
// binding and database evidence identity. It is not proof of nonce consumption,
// physical reservation, full prelocked authority or a successful commit.
type DownloadAdmissionRecords struct {
	state                   *downloadAdmissionRecordsState
	tx                      *sql.Tx
	binding                 *DownloadAdmissionContentBinding
	operationID, evidenceID int64
	retainUntil             time.Time
}

type downloadAdmissionRecordsState struct {
	mu             sync.Mutex
	failed         bool
	nonceAttempted bool
}

func (*DownloadAdmissionRecords) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*DownloadAdmissionRecords) String() string               { return "DownloadAdmissionRecords" }
func (*DownloadAdmissionRecords) GoString() string             { return "DownloadAdmissionRecords" }

// PendingOperationDatabaseID is only an FK for the outer transaction's nonce
// INSERT, never a committed/public download capability.
func (r *DownloadAdmissionRecords) PendingOperationDatabaseID() int64 {
	if r == nil {
		return 0
	}
	return r.operationID
}

func downloadAdmissionOne(result sql.Result, err error) bool {
	if err != nil || result == nil {
		return false
	}
	n, e := result.RowsAffected()
	return e == nil && n == 1
}

func readDownloadAdmissionEvidenceAnchor(ctx context.Context, tx *sql.Tx, b *DownloadAdmissionContentBinding, retain time.Time) (int64, error) {
	var id, version int64
	var installation, claim sql.NullString
	var until, protected sql.NullTime
	var state string
	if tx.QueryRowContext(ctx, downloadAdmissionEvidenceAnchorSQL, b.receipt.EvidenceID).Scan(&id, &installation, &version, &claim, &until, &protected, &state) != nil ||
		id < 1 || !installation.Valid || installation.String != b.receipt.Installation || version != b.receipt.EvidenceRowVersion || state != "ready" ||
		!claim.Valid || hash([]byte(claim.String)) != b.receipt.ClaimSHA256 || !until.Valid || !until.Time.Equal(b.receipt.ClaimExpiresAt) ||
		protected.Valid && (!downloadAdmissionContentTime(protected.Time) || protected.Time.After(retain)) {
		return 0, ErrDownloadAdmissionNotReady
	}
	return id, nil
}

// StageDownloadAdmissionRecords writes only Operation and immutable private/
// public bytes. D must already have the common prefix, current authorization,
// owner/ref/nonce locks, a real capacity reservation, original intent audit and
// successful evidence claim CAS. retainUntil must come from D's frozen complete
// retention policy, not HTTP or payload length. Every error requires rollback
// of the WHOLE outer transaction; this helper neither commits nor saves a
// failure receipt. No provider access or independent nonce transaction occurs.
func StageDownloadAdmissionRecords(ctx context.Context, tx *sql.Tx, key *DownloadAdmissionKeyLock, b *DownloadAdmissionContentBinding, current Record, retainUntil time.Time) (*DownloadAdmissionRecords, error) {
	if key == nil || key.state == nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	key.state.mu.Lock()
	defer key.state.mu.Unlock()
	if key.state.failed || key.state.staged {
		return nil, ErrDownloadAdmissionNotReady
	}
	key.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || b == nil || key.tx != tx || b.tx != tx || key.operationID != b.operation.OperationID || !sameDownloadAdmissionActor(key.actor, b.actor) ||
		key.request.InstallationID() != b.receipt.Installation || key.request.RequestHash() != b.receipt.RequestHash || key.request.IdempotencyKey() != b.operation.IdempotencyKey ||
		!key.proof.SameAdmissionVerification(b.proof) ||
		b.receipt.AdmittedAt.Before(key.observedAt) || !downloadAdmissionContentTime(retainUntil) || !retainUntil.After(b.receipt.ClaimExpiresAt) || !retainUntil.After(b.proof.ProofExpiresAt()) ||
		b.Recheck(ctx, tx, key.actor, current) != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	evidenceID, err := readDownloadAdmissionEvidenceAnchor(ctx, tx, b, retainUntil)
	if err != nil {
		return nil, err
	}
	o := b.operation
	empty := []byte("[]")
	result, err := tx.ExecContext(ctx, downloadAdmissionOperationInsertSQL, o.OperationID, o.Installation, o.EvidenceID, evidenceID, strconv.FormatInt(o.ActorID, 10), o.IdempotencyKey, o.RequestHash,
		empty, hash(empty), o.DeadlineAt, o.AdmittedAt, o.AdmittedAt, o.AdmittedAt, o.AdmittedAt)
	if !downloadAdmissionOne(result, err) {
		return nil, ErrDownloadAdmissionNotReady
	}
	operationID, err := result.LastInsertId()
	if err != nil || operationID < 1 {
		return nil, ErrDownloadAdmissionNotReady
	}
	r := b.receipt
	private, public := b.ReceiptJSON(), b.OperationJSON()
	if VerifyDownloadAdmissionContent(private, public, hash(private), hash(public), int64(len(private)), int64(len(public)), r, o) != nil {
		return nil, ErrIntegrity
	}
	result, err = tx.ExecContext(ctx, downloadAdmissionReceiptInsertSQL, operationID, r.Installation, r.OperationID, evidenceID, r.EvidenceID, r.IntentAuditID,
		private, int64(len(private)), hash(private), public, int64(len(public)), hash(public), r.AdmittedAt, r.ClaimExpiresAt, o.DeadlineAt, retainUntil)
	if !downloadAdmissionOne(result, err) {
		return nil, ErrDownloadAdmissionNotReady
	}
	anchor := &DownloadAdmissionRecords{state: &downloadAdmissionRecordsState{}, tx: tx, binding: b, operationID: operationID, evidenceID: evidenceID, retainUntil: retainUntil}
	if anchor.Recheck(ctx, tx, key.actor, current) != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	key.state.staged, key.state.failed = true, false
	return anchor, nil
}

// Recheck independently reloads the original SQL rows/bytes after later nonce
// writes or callbacks. It never extends retention, the claim or any deadline.
// Current authentication/config/material/capacity and a final SQL UTC after ALL
// outer effects remain mandatory in D's complete admission owner.
func (a *DownloadAdmissionRecords) Recheck(ctx context.Context, tx *sql.Tx, actor systembackupsecurity.RegistrationActor, current Record) error {
	if a == nil || a.state == nil {
		return ErrDownloadAdmissionNotReady
	}
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	if a.state.failed {
		return ErrDownloadAdmissionNotReady
	}
	a.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != a.tx || a.binding == nil || a.binding.Recheck(ctx, tx, actor, current) != nil {
		return ErrDownloadAdmissionNotReady
	}
	b := a.binding
	o, r := b.operation, b.receipt
	if id, err := readDownloadAdmissionEvidenceAnchor(ctx, tx, b, a.retainUntil); err != nil || id != a.evidenceID {
		return ErrDownloadAdmissionNotReady
	}
	if err := readDownloadAdmissionOperationReceipt(ctx, tx, a.operationID, a.evidenceID, a.retainUntil, r, o); err != nil {
		return err
	}
	// This fresh sample is after every storage read and original audit recheck.
	if b.Recheck(ctx, tx, actor, current) != nil {
		return ErrDownloadAdmissionNotReady
	}
	a.state.failed = false
	return nil
}

// Both the pending owner and a known-committed read use the same complete SQL
// predicates/closed byte comparison. The caller establishes its own lock scope;
// this helper cannot establish a commit or authorize a provider.
func readDownloadAdmissionOperationReceipt(ctx context.Context, tx *sql.Tx, operationDBID, evidenceDBID int64, retain time.Time, r DownloadAdmissionReceiptFacts, o DownloadAdmissionOperationFacts) error {
	if err := readDownloadAdmissionOperationRow(ctx, tx, operationDBID, evidenceDBID, o); err != nil {
		return err
	}
	var private, public []byte
	var privateSize, publicSize int64
	var privateSHA, publicSHA string
	if tx.QueryRowContext(ctx, downloadAdmissionReceiptReadSQL, operationDBID, r.Installation, r.OperationID, evidenceDBID, r.EvidenceID, r.IntentAuditID,
		r.AdmittedAt, r.ClaimExpiresAt, o.DeadlineAt, retain).Scan(&private, &privateSize, &privateSHA, &public, &publicSize, &publicSHA) != nil {
		return ErrDownloadAdmissionNotReady
	}
	if VerifyDownloadAdmissionContent(private, public, privateSHA, publicSHA, privateSize, publicSize, r, o) != nil {
		return ErrIntegrity
	}
	return nil
}

func readDownloadAdmissionOperationRow(ctx context.Context, tx *sql.Tx, operationDBID, evidenceDBID int64, o DownloadAdmissionOperationFacts) error {
	empty := []byte("[]")
	var operationID int64
	if tx.QueryRowContext(ctx, downloadAdmissionOperationReadSQL, operationDBID, o.OperationID, o.Installation, o.EvidenceID, evidenceDBID, strconv.FormatInt(o.ActorID, 10), o.IdempotencyKey, o.RequestHash,
		empty, hash(empty), o.DeadlineAt, o.AdmittedAt, o.AdmittedAt, o.AdmittedAt, o.AdmittedAt).Scan(&operationID) != nil || operationID != operationDBID {
		return ErrDownloadAdmissionNotReady
	}
	return nil
}
