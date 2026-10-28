package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"time"

	"clawreef/internal/systembackupsecurity"
)

var (
	ErrDownloadAdmissionKeyConflict = errors.New("idempotency_conflict")
	ErrDownloadAdmissionKeyExpired  = errors.New("idempotency_expired")
	ErrDownloadAdmissionNotReady    = errors.New("not_ready")
)

const downloadAdmissionKeySQL = `SELECT id,request_hash FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint='getSystemBackupEvidence' AND idempotency_key=? FOR UPDATE`
const downloadAdmissionTombstoneSQL = `SELECT request_hash FROM system_backup_v2_compact_tombstones WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint='getSystemBackupEvidence' AND idempotency_key=? FOR UPDATE`
const downloadAdmissionReceiptKeySQL = `SELECT operation_id FROM system_backup_v2_download_admission_receipts WHERE origin_installation_id=? AND operation_public_id=? FOR UPDATE`

// DownloadAdmissionKeyLock is only the L3 operation/receipt-key lock, not a
// download authority. D must already own a fresh RepeatableRead transaction,
// L0/L1 locks and current A authentication/target/RBAC/proof checks. Owner and
// reference locks, nonce candidates, capacity, audit and evidence follow it.
// Private fields bind it to this transaction and the exact verified request;
// storage must still consume/check it inside the outer transaction.
type DownloadAdmissionKeyLock struct {
	state       *downloadAdmissionKeyState
	tx          *sql.Tx
	actor       systembackupsecurity.RegistrationActor
	request     systembackupsecurity.SensitiveDownloadRequest
	proof       systembackupsecurity.SensitiveDownloadProofVerification
	operationID string
	observedAt  time.Time
}

type downloadAdmissionKeyState struct {
	mu             sync.Mutex
	failed, staged bool
	claimAttempted bool
}

func (*DownloadAdmissionKeyLock) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*DownloadAdmissionKeyLock) String() string               { return "DownloadAdmissionKeyLock" }
func (*DownloadAdmissionKeyLock) GoString() string             { return "DownloadAdmissionKeyLock" }

// LockDownloadAdmissionKey must run AFTER non-consuming proof verification but
// BEFORE nonce replay lookup. Same key/same hash and same key/different hash
// both conflict: an admission never replays binary plaintext. A retained expired
// marker always returns 410, so it cannot become a fresh key. No writes, nested
// transactions, commits, provider access or nonce consumption occur here.
func LockDownloadAdmissionKey(ctx context.Context, tx *sql.Tx, actor systembackupsecurity.RegistrationActor, verified systembackupsecurity.SensitiveDownloadProofVerification, operationID string) (*DownloadAdmissionKeyLock, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !downloadAdmissionOperationID.MatchString(operationID) {
		return nil, ErrDownloadAdmissionNotReady
	}
	r := verified.Request()
	// Use the sealed A verification's identity, never a receipt/HTTP assertion.
	if !r.MatchesActor(actor) || !installationPattern.MatchString(r.InstallationID()) ||
		actor.Subject != "user:"+strconv.FormatInt(actor.UserID, 10) || actor.UserID < 1 || actor.UserID > 2147483647 ||
		!downloadAdmissionKey.MatchString(r.IdempotencyKey()) || !digestPattern.MatchString(r.RequestHash()) {
		return nil, ErrDownloadAdmissionNotReady
	}
	now, err := downloadIntentNow(ctx, tx, time.Time{})
	if err != nil || !downloadAdmissionActorAt(actor, now) {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = verified.RecheckProofAt(now); err != nil {
		return nil, err
	}
	var id int64
	var digest string
	err = tx.QueryRowContext(ctx, downloadAdmissionKeySQL, r.InstallationID(), strconv.FormatInt(actor.UserID, 10), r.IdempotencyKey()).Scan(&id, &digest)
	if err == nil {
		if id < 1 || !digestPattern.MatchString(digest) {
			return nil, ErrDownloadAdmissionNotReady
		}
		return nil, ErrDownloadAdmissionKeyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDownloadAdmissionNotReady
	}
	err = tx.QueryRowContext(ctx, downloadAdmissionTombstoneSQL, r.InstallationID(), strconv.FormatInt(actor.UserID, 10), r.IdempotencyKey()).Scan(&digest)
	if err == nil {
		if !digestPattern.MatchString(digest) {
			return nil, ErrDownloadAdmissionNotReady
		}
		return nil, ErrDownloadAdmissionKeyExpired
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDownloadAdmissionNotReady
	}
	// This is the server-generated operation public ID's receipt key, not a
	// client-selected receipt ID or a lookup of a supposedly latest receipt.
	err = tx.QueryRowContext(ctx, downloadAdmissionReceiptKeySQL, r.InstallationID(), operationID).Scan(&id)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDownloadAdmissionNotReady
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !downloadAdmissionActorAt(actor, now) {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = verified.RecheckProofAt(now); err != nil {
		return nil, err
	}
	return &DownloadAdmissionKeyLock{state: &downloadAdmissionKeyState{}, tx: tx, actor: actor, request: r, proof: verified, operationID: operationID, observedAt: now}, nil
}
