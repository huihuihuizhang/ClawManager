package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"clawreef/internal/systembackupsecurity"
)

const downloadAdmissionNonceInsertSQL = `INSERT INTO system_backup_v2_strong_auth_nonces
(origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,
authenticated_at,expires_at,consumed_at,operation_id,response_sha256,audit_log_id,retain_until,created_at)
SELECT ?,?,?,?,?,?,'getSystemBackupEvidence',?,?,?,?,UTC_TIMESTAMP(6),?,NULL,?,?,UTC_TIMESTAMP(6)
WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<? AND UTC_TIMESTAMP(6)<?`
const downloadAdmissionNonceReadSQL = `SELECT consumed_at,created_at FROM system_backup_v2_strong_auth_nonces
WHERE id=? AND schema_version='system-backup-strong-auth-nonce.v1' AND origin_installation_id=? AND issuer_sha256=? AND subject_sha256=? AND session_sha256=?
AND nonce_hmac=? AND nonce_hmac_key_version=? AND endpoint='getSystemBackupEvidence' AND request_hash=? AND idempotency_key=?
AND authenticated_at=? AND expires_at=? AND operation_id=? AND response_sha256 IS NULL AND audit_log_id=? AND retain_until=? FOR UPDATE`
const downloadAdmissionNonceCandidateReadSQL = `SELECT id FROM system_backup_v2_strong_auth_nonces WHERE nonce_hmac=? AND nonce_hmac_key_version=? FOR UPDATE`

// DownloadAdmissionNonce anchors an UNCOMMITTED nonce to the original storage
// rows and exact all-version lock scope. Only the outer owner may commit, after
// its current authorization/config/material/capacity and final SQL UTC guards.
type DownloadAdmissionNonce struct {
	state                        *downloadAdmissionNonceState
	tx                           *sql.Tx
	scope                        *systembackupsecurity.SensitiveDownloadNonceScope
	records                      *DownloadAdmissionRecords
	id                           int64
	floor, consumedAt, expiresAt time.Time
}
type downloadAdmissionNonceState struct {
	mu     sync.Mutex
	failed bool
}

func (*DownloadAdmissionNonce) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*DownloadAdmissionNonce) String() string               { return "DownloadAdmissionNonce" }
func (*DownloadAdmissionNonce) GoString() string             { return "DownloadAdmissionNonce" }

// StageNonce uses actual original Operation/audit IDs, SQL proof acceptance
// time (never signed auth_time), conservative DATETIME(6) signature expiry and
// the same immutable retention group. It cannot run twice, including via a
// copied records value. No raw nonce/proof/bearer is persisted or returned.
func (a *DownloadAdmissionRecords) StageNonce(ctx context.Context, tx *sql.Tx, scope *systembackupsecurity.SensitiveDownloadNonceScope, actor systembackupsecurity.RegistrationActor, current Record) (out *DownloadAdmissionNonce, err error) {
	if a == nil || a.state == nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	a.state.mu.Lock()
	if a.state.failed || a.state.nonceAttempted {
		a.state.mu.Unlock()
		return nil, ErrDownloadAdmissionNotReady
	}
	a.state.nonceAttempted = true
	a.state.mu.Unlock()
	defer func() {
		if err != nil {
			a.state.mu.Lock()
			a.state.failed = true
			a.state.mu.Unlock()
		}
	}()
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != a.tx || scope == nil || a.binding == nil || a.Recheck(ctx, tx, actor, current) != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	b := a.binding
	r, o := b.receipt, b.operation
	proof := b.proof
	accepted := proof.ProofAcceptedAt()
	expires := proof.ProofExpiresAt().UTC().Truncate(time.Microsecond)
	if !downloadAdmissionContentTime(accepted) || !downloadAdmissionContentTime(expires) || !a.retainUntil.After(proof.ProofExpiresAt()) || accepted.After(r.AdmittedAt) {
		return nil, ErrDownloadAdmissionNotReady
	}
	var anchor *DownloadAdmissionNonce
	err = scope.UseLockedCandidates(ctx, tx, proof, func(active systembackupsecurity.NonceHMACCandidate) error {
		now, e := downloadIntentNow(ctx, tx, b.lastObserved)
		if e != nil || !now.Before(o.DeadlineAt) || !now.Before(expires) || proof.RecheckProofAt(now) != nil {
			return ErrDownloadAdmissionNotReady
		}
		result, e := tx.ExecContext(ctx, downloadAdmissionNonceInsertSQL, r.Installation, proof.IssuerSHA256(), r.SubjectSHA256, r.SessionSHA256, active.HMAC, active.KeyVersion,
			r.RequestHash, proof.Request().IdempotencyKey(), accepted, expires, a.operationID, r.IntentAuditID, a.retainUntil, now, o.DeadlineAt, expires)
		if !downloadAdmissionOne(result, e) {
			return ErrDownloadAdmissionNotReady
		}
		id, e := result.LastInsertId()
		if e != nil || id < 1 {
			return ErrDownloadAdmissionNotReady
		}
		anchor = &DownloadAdmissionNonce{state: &downloadAdmissionNonceState{}, tx: tx, scope: scope, records: a, id: id, floor: now, expiresAt: expires}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if anchor == nil || anchor.Recheck(ctx, tx, actor, current) != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	return anchor, nil
}

// Recheck validates the original nonce row AND all historical candidates, then
// the original operation/receipt/audit/claim, and samples SQL UTC after reads.
// Restoring a row after a failed check cannot revive this anchor or a copy.
func (n *DownloadAdmissionNonce) Recheck(ctx context.Context, tx *sql.Tx, actor systembackupsecurity.RegistrationActor, current Record) error {
	if n == nil || n.state == nil {
		return ErrDownloadAdmissionNotReady
	}
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	if n.state.failed {
		return ErrDownloadAdmissionNotReady
	}
	n.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != n.tx || n.records == nil || n.scope == nil || n.records.Recheck(ctx, tx, actor, current) != nil {
		return ErrDownloadAdmissionNotReady
	}
	a := n.records
	b := a.binding
	r := b.receipt
	proof := b.proof
	active := proof.ActiveNonce()
	var consumed, created time.Time
	if tx.QueryRowContext(ctx, downloadAdmissionNonceReadSQL, n.id, r.Installation, proof.IssuerSHA256(), r.SubjectSHA256, r.SessionSHA256, active.HMAC, active.KeyVersion,
		r.RequestHash, proof.Request().IdempotencyKey(), proof.ProofAcceptedAt(), n.expiresAt, a.operationID, r.IntentAuditID, a.retainUntil).Scan(&consumed, &created) != nil ||
		!downloadAdmissionContentTime(consumed) || !downloadAdmissionContentTime(created) || !consumed.Equal(created) || consumed.Before(n.floor) ||
		!n.consumedAt.IsZero() && !consumed.Equal(n.consumedAt) || !consumed.Before(b.operation.DeadlineAt) || !consumed.Before(n.expiresAt) {
		return ErrDownloadAdmissionNotReady
	}
	for _, candidate := range proof.NonceCandidates() {
		var id int64
		err := tx.QueryRowContext(ctx, downloadAdmissionNonceCandidateReadSQL, candidate.HMAC, candidate.KeyVersion).Scan(&id)
		if candidate == active {
			if err != nil || id != n.id {
				return ErrDownloadAdmissionNotReady
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return ErrDownloadAdmissionNotReady
		}
	}
	if n.scope.RecheckUsedCandidates(ctx, tx, proof) != nil || a.Recheck(ctx, tx, actor, current) != nil {
		return ErrDownloadAdmissionNotReady
	}
	now, err := downloadIntentNow(ctx, tx, consumed)
	if err != nil || !now.Before(b.operation.DeadlineAt) || !now.Before(n.expiresAt) || proof.RecheckProofAt(now) != nil {
		return ErrDownloadAdmissionNotReady
	}
	n.consumedAt, n.state.failed = consumed, false
	return nil
}
