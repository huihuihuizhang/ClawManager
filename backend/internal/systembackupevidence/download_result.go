package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

const maxDownloadResultBytes = 2048
const downloadResultActorSQL = `SELECT id FROM users WHERE id=? FOR UPDATE`
const downloadResultInsertSQL = `INSERT INTO audit_logs (user_id,action,resource_type,resource_id,details,created_at) VALUES (?,'system_backup.evidence_download.result','system_backup',NULL,?,?)`
const downloadResultReadSQL = `SELECT user_id,action,resource_type,resource_id,details,created_at FROM audit_logs WHERE id=? FOR UPDATE`
const downloadResultReleaseSQL = `UPDATE system_backup_v2_evidence SET claim_owner=NULL,claim_expires_at=NULL,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6)
WHERE id=? AND public_id=? AND origin_installation_id=? AND owner_target_type=? AND owner_target_public_id=? AND row_version=? AND claim_owner=? AND claim_expires_at=? AND row_version<9007199254740991`
const downloadResultReleaseReadSQL = `SELECT origin_installation_id,row_version,claim_owner,claim_expires_at FROM system_backup_v2_evidence WHERE id=? AND public_id=? FOR UPDATE`

var ErrDownloadResultCommitUnknown = errors.New("download_result_commit_unknown")

// Deployment supplies the same authoritative owner/ref lock implementation and
// a measured physical audit/result-receipt/index/FK budget. Result recording grants no download
// authority and does not require a still-live/reusable user session or proof.
type SQLDownloadResultsConfig struct {
	Registry                 SQLRegistry
	Owners                   DownloadAdmissionOwners
	Capacity                 *sec.ConfigMutationCapacity
	MeasuredReservationBytes int
}
type SQLDownloadResults struct{ c SQLDownloadResultsConfig }

func NewSQLDownloadResults(c SQLDownloadResultsConfig) (*SQLDownloadResults, error) {
	if c.Registry.DB == nil || nilSystemAdapter(c.Registry.Policy) || !installationPattern.MatchString(c.Registry.Installation) || c.Registry.ServerUUID == "" || c.Registry.Database == "" || nilSystemAdapter(c.Owners) || c.Capacity == nil || c.MeasuredReservationBytes < maxDownloadResultBytes || c.MeasuredReservationBytes > 1048576 {
		return nil, ErrDownloadAdmissionNotReady
	}
	return &SQLDownloadResults{c}, nil
}

type DownloadResultObservation struct {
	Outcome      string
	BytesWritten int64
}

// Only bounded correlation facts are made available to the mandatory durable
// failure sink. No request/proof/claim/provider locator is added to this context.
type DownloadFailureReference struct {
	OperationID   string `json:"operation_public_id"`
	IntentAuditID int64  `json:"intent_audit_id"`
	ClaimSHA256   string `json:"claim_sha256"`
}
type downloadFailureReferenceKey struct{}

func DownloadFailureReferenceFrom(ctx context.Context) (DownloadFailureReference, bool) {
	if ctx == nil {
		return DownloadFailureReference{}, false
	}
	r, ok := ctx.Value(downloadFailureReferenceKey{}).(DownloadFailureReference)
	return r, ok
}
func downloadFailureContext(c *CommittedDownloadAdmission) context.Context {
	return context.WithValue(context.Background(), downloadFailureReferenceKey{}, DownloadFailureReference{c.operationID, c.intentAuditID, hash([]byte(c.record.Claim))})
}

func downloadResultBody(c *CommittedDownloadAdmission, o DownloadResultObservation, now time.Time) []byte {
	return downloadResultReceiptBody(c.rows.receipt, c.rows.retainUntil, o, now)
}

func downloadResultReceiptBody(r DownloadAdmissionReceiptFacts, retain time.Time, o DownloadResultObservation, now time.Time) []byte {
	return canonical(map[string]any{"schema_version": "system-backup-evidence-download-result.v1", "origin_installation_id": r.Installation,
		"operation_public_id": r.OperationID, "intent_audit_id": r.IntentAuditID, "evidence_id": r.EvidenceID, "evidence_row_version": r.EvidenceRowVersion,
		"claim_sha256": r.ClaimSHA256, "request_hash": r.RequestHash, "range_start": r.Start, "range_end": r.End, "range_present": r.RangePresent,
		"outcome": o.Outcome, "bytes_written": o.BytesWritten, "result_at": now.UTC().Format("2006-01-02T15:04:05.000000Z"), "retain_until": retain.UTC().Format("2006-01-02T15:04:05.000000Z")})
}

func verifyDownloadResult(ctx context.Context, tx *sql.Tx, id, actor int64, body []byte, at time.Time) error {
	var user, resource sql.NullInt64
	var action, kind string
	var stored []byte
	var created time.Time
	if tx.QueryRowContext(ctx, downloadResultReadSQL, id).Scan(&user, &action, &kind, &resource, &stored, &created) != nil || !user.Valid || user.Int64 != actor || resource.Valid || action != "system_backup.evidence_download.result" || kind != "system_backup" || !created.Equal(at) || len(stored) > maxDownloadResultBytes {
		return ErrAudit
	}
	d := json.NewDecoder(bytes.NewReader(stored))
	d.UseNumber()
	var decoded map[string]any
	var extra any
	if d.Decode(&decoded) != nil || d.Decode(&extra) != io.EOF || !bytes.Equal(canonical(decoded), body) {
		return ErrAudit
	}
	return nil
}

// Finish makes one independent result attempt, even if binding, permission or
// the original download deadline has failed. It never replays admission or
// modifies nonce/Operation/admission receipt/intent. Its separate immutable
// result receipt protects the audit in that retention group. Unknown commit
// is terminal, no retry.
func (s *SQLDownloadResults) Finish(ctx context.Context, c *CommittedDownloadAdmission, o DownloadResultObservation) error {
	if c == nil || c.state == nil {
		return ErrAudit
	}
	c.state.mu.Lock()
	if c.state.resultAttempted {
		c.state.mu.Unlock()
		return ErrAudit
	}
	c.state.resultAttempted, c.state.failed = true, true
	c.state.mu.Unlock()
	if s == nil || ctx == nil || ctx.Err() != nil || c.service == nil || s.c.Registry.DB != c.service.registry.DB || s.c.Registry.Installation != c.service.registry.Installation || s.c.Registry.ServerUUID != c.service.registry.ServerUUID || s.c.Registry.Database != c.service.registry.Database {
		return ErrAudit
	}
	start, end, _ := c.Range()
	expected := end - start + 1
	if expected < 1 || expected > MaxResponse || o.BytesWritten < 0 || o.BytesWritten > expected || !oneOf(o.Outcome, "rejected", "interrupted", "local_write_complete") || o.Outcome == "rejected" && o.BytesWritten != 0 || o.Outcome == "local_write_complete" && o.BytesWritten != expected {
		return ErrAudit
	}
	r := s.c.Registry
	tx, now, err := r.begin(ctx)
	if err != nil {
		return ErrAudit
	}
	defer tx.Rollback()
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, sec.DatabaseIdentity{ServerUUID: r.ServerUUID, Database: r.Database}, r.Installation)
	if err != nil {
		return ErrAudit
	}
	config, err := scope.LoadConfig(ctx, tx)
	if err != nil {
		return ErrAudit
	}
	// Lock the audit FK target at L2, even for disabled/revoked users. This is
	// not current authorization; it prevents INSERT's implicit user FK lock
	// from being acquired backwards after owner/nonce/reservation/audit locks.
	var actorID int64
	if tx.QueryRowContext(ctx, downloadResultActorSQL, c.actor.UserID).Scan(&actorID) != nil || actorID != c.actor.UserID {
		return ErrAudit
	}
	if c.checkOperationReceipt(ctx, tx) != nil || lockDownloadResultRetention(ctx, tx, c) != nil {
		return ErrAudit
	}
	group, err := LockDownloadRetentionGroup(ctx, tx, sec.DatabaseIdentity{ServerUUID: r.ServerUUID, Database: r.Database}, config, c.operationID)
	if err != nil || !group.matchesCommitted(c) || s.c.Owners.LockOwnerReferences(ctx, tx, c.Record()) != nil || c.checkNonce(ctx, tx) != nil || group.LockNonce(ctx, tx) != nil {
		return ErrAudit
	}
	now, err = downloadIntentNow(ctx, tx, c.admittedAt)
	if err != nil || !now.Before(c.rows.retainUntil) {
		return ErrAudit
	}
	reservation, err := s.c.Capacity.Reserve(ctx, tx, config.Values(), config.Values(), s.c.MeasuredReservationBytes, now)
	if err != nil || nilSystemAdapter(reservation) {
		return ErrCapacity
	}
	until := reservation.ValidUntil()
	if !downloadAdmissionContentTime(until) || !now.Before(until) {
		return ErrCapacity
	}
	// Re-read the original intent only after L6 reservation, before a new audit.
	if c.checkIntent(ctx, tx) != nil || group.VerifyAudits(ctx, tx) != nil {
		return ErrAudit
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return ErrAudit
	}
	body := downloadResultBody(c, o, now)
	if len(body) > maxDownloadResultBytes {
		return ErrAudit
	}
	recorded := now.Truncate(time.Second)
	insert, err := tx.ExecContext(ctx, downloadResultInsertSQL, c.actor.UserID, body, recorded)
	if !downloadAdmissionOne(insert, err) {
		return ErrAudit
	}
	id, err := insert.LastInsertId()
	if err != nil || id < 1 || id > 2147483647 || id == c.intentAuditID {
		return ErrAudit
	}
	if verifyDownloadResult(ctx, tx, id, c.actor.UserID, body, recorded) != nil {
		return ErrAudit
	}
	retention := resultRetention(c, id, body, now)
	if retention.insert(ctx, tx) != nil || group.attachResult(retention) != nil {
		return ErrAudit
	}
	i := c.record.Manifest.Identity
	released, err := tx.ExecContext(ctx, downloadResultReleaseSQL, c.rows.evidenceID, i.ID, i.Installation, i.OwnerType, i.OwnerID, c.record.RowVersion, c.record.Claim, c.record.ClaimUntil)
	if err != nil || released == nil {
		return ErrAudit
	}
	affected, err := released.RowsAffected()
	if err != nil || affected < 0 || affected > 1 {
		return ErrAudit
	}
	if affected == 1 {
		var installation sql.NullString
		var version int64
		var claim sql.NullString
		var expires sql.NullTime
		if tx.QueryRowContext(ctx, downloadResultReleaseReadSQL, c.rows.evidenceID, i.ID).Scan(&installation, &version, &claim, &expires) != nil || !installation.Valid || installation.String != i.Installation || version != c.record.RowVersion+1 || claim.Valid || expires.Valid {
			return ErrAudit
		}
	}
	// No external callbacks after these independent original/audit rechecks.
	if config.Recheck(ctx, tx) != nil || reservation.Recheck(ctx, tx, now) != nil || c.checkOperationReceipt(ctx, tx) != nil || c.checkNonce(ctx, tx) != nil || c.checkIntent(ctx, tx) != nil || verifyDownloadResult(ctx, tx, id, c.actor.UserID, body, recorded) != nil || retention.verify(ctx, tx) != nil || group.Recheck(ctx, tx) != nil {
		return ErrAudit
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !now.Before(until) || !now.Before(c.rows.retainUntil) || ctx.Err() != nil {
		return ErrAudit
	}
	if tx.Commit() != nil {
		return ErrDownloadResultCommitUnknown
	}
	return nil
}
