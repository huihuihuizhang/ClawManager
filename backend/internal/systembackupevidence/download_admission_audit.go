package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"regexp"
	"time"
)

const downloadIntentClockSQL = `SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))`
const downloadIntentInsertSQL = `INSERT INTO audit_logs (user_id,action,resource_type,resource_id,details,created_at) VALUES (?,'system_backup.evidence_download.intent','system_backup',NULL,?,?)`
const downloadIntentReadSQL = `SELECT user_id,action,resource_type,resource_id,details,created_at FROM audit_logs WHERE id=? FOR UPDATE`

var downloadAdmissionOperationID = regexp.MustCompile(`^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var downloadAdmissionClaimID = regexp.MustCompile(`^aev_[0-9a-f]{32}$`)

// DownloadAdmissionIntent contains server facts, not HTTP input or authority.
// The transaction owner must establish the common lock prefix, authenticate
// the actor and reserve physical capacity BEFORE calling this storage helper.
type DownloadAdmissionIntent struct {
	Installation, OperationID, EvidenceID, RequestHash, ManifestSHA256, Claim string
	ActorID, EvidenceRowVersion, Start, End                                   int64
	RangePresent                                                              bool
}

// The transient input contains the raw server claim. It must never be copied
// wholesale into an audit/receipt/API JSON body; only downloadIntentBody's
// closed projection, with claim digest, is eligible for persistence.
func (DownloadAdmissionIntent) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (f DownloadAdmissionIntent) valid() bool {
	return installationPattern.MatchString(f.Installation) && downloadAdmissionOperationID.MatchString(f.OperationID) &&
		idPattern.MatchString(f.EvidenceID) && digestPattern.MatchString(f.RequestHash) && digestPattern.MatchString(f.ManifestSHA256) &&
		downloadAdmissionClaimID.MatchString(f.Claim) && f.ActorID > 0 && f.ActorID <= 2147483647 &&
		f.EvidenceRowVersion > 0 && f.EvidenceRowVersion <= 9007199254740991 &&
		f.Start >= 0 && f.End >= f.Start && f.End < MaxContent && f.End-f.Start+1 <= MaxResponse &&
		(f.RangePresent || f.Start == 0)
}

func downloadIntentBody(f DownloadAdmissionIntent, now time.Time) []byte {
	return canonical(map[string]any{
		"schema_version": "system-backup-evidence-download-intent.v1", "origin_installation_id": f.Installation,
		"operation_public_id": f.OperationID, "evidence_id": f.EvidenceID, "evidence_row_version": f.EvidenceRowVersion,
		"request_hash": f.RequestHash, "manifest_sha256": f.ManifestSHA256, "claim_sha256": hash([]byte(f.Claim)),
		"range_present": f.RangePresent, "range_start": f.Start, "range_end": f.End,
		"intent_at": now.UTC().Format("2006-01-02T15:04:05.000000Z"),
	})
}

// DownloadIntentAuditAnchor is bound to the exact transaction and original
// immutable audit body. It neither authorizes nor commits a download. No raw
// claim, proof, nonce, bearer or key is retained in this capability.
type DownloadIntentAuditAnchor struct {
	tx                     *sql.Tx
	id, actor              int64
	body                   string
	observedAt, recordedAt time.Time
}

func (DownloadIntentAuditAnchor) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// SQLDownloadAdmissionAudits is candidate SQL storage, separate from SQLPolicy's
// existing Audit method. It performs no Begin/Commit/Rollback and is not wired
// into the HTTP handler; the full admission owner must still be implemented.
type SQLDownloadAdmissionAudits struct{}

func downloadIntentNow(ctx context.Context, tx *sql.Tx, floor time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return time.Time{}, ErrAudit
	}
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, downloadIntentClockSQL).Scan(&now, &offset) != nil {
		return time.Time{}, ErrAudit
	}
	_, driverOffset := now.Zone()
	if now.IsZero() || offset != 0 || driverOffset != 0 ||
		now.Year() < 1970 || now.Year() > 9999 || now.Nanosecond()%1000 != 0 || now.Before(floor) || ctx.Err() != nil {
		return time.Time{}, ErrAudit
	}
	return now.UTC(), nil
}

func verifyDownloadIntent(ctx context.Context, tx *sql.Tx, a DownloadIntentAuditAnchor) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || a.tx != tx || a.id < 1 || a.id > 2147483647 || a.actor < 1 ||
		a.body == "" || len(a.body) > 8192 || a.recordedAt.IsZero() || a.observedAt.IsZero() {
		return ErrAudit
	}
	var user, resource sql.NullInt64
	var action, resourceType string
	var body []byte
	var created time.Time
	if tx.QueryRowContext(ctx, downloadIntentReadSQL, a.id).Scan(&user, &action, &resourceType, &resource, &body, &created) != nil ||
		!user.Valid || user.Int64 != a.actor || resource.Valid || action != "system_backup.evidence_download.intent" ||
		resourceType != "system_backup" || !created.Equal(a.recordedAt) || len(body) > 8192 {
		return ErrAudit
	}
	// MySQL JSON may reorder keys and insert spaces. Compare closed semantic
	// bytes, retaining exact integer/string distinctions and rejecting extras.
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var stored map[string]any
	var extra any
	if d.Decode(&stored) != nil || d.Decode(&extra) != io.EOF || !bytes.Equal(canonical(stored), []byte(a.body)) || ctx.Err() != nil {
		return ErrAudit
	}
	return nil
}

// StageIntent inserts once, uses that INSERT's actual ID, and independently
// reads the row back before returning a sealed anchor. On any error the caller
// must abort its transaction; no usable ID/anchor is returned for pending work.
func (SQLDownloadAdmissionAudits) StageIntent(ctx context.Context, tx *sql.Tx, f DownloadAdmissionIntent) (DownloadIntentAuditAnchor, error) {
	zero := DownloadIntentAuditAnchor{}
	if !f.valid() {
		return zero, ErrInvalid
	}
	now, err := downloadIntentNow(ctx, tx, time.Time{})
	if err != nil {
		return zero, err
	}
	body := downloadIntentBody(f, now)
	if len(body) == 0 || len(body) > 8192 {
		return zero, ErrAudit
	}
	// audit_logs.created_at is TIMESTAMP(0) in published 001. Explicitly
	// truncate before binding, so MySQL fractional rounding cannot move the
	// audit into the future. The JSON retains the exact microsecond SQL time.
	recorded := now.Truncate(time.Second)
	result, err := tx.ExecContext(ctx, downloadIntentInsertSQL, f.ActorID, body, recorded)
	if err != nil || result == nil {
		return zero, ErrAudit
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return zero, ErrAudit
	}
	id, err := result.LastInsertId()
	if err != nil || id < 1 || id > 2147483647 {
		return zero, ErrAudit
	}
	a := DownloadIntentAuditAnchor{tx: tx, id: id, actor: f.ActorID, body: string(body), observedAt: now, recordedAt: recorded}
	if verifyDownloadIntent(ctx, tx, a) != nil {
		return zero, ErrAudit
	}
	return a, nil
}

// AuditIntent is the agreed low-level actual INSERT-ID API. It is not a nonce
// consumption API. Full admission should retain StageIntent's sealed anchor so
// RecheckIntent can detect changes made by later callbacks in the same tx.
func (s SQLDownloadAdmissionAudits) AuditIntent(ctx context.Context, tx *sql.Tx, f DownloadAdmissionIntent) (int64, error) {
	a, err := s.StageIntent(ctx, tx, f)
	if err != nil {
		return 0, err
	}
	return a.id, nil
}

// RecheckIntent checks the same original body/ID/second-precision SQL column,
// rejects a different transaction or regressed SQL clock, then returns the FK.
// The caller still performs its fresh final UTC/deadline check after all writes.
func (SQLDownloadAdmissionAudits) RecheckIntent(ctx context.Context, tx *sql.Tx, a DownloadIntentAuditAnchor) (int64, error) {
	if tx == nil || a.tx != tx || a.observedAt.IsZero() {
		return 0, ErrAudit
	}
	if _, err := downloadIntentNow(ctx, tx, a.observedAt); err != nil {
		return 0, ErrAudit
	}
	if err := verifyDownloadIntent(ctx, tx, a); err != nil {
		return 0, ErrAudit
	}
	return a.id, nil
}
