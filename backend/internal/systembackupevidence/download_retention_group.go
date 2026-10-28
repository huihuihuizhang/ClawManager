package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

const downloadRetentionOperationSQL = `SELECT id,public_id,origin_installation_id,target_public_id,download_evidence_id,actor_id,idempotency_key,request_hash,deadline_at,created_at,row_version
FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=? FOR UPDATE`
const downloadRetentionReceiptSQL = `SELECT operation_id,origin_installation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,
IF(OCTET_LENGTH(receipt_canonical_json) BETWEEN 2 AND 8192,receipt_canonical_json,NULL),receipt_size_bytes,receipt_sha256,
IF(OCTET_LENGTH(operation_canonical_json) BETWEEN 2 AND 8192,operation_canonical_json,NULL),operation_size_bytes,operation_sha256,
admitted_at,claim_expires_at,deadline_at,retain_until FROM system_backup_v2_download_admission_receipts
WHERE operation_id=? AND origin_installation_id=? AND schema_version='system-backup-evidence-download-admission.v1' FOR UPDATE`
const downloadRetentionNonceSQL = `SELECT id,origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,
authenticated_at,expires_at,consumed_at,operation_id,response_sha256,audit_log_id,retain_until,created_at,schema_version
FROM system_backup_v2_strong_auth_nonces WHERE operation_id=? ORDER BY id LIMIT 2 FOR UPDATE`
const downloadRetentionAuditSQL = `SELECT user_id,action,resource_type,resource_id,IF(OCTET_LENGTH(details) BETWEEN 2 AND 8192,details,NULL),created_at FROM audit_logs WHERE id=? FOR UPDATE`

var downloadRetentionNonceVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// DownloadRetentionGroup is a transaction-bound reconstruction of persisted
// facts, not a download, worker, commit or GC authority. Callers own the same
// L0/L1 scope, L2 FK targets and transaction. Owner/ref/evidence/hold guards,
// tombstone, capacity and a reviewed GC principal remain separate requirements.
// Private receipts/HMACs are never exposed through JSON, String or summaries.
type DownloadRetentionGroup struct {
	state                   *downloadRetentionGroupState
	tx                      *sql.Tx
	config                  *sec.SensitiveDownloadConfig
	database                sec.DatabaseIdentity
	operation               DownloadAdmissionOperationFacts
	receipt                 DownloadAdmissionReceiptFacts
	operationID, evidenceID int64
	retain                  time.Time
	private, public         []byte
	nonce                   *downloadRetentionNonce
	result                  *downloadResultRetention
	intentBody, resultBody  []byte
	rolling                 string
}
type downloadRetentionGroupState struct {
	sync.Mutex
	failed, verified bool
}

func (DownloadRetentionGroup) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadRetentionGroup) String() string               { return "DownloadRetentionGroup" }
func (DownloadRetentionGroup) GoString() string             { return "DownloadRetentionGroup" }

// LockDownloadRetentionGroup locks only the original L3 operation/receipt/result
// slot. It never asks for a current user session, proof, HMAC secret or provider
// lease: historical cleanup facts must remain readable after those expire.
// Its public result still cannot authorize cleanup or establish eligibility.
func LockDownloadRetentionGroup(ctx context.Context, tx *sql.Tx, database sec.DatabaseIdentity, config *sec.SensitiveDownloadConfig, operation string) (*DownloadRetentionGroup, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || config == nil || database.ServerUUID == "" || database.Database == "" || !downloadAdmissionOperationID.MatchString(operation) {
		return nil, ErrAudit
	}
	g := &DownloadRetentionGroup{state: &downloadRetentionGroupState{}, tx: tx, config: config, database: database}
	if g.checkDatabase(ctx) != nil || config.Recheck(ctx, tx) != nil {
		return nil, ErrAudit
	}
	var actor string
	o := &g.operation
	if tx.QueryRowContext(ctx, downloadRetentionOperationSQL, config.InstallationID(), operation).Scan(&g.operationID, &o.OperationID, &o.Installation, &o.EvidenceID, &g.evidenceID, &actor, &o.IdempotencyKey, &o.RequestHash, &o.DeadlineAt, &o.AdmittedAt, &o.RowVersion) != nil || g.operationID < 1 || g.evidenceID < 1 || o.OperationID != operation || o.Installation != config.InstallationID() || o.RowVersion != 1 {
		return nil, ErrAudit
	}
	id, err := strconv.ParseInt(actor, 10, 64)
	if err != nil || strconv.FormatInt(id, 10) != actor {
		return nil, ErrAudit
	}
	o.ActorID = id
	if _, err = CanonicalDownloadAdmissionOperation(*o); err != nil || readDownloadAdmissionOperationRow(ctx, tx, g.operationID, g.evidenceID, *o) != nil {
		return nil, ErrAudit
	}
	if g.readReceipt(ctx) != nil {
		return nil, ErrAudit
	}
	var existing int64
	err = tx.QueryRowContext(ctx, downloadResultRetentionKeySQL, g.operationID).Scan(&existing)
	if err == nil {
		if existing != g.operationID {
			return nil, ErrAudit
		}
		g.result, err = g.readResult(ctx)
		if err != nil {
			return nil, ErrAudit
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAudit
	}
	return g, nil
}

func (g *DownloadRetentionGroup) readReceipt(ctx context.Context) error {
	var operationID, evidenceID, intent, size, publicSize int64
	var installation, operation, evidence, digest, publicDigest string
	var body, public []byte
	var admitted, claim, deadline, retain time.Time
	if g.tx.QueryRowContext(ctx, downloadRetentionReceiptSQL, g.operationID, g.operation.Installation).Scan(&operationID, &installation, &operation, &evidenceID, &evidence, &intent, &body, &size, &digest, &public, &publicSize, &publicDigest, &admitted, &claim, &deadline, &retain) != nil {
		return ErrAudit
	}
	r, err := DecodeCanonicalDownloadAdmissionReceipt(body)
	if err != nil || operationID != g.operationID || evidenceID != g.evidenceID || installation != g.operation.Installation || operation != g.operation.OperationID || evidence != g.operation.EvidenceID || r.Installation != installation || r.OperationID != operation || r.EvidenceID != evidence || r.IntentAuditID != intent || !r.AdmittedAt.Equal(admitted) || !r.ClaimExpiresAt.Equal(claim) || !g.operation.DeadlineAt.Equal(deadline) || !downloadAdmissionContentTime(retain) || !retain.After(claim) || VerifyDownloadAdmissionContent(body, public, digest, publicDigest, size, publicSize, r, g.operation) != nil {
		return ErrAudit
	}
	if g.private != nil && (!bytes.Equal(g.private, body) || !bytes.Equal(g.public, public) || !g.retain.Equal(retain)) {
		return ErrAudit
	}
	g.receipt, g.retain = r, retain
	g.private, g.public = append([]byte(nil), body...), append([]byte(nil), public...)
	return nil
}

func (g *DownloadRetentionGroup) readResult(ctx context.Context) (*downloadResultRetention, error) {
	r := new(downloadResultRetention)
	if g.tx.QueryRowContext(ctx, downloadResultRetentionReadSQL, g.operationID).Scan(&r.operationID, &r.installation, &r.operationPublicID, &r.evidenceID, &r.evidencePublicID, &r.intentID, &r.resultID, &r.size, &r.digest, &r.at, &r.retain) != nil || r.operationID != g.operationID || r.installation != g.operation.Installation || r.operationPublicID != g.operation.OperationID || r.evidenceID != g.evidenceID || r.evidencePublicID != g.receipt.EvidenceID || r.intentID != g.receipt.IntentAuditID || r.resultID < 1 || r.resultID > 2147483647 || r.resultID == r.intentID || r.size < 2 || r.size > maxDownloadResultBytes || !digestPattern.MatchString(r.digest) || !downloadAdmissionContentTime(r.at) || r.at.Before(g.receipt.AdmittedAt) || !r.retain.Equal(g.retain) || !r.at.Before(r.retain) {
		return nil, ErrAudit
	}
	return r, nil
}

func (g *DownloadRetentionGroup) run(ctx context.Context, tx *sql.Tx, fn func() error) error {
	if g == nil || g.state == nil {
		return ErrAudit
	}
	g.state.Lock()
	defer g.state.Unlock()
	if g.state.failed {
		return ErrAudit
	}
	g.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != g.tx || g.config == nil || fn == nil || g.checkDatabase(ctx) != nil || fn() != nil || g.checkDatabase(ctx) != nil {
		return ErrAudit
	}
	g.state.failed = false
	return nil
}

func (g *DownloadRetentionGroup) checkDatabase(ctx context.Context) error {
	var observed sec.DatabaseIdentity
	if g.tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&observed.ServerUUID, &observed.Database) != nil || observed != g.database {
		return ErrAudit
	}
	return nil
}

type downloadRetentionNonce struct {
	id, operationID, auditID                                                      int64
	installation, issuer, subject, session, hmac, version, endpoint, request, key string
	schema                                                                        string
	authenticated, expires, consumed, retain, created                             time.Time
}

func (n downloadRetentionNonce) canonical() []byte {
	return canonical(map[string]any{"id": strconv.FormatInt(n.id, 10), "operation": strconv.FormatInt(n.operationID, 10), "audit": n.auditID, "installation": n.installation, "issuer": n.issuer, "subject": n.subject, "session": n.session, "nonce_hmac": n.hmac, "key_version": n.version, "endpoint": n.endpoint, "request": n.request, "key": n.key, "authenticated": downloadAdmissionFormatTime(n.authenticated), "expires": downloadAdmissionFormatTime(n.expires), "consumed": downloadAdmissionFormatTime(n.consumed), "retain": downloadAdmissionFormatTime(n.retain), "created": downloadAdmissionFormatTime(n.created)})
}

// LockNonce follows the caller's L4/L5 owner/ref prefix and precedes L6/L7.
// LIMIT 2 detects an ambiguous group without scanning or retaining an unbounded
// ledger. All association fields are checked against independent L3 SQL facts.
func (g *DownloadRetentionGroup) LockNonce(ctx context.Context, tx *sql.Tx) error {
	return g.run(ctx, tx, func() error { return g.readNonce(ctx) })
}
func (g *DownloadRetentionGroup) readNonce(ctx context.Context) error {
	rows, err := g.tx.QueryContext(ctx, downloadRetentionNonceSQL, g.operationID)
	if err != nil {
		return ErrAudit
	}
	defer rows.Close()
	if !rows.Next() {
		return ErrAudit
	}
	n := new(downloadRetentionNonce)
	var response sql.NullString
	if rows.Scan(&n.id, &n.installation, &n.issuer, &n.subject, &n.session, &n.hmac, &n.version, &n.endpoint, &n.request, &n.key, &n.authenticated, &n.expires, &n.consumed, &n.operationID, &response, &n.auditID, &n.retain, &n.created, &n.schema) != nil || rows.Next() || rows.Err() != nil || rows.Close() != nil {
		return ErrAudit
	}
	r, o := g.receipt, g.operation
	if n.schema != "system-backup-strong-auth-nonce.v1" || n.id < 1 || n.operationID != g.operationID || n.auditID != r.IntentAuditID || n.installation != r.Installation || n.subject != r.SubjectSHA256 || n.session != r.SessionSHA256 || !digestPattern.MatchString(n.issuer) || !digestPattern.MatchString(n.hmac) || !downloadRetentionNonceVersion.MatchString(n.version) || bytes.Contains([]byte(n.version), []byte("..")) || n.endpoint != sec.SensitiveDownloadEndpoint || n.request != r.RequestHash || n.key != o.IdempotencyKey || response.Valid || !n.retain.Equal(g.retain) {
		return ErrAudit
	}
	for _, at := range []time.Time{n.authenticated, n.expires, n.consumed, n.retain, n.created} {
		if !downloadAdmissionContentTime(at) {
			return ErrAudit
		}
	}
	if n.authenticated.After(r.AdmittedAt) || n.consumed.Before(r.AdmittedAt) || n.consumed.Before(n.authenticated) || !n.consumed.Before(n.expires) || !n.consumed.Before(o.DeadlineAt) || !n.created.Equal(n.consumed) || !n.retain.After(n.expires) || g.nonce != nil && !bytes.Equal(g.nonce.canonical(), n.canonical()) {
		return ErrAudit
	}
	g.nonce = n
	return nil
}

// decodeDownloadAudit accepts MySQL's harmless whitespace/key reordering, but
// rejects duplicate keys, nested values, trailing data and non-primitive bodies.
func decodeDownloadAudit(raw []byte, limit int) (map[string]any, error) {
	if len(raw) < 2 || len(raw) > limit {
		return nil, ErrAudit
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrAudit
	}
	m := map[string]any{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || len(m) >= 32 {
			return nil, ErrAudit
		}
		if _, exists := m[name]; exists {
			return nil, ErrAudit
		}
		var value any
		if d.Decode(&value) != nil {
			return nil, ErrAudit
		}
		switch value.(type) {
		case string, bool, json.Number, nil:
		default:
			return nil, ErrAudit
		}
		m[name] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') {
		return nil, ErrAudit
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrAudit
	}
	return m, nil
}

func (g *DownloadRetentionGroup) audit(ctx context.Context, id int64, action string, limit int) (map[string]any, time.Time, error) {
	var user, resource sql.NullInt64
	var storedAction, kind string
	var raw []byte
	var created time.Time
	if g.tx.QueryRowContext(ctx, downloadRetentionAuditSQL, id).Scan(&user, &storedAction, &kind, &resource, &raw, &created) != nil || !user.Valid || user.Int64 != g.operation.ActorID || resource.Valid || storedAction != action || kind != "system_backup" || !downloadAdmissionContentTime(created) || created.Nanosecond() != 0 {
		return nil, time.Time{}, ErrAudit
	}
	m, err := decodeDownloadAudit(raw, limit)
	return m, created, err
}

// VerifyAudits follows L6 capacity/intent locking. A missing result is retained
// as pending facts and never produces a complete detail hash. No current user
// authorization, provider I/O, writes or transaction control are performed.
func (g *DownloadRetentionGroup) VerifyAudits(ctx context.Context, tx *sql.Tx) error {
	return g.run(ctx, tx, func() error { return g.verifyAudits(ctx) })
}
func (g *DownloadRetentionGroup) verifyAudits(ctx context.Context) error {
	if g.nonce == nil {
		return ErrAudit
	}
	r := g.receipt
	body, created, err := g.audit(ctx, r.IntentAuditID, "system_backup.evidence_download.intent", 8192)
	if err != nil {
		return ErrAudit
	}
	stamp, ok := body["intent_at"].(string)
	at, err := time.Parse("2006-01-02T15:04:05.000000Z", stamp)
	if !ok || err != nil || stamp != at.UTC().Format("2006-01-02T15:04:05.000000Z") || at.Before(g.nonce.authenticated) || at.After(r.AdmittedAt) || !created.Equal(at.Truncate(time.Second)) {
		return ErrAudit
	}
	want := canonical(map[string]any{"schema_version": "system-backup-evidence-download-intent.v1", "origin_installation_id": r.Installation, "operation_public_id": r.OperationID, "evidence_id": r.EvidenceID, "evidence_row_version": r.EvidenceRowVersion, "request_hash": r.RequestHash, "manifest_sha256": r.ManifestSHA256, "claim_sha256": r.ClaimSHA256, "range_present": r.RangePresent, "range_start": r.Start, "range_end": r.End, "intent_at": stamp})
	if !bytes.Equal(canonical(body), want) || g.intentBody != nil && !bytes.Equal(g.intentBody, want) {
		return ErrAudit
	}
	g.intentBody = want
	if g.result != nil {
		link := g.result
		m, created, err := g.audit(ctx, link.resultID, "system_backup.evidence_download.result", maxDownloadResultBytes)
		if err != nil || link.at.Before(g.nonce.consumed) || !created.Equal(link.at.Truncate(time.Second)) {
			return ErrAudit
		}
		outcome, ok := m["outcome"].(string)
		number, numeric := m["bytes_written"].(json.Number)
		written, err := strconv.ParseInt(string(number), 10, 64)
		if !ok || !numeric || err != nil {
			return ErrAudit
		}
		expected := r.End - r.Start + 1
		if written < 0 || written > expected || !oneOf(outcome, "rejected", "interrupted", "local_write_complete") || outcome == "rejected" && written != 0 || outcome == "local_write_complete" && written != expected {
			return ErrAudit
		}
		result := downloadResultReceiptBody(r, g.retain, DownloadResultObservation{outcome, written}, link.at)
		if !bytes.Equal(canonical(m), result) || int64(len(result)) != link.size || hash(result) != link.digest || g.resultBody != nil && !bytes.Equal(g.resultBody, result) {
			return ErrAudit
		}
		g.resultBody = result
		g.rolling = hash(canonical(map[string]any{"schema_version": "system-backup-download-retention-group.v1", "operation_database_id": strconv.FormatInt(g.operationID, 10), "evidence_database_id": strconv.FormatInt(g.evidenceID, 10), "receipt_sha256": hash(g.private), "operation_sha256": hash(g.public), "nonce_sha256": hash(g.nonce.canonical()), "intent_sha256": hash(g.intentBody), "result_audit_id": link.resultID, "result_sha256": hash(g.resultBody), "result_at": downloadAdmissionFormatTime(link.at), "retain_until": downloadAdmissionFormatTime(g.retain)}))
	}
	g.state.verified = true
	return nil
}

// DetailRollingHash is only a digest of a fully cross-checked persisted group.
// It is not GC eligibility: all owner/artifact/hold/ref/retention guards and a
// same-transaction compact tombstone are still required before any deletion.
func (g *DownloadRetentionGroup) DetailRollingHash() (string, bool) {
	if g == nil || g.state == nil {
		return "", false
	}
	g.state.Lock()
	defer g.state.Unlock()
	if g.state.failed || !g.state.verified || g.result == nil || !digestPattern.MatchString(g.rolling) {
		return "", false
	}
	return g.rolling, true
}

func (g *DownloadRetentionGroup) matchesCommitted(c *CommittedDownloadAdmission) bool {
	if g == nil || c == nil {
		return false
	}
	r, err := CanonicalDownloadAdmissionReceipt(c.rows.receipt)
	o, e := CanonicalDownloadAdmissionOperation(c.rows.operation)
	return err == nil && e == nil && g.operationID == c.rows.operationID && g.evidenceID == c.rows.evidenceID && g.operation.OperationID == c.operationID && g.operation.ActorID == c.actor.UserID && g.operation.RequestHash == c.request.RequestHash() && g.receipt.EvidenceRowVersion == c.record.RowVersion && g.receipt.IntentAuditID == c.intentAuditID && g.receipt.ClaimSHA256 == hash([]byte(c.record.Claim)) && g.retain.Equal(c.rows.retainUntil) && bytes.Equal(g.private, r) && bytes.Equal(g.public, o)
}

func (g *DownloadRetentionGroup) attachResult(r downloadResultRetention) error {
	if g.result != nil {
		return ErrAudit
	}
	g.result = &r
	g.state.verified = false
	return nil
}

// Recheck reads only the exact L3/L5/L7 rows/ranges held above. It permanently
// poisons all copies after any mismatch; restoring rows cannot revive a group.
func (g *DownloadRetentionGroup) Recheck(ctx context.Context, tx *sql.Tx) error {
	return g.run(ctx, tx, func() error {
		if g.config.Recheck(ctx, tx) != nil || readDownloadAdmissionOperationRow(ctx, tx, g.operationID, g.evidenceID, g.operation) != nil || g.readReceipt(ctx) != nil || g.readNonce(ctx) != nil {
			return ErrAudit
		}
		if g.result != nil {
			if g.result.verify(ctx, tx) != nil {
				return ErrAudit
			}
		}
		return g.verifyAudits(ctx)
	})
}
