package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

// SQLPolicy is the D-owned integration point for the existing authoritative
// config, owner, references, RBAC and audit tables. No permissive fallback is
// provided. LockScope must lock config/owner/reference admission in the common
// control-plane lock order BEFORE this adapter locks the evidence row.
type SQLPolicy interface {
	LockScope(context.Context, *sql.Tx, string, Identity) error
	Admit(context.Context, *sql.Tx, Record, time.Time) error
	Authorize(context.Context, *sql.Tx, Actor, Record, []string) error
	Deletable(context.Context, *sql.Tx, Record, time.Time) error
	Audit(context.Context, *sql.Tx, Audit) error
	OwnerDeadline(context.Context, *sql.Tx, Identity) (time.Time, error)
}
type SQLRegistry struct {
	DB                                 *sql.DB
	Installation, ServerUUID, Database string
	Policy                             SQLPolicy
}
type sqlLocked struct {
	registry SQLRegistry
	tx       *sql.Tx
	record   Record
	now      time.Time
}

func (t *sqlLocked) Record() Record {
	r := t.record
	r.Manifest.Chunks = append([]Chunk(nil), r.Manifest.Chunks...)
	return r
}
func (t *sqlLocked) Time() time.Time { return t.now }
func (t *sqlLocked) Authorize(ctx context.Context, a Actor, p []string) error {
	return t.registry.Policy.Authorize(ctx, t.tx, a, t.Record(), p)
}
func (t *sqlLocked) Deletable(ctx context.Context) error {
	return t.registry.Policy.Deletable(ctx, t.tx, t.Record(), t.now)
}
func (t *sqlLocked) Audit(ctx context.Context, a Audit) error {
	return t.registry.Policy.Audit(ctx, t.tx, a)
}

func (s SQLRegistry) begin(ctx context.Context) (*sql.Tx, time.Time, error) {
	if s.DB == nil || s.Policy == nil || !installationPattern.MatchString(s.Installation) || s.ServerUUID == "" || s.Database == "" {
		return nil, time.Time{}, ErrUnavailable
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, time.Time{}, ErrUnavailable
	}
	var server, name string
	var now time.Time
	var offset int64
	e = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &name, &now, &offset)
	if e != nil || server != s.ServerUUID || name != s.Database || now.IsZero() || offset != 0 {
		tx.Rollback()
		return nil, time.Time{}, ErrUnavailable
	}
	return tx, now, nil
}

func (s SQLRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	if !idPattern.MatchString(id) || fn == nil {
		return ErrInvalid
	}
	tx, now, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// This first read is only an immutable ownership hint. Scope is authorized
	// by the mandatory policy, and the locked row is compared to the hint.
	i := Identity{Installation: s.Installation, ID: id}
	e = tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&i.OwnerType, &i.OwnerID)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return ErrUnavailable
	}
	if e = s.Policy.LockScope(ctx, tx, s.Installation, i); e != nil {
		return boundary(e)
	}
	r, e := s.load(ctx, tx, id)
	if e != nil {
		return e
	}
	if r.Manifest.Identity.OwnerType != i.OwnerType || r.Manifest.Identity.OwnerID != i.OwnerID {
		return ErrIntegrity
	}
	// Lock waits may consume the entire lease; sample authoritative time again.
	if e = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); e != nil {
		return ErrUnavailable
	}
	if e = fn(&sqlLocked{s, tx, r, now}); e != nil {
		return boundary(e)
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}

func (s SQLRegistry) load(ctx context.Context, tx *sql.Tx, id string) (Record, error) {
	if nilSystemAdapter(s.Policy) {
		return Record{}, ErrUnavailable
	}
	return s.loadManifest(ctx, tx, id, true, s.Policy.OwnerDeadline)
}

// Both paths decode exactly the same immutable envelope/chunks. The preview
// caller supplies its purpose-specific current owner authorization and never
// takes the evidence/chunk FOR UPDATE locks that belong to admission's L9.
func (s SQLRegistry) loadManifest(ctx context.Context, tx *sql.Tx, id string, locking bool, owner func(context.Context, *sql.Tx, Identity) (time.Time, error)) (Record, error) {
	lock := ""
	if locking {
		lock = " FOR UPDATE"
	}
	r := Record{}
	r.Manifest.Identity.Installation = s.Installation
	r.Manifest.Identity.ID = id
	i := &r.Manifest.Identity
	m := &r.Manifest
	var dbID int64
	var encryption string
	var identity, version, key, immutable, objectHash, envelopeHash, kekIdentity, kekVersion, root, claim sql.NullString
	var role, keyHash, framing sql.NullString
	var objectSize, chunkSize sql.NullInt64
	var protected, until sql.NullTime
	var count int64
	e := tx.QueryRowContext(ctx, `SELECT id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,
storage_identity_hash,storage_ref_version,storage_relative_key,storage_immutable_version,content_checksum,content_size_bytes,
object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_count,chunk_list_root,media_type,encryption,kek_identity_hash,kek_version,envelope_hash,
redaction_classification,claim_owner,claim_expires_at,expires_at,protected_until,row_version,created_at,storage_provider_role,storage_relative_key_hash,envelope_framing_version
FROM system_backup_v2_evidence WHERE public_id=?`+lock, id).Scan(&dbID, &i.OwnerType, &i.OwnerID, &i.Type, &r.State, &r.Failure,
		&identity, &version, &key, &immutable, &i.ContentHash, &i.ContentSize, &objectHash, &objectSize, &chunkSize, &count, &root, &i.Media, &encryption, &kekIdentity, &kekVersion, &envelopeHash,
		&i.Classification, &claim, &until, &r.ExpiresAt, &protected, &r.RowVersion, &r.CreatedAt, &role, &keyHash, &framing)
	if e != nil {
		return r, ErrUnavailable
	}
	if encryption != "envelope_v1" || r.State == "inline" {
		return r, ErrState
	}
	r.Ref = Ref{identity.String, version.String, key.String, immutable.String}
	m.Key = KeyRef{kekIdentity.String, kekVersion.String}
	m.EnvelopeHash = envelopeHash.String
	m.ObjectHash = objectHash.String
	m.ObjectSize = objectSize.Int64
	m.ChunkRoot = root.String
	r.Claim = claim.String
	r.ClaimUntil = until.Time
	r.ProtectedUntil = protected.Time
	// Owner deadline is NOT an evidence-table field; policy must resolve the
	// immutable owner's actual deadline. The SQL adapter requires this resolver.
	r.OwnerDeadline, e = owner(ctx, tx, *i)
	if e != nil {
		return r, ErrUnavailable
	}
	if r.State == "deleted" {
		return r, nil
	}
	if role.String != "evidence" || keyHash.String != hash([]byte(r.Ref.RelativeKey)) || framing.String != Framing {
		return r, ErrIntegrity
	}
	if count < 1 || count > 1024 || chunkSize.Int64 != ChunkSize {
		return r, ErrIntegrity
	}
	rows, e := tx.QueryContext(ctx, `SELECT chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index`+lock, dbID)
	if e != nil {
		return r, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		c := Chunk{EvidenceID: id}
		var nonce, tag []byte
		if rows.Scan(&c.Index, &c.PlainOffset, &c.PlainLength, &c.PlainHash, &c.FrameOffset, &c.FrameLength, &c.CipherHash, &nonce, &tag) != nil {
			return r, ErrUnavailable
		}
		c.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
		c.Tag = base64.RawURLEncoding.EncodeToString(tag)
		m.Chunks = append(m.Chunks, c)
		if len(m.Chunks) > 1024 {
			return r, ErrIntegrity
		}
	}
	if rows.Err() != nil || int64(len(m.Chunks)) != count {
		return r, ErrIntegrity
	}
	m.HeaderSize = m.Chunks[0].FrameOffset
	if !validRecord(r) {
		return r, ErrIntegrity
	}
	return r, nil
}

func (s SQLRegistry) PersistPending(ctx context.Context, r Record) error {
	// Small system evidence must use the separate producer transaction owner
	// with its final Guard. The legacy registry cannot admit that new path.
	if !r.Manifest.Identity.valid() {
		return ErrInvalid
	}
	if !validRecord(r) || r.State != "pending" || r.Failure != "none" || r.RowVersion != 1 || r.Ref.ImmutableVersion != "" || r.Manifest.Identity.Installation != s.Installation {
		return ErrInvalid
	}
	tx, now, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.Policy.LockScope(ctx, tx, s.Installation, r.Manifest.Identity); e != nil {
		return boundary(e)
	}
	if e = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); e != nil {
		return ErrUnavailable
	}
	deadline, e := s.Policy.OwnerDeadline(ctx, tx, r.Manifest.Identity)
	if e != nil || !deadline.Equal(r.OwnerDeadline) {
		return ErrState
	}
	if !now.Before(r.OwnerDeadline) || r.CreatedAt.After(now) {
		return ErrState
	}
	if e = s.Policy.Admit(ctx, tx, r, now); e != nil {
		return boundary(e)
	}
	m := r.Manifest
	i := m.Identity
	result, e := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence
(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,storage_provider_role,
storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,content_checksum,content_size_bytes,
object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_count,chunk_list_root,media_type,encryption,envelope_framing_version,
kek_identity_hash,kek_version,envelope_hash,redaction_classification,observed_health,expires_at,protected_until,created_at)
VALUES (?,?,?,?,'pending','none','evidence',?,?,?,?,?,?,?,?,?,?,?,?, 'envelope_v1',?,?,?,?,?,'unknown',?,?,?)`,
		i.ID, i.OwnerType, i.OwnerID, i.Type, r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), i.ContentHash, i.ContentSize,
		m.ObjectHash, m.ObjectSize, ChunkSize, len(m.Chunks), m.ChunkRoot, i.Media, Framing, m.Key.Identity, m.Key.Version, m.EnvelopeHash, i.Classification, r.ExpiresAt, nullTime(r.ProtectedUntil), r.CreatedAt)
	if e != nil {
		return ErrUnavailable
	}
	dbID, e := result.LastInsertId()
	if e != nil || dbID <= 0 {
		return ErrUnavailable
	}
	for _, c := range m.Chunks {
		nonce, _ := base64.RawURLEncoding.DecodeString(c.Nonce)
		tag, _ := base64.RawURLEncoding.DecodeString(c.Tag)
		_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) VALUES (?,?,?,?,?,?,?,?,?,?)`, dbID, c.Index, c.PlainOffset, c.PlainLength, c.PlainHash, c.FrameOffset, c.FrameLength, c.CipherHash, nonce, tag)
		if e != nil {
			return ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}

func (t *sqlLocked) Save(ctx context.Context, next Record) error {
	return t.save(ctx, next, nil)
}

type evidenceObservation struct {
	health string
	next   time.Time
}

// saveRecoveryResult is explicit: acquiring/releasing a download or worker
// claim must never manufacture a successful provider observation. Metadata and
// the result share one row-version CAS and the caller's audit transaction.
func (t *sqlLocked) saveRecoveryResult(ctx context.Context, next Record, retry time.Duration) error {
	old := t.record
	if !oneOf(old.State, "pending", "write_unknown") || old.Claim == "" || !t.now.Before(old.ClaimUntil) || next.Claim != "" || !next.ClaimUntil.IsZero() || t.now.IsZero() || retry < 5*time.Second || retry > 600*time.Second || retry%time.Second != 0 {
		return ErrState
	}
	o := evidenceObservation{}
	switch {
	case next.State == "ready" && next.Failure == "none" && next.Ref.valid(true):
		o.health = "healthy"
	case next.State == "write_unknown" && next.Failure == "provider_unavailable":
		o.health = "unknown"
		o.next = t.now.Add(retry)
	case next.State == "write_failed" && next.Failure == "checksum_mismatch":
		o.health = "degraded"
	default:
		return ErrState
	}
	return t.save(ctx, next, &o)
}

// A GC result is an observation of deletion, not renewed evidence readability.
// Claims and idempotent tombstone reads must never refresh this observation.
func (t *sqlLocked) saveGCResult(ctx context.Context, next Record, retry time.Duration) error {
	old := t.record
	if old.State != "deleting" || old.Claim == "" || !t.now.Before(old.ClaimUntil) || next.Claim != "" || !next.ClaimUntil.IsZero() || t.now.IsZero() || retry < 5*time.Second || retry > 600*time.Second || retry%time.Second != 0 {
		return ErrState
	}
	o := evidenceObservation{health: "unknown"}
	switch {
	case next.State == "deleted" && next.Failure == "none" && next.Ref == (Ref{}) && len(next.Manifest.Chunks) == 0:
		// Authoritative absence completes GC, not availability/KEK health.
	case next.State == "delete_failed" && oneOf(next.Failure, "provider_unavailable", "permission_denied", "checksum_mismatch", "deadline_exceeded", "internal"):
		if oneOf(next.Failure, "permission_denied", "checksum_mismatch") {
			o.health = "degraded"
		}
		o.next = t.now.Add(retry)
	default:
		return ErrState
	}
	return t.save(ctx, next, &o)
}

func (t *sqlLocked) save(ctx context.Context, next Record, observation *evidenceObservation) error {
	old := t.record
	if next.RowVersion != old.RowVersion+1 || next.Manifest.Identity != old.Manifest.Identity || next.CreatedAt != old.CreatedAt || next.ExpiresAt.Before(old.ExpiresAt) || next.ProtectedUntil.Before(old.ProtectedUntil) {
		return ErrConflict
	}
	allowed := next.State == old.State || oneOf(old.State, "pending", "write_unknown") && oneOf(next.State, "ready", "write_unknown", "write_failed") || oneOf(old.State, "ready", "delete_failed") && next.State == "deleting" || old.State == "deleting" && oneOf(next.State, "deleted", "delete_failed")
	if !allowed {
		return ErrState
	}
	var result sql.Result
	var e error
	if next.State == "deleted" {
		// Requires the accompanying D migration proposal; old 065 constraints
		// reject this atomically rather than keeping a misleading ready payload.
		_, e = t.tx.ExecContext(ctx, "DELETE c FROM system_backup_v2_evidence_chunks c JOIN system_backup_v2_evidence e ON e.id=c.evidence_id WHERE e.public_id=? AND e.row_version=? AND e.storage_state='deleting'", old.Manifest.Identity.ID, old.RowVersion)
		if e != nil {
			return ErrUnavailable
		}
		query := `UPDATE system_backup_v2_evidence SET storage_state='deleted',evidence_failure_code='none',storage_provider_role=NULL,storage_identity_hash=NULL,storage_ref_version=NULL,storage_relative_key=NULL,storage_relative_key_hash=NULL,storage_immutable_version=NULL,inline_payload=NULL,object_checksum=NULL,object_size_bytes=NULL,plaintext_chunk_size_bytes=NULL,chunk_count=0,chunk_list_root=NULL,claim_owner=NULL,claim_expires_at=NULL`
		var args []any
		if observation != nil {
			query += `,observed_health=?,last_checked_at=?,next_reconcile_at=?`
			args = append(args, observation.health, t.now.UTC(), nullTime(observation.next))
		}
		query += `,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND storage_state='deleting'`
		args = append(args, old.Manifest.Identity.ID, old.RowVersion)
		result, e = t.tx.ExecContext(ctx, query, args...)
	} else {
		if hash(canonical(next.Manifest)) != hash(canonical(old.Manifest)) || next.Ref.Identity != old.Ref.Identity || next.Ref.Version != old.Ref.Version || next.Ref.RelativeKey != old.Ref.RelativeKey || old.Ref.ImmutableVersion != "" && next.Ref.ImmutableVersion != old.Ref.ImmutableVersion {
			return ErrIntegrity
		}
		query := `UPDATE system_backup_v2_evidence SET storage_state=?,evidence_failure_code=?,storage_immutable_version=?,claim_owner=?,claim_expires_at=?,expires_at=?,protected_until=?`
		args := []any{next.State, next.Failure, nullString(next.Ref.ImmutableVersion), nullString(next.Claim), nullTime(next.ClaimUntil), next.ExpiresAt, nullTime(next.ProtectedUntil)}
		if observation != nil {
			query += `,observed_health=?,last_checked_at=?,next_reconcile_at=?`
			args = append(args, observation.health, t.now.UTC(), nullTime(observation.next))
		}
		query += `,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=?`
		args = append(args, old.Manifest.Identity.ID, old.RowVersion)
		result, e = t.tx.ExecContext(ctx, query, args...)
	}
	if e != nil {
		return ErrUnavailable
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	t.record = next
	return nil
}
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
