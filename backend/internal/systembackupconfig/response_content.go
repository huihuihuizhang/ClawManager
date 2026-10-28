package systembackupconfig

import (
	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"
)

// StageInline is only the <=8KiB branch of the complete response adapter. Call
// after live authorization/capacity in the mutation's caller-owned transaction.
// It neither creates write authority nor commits. A large body must go through
// encrypted immutable publication and atomic binding, never this branch.
func (c ConfigMutationResponseContent) StageInline(ctx context.Context, tx *sql.Tx, now time.Time) (int64, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || len(c.payload) < 2 || len(c.payload) > 8192 || now.Before(c.created) || !now.Before(c.until) || checkDatabase(ctx, tx, c.database) != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence
(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at,created_at)
SELECT ?,'system',?,'diagnostic','inline',?,?,?,'application/json','none','internal','healthy',?,?
WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<?`, c.identity.ID, c.identity.Installation, c.payload, c.identity.ContentHash, len(c.payload), c.retain.UTC(), c.created.UTC(), c.created.UTC(), c.until.UTC())
	if err != nil {
		return 0, sec.ErrProviderEvidenceStorage
	}
	if !oneRow(result, nil) {
		return 0, sec.ErrRegistrationUnavailable
	}
	id, err := result.LastInsertId()
	if err != nil || id < 1 {
		return 0, sec.ErrProviderEvidenceStorage
	}
	return id, nil
}

// BindPublished binds an ALREADY durably published external response in the
// caller's transaction. The C-owned publisher must have persisted its intent
// before PUT and resolved the exact immutable object; this method cannot
// promote pending/write_unknown, manufacture health, or perform provider I/O.
// Caller must still recheck the publication authority and c.ValidUntil before
// commit. Returning the locked ID lets the operation FK bind atomically.
func (c ConfigMutationResponseContent) BindPublished(ctx context.Context, tx *sql.Tx, p ev.Prepared, ref ev.Ref, now time.Time) (int64, error) {
	m := p.Manifest()
	if ctx == nil || ctx.Err() != nil || tx == nil || len(c.payload) <= 8192 || m.Identity != c.identity || m.Key != c.kek || len(m.Chunks) != 1 || ref.Identity != c.store.IdentityHash || ref.Version != c.store.Version || !configMutationResponseRelativeKey(ref.RelativeKey) || ref.ImmutableVersion == "" || ref.ImmutableVersion == "null" || len(ref.ImmutableVersion) > 256 || now.Before(c.created) || !now.Before(c.until) || checkDatabase(ctx, tx, c.database) != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	var id, contentSize, objectSize, chunkSize, count int64
	var schema, publicID, ownerType, owner, evidenceType, state, failure, health, provider, identity, version, key, keyHash, immutable, contentHash, objectHash, root, media, encryption, framing, kekIdentity, kekVersion, envelopeHash, classification string
	var expiry, created time.Time
	err := tx.QueryRowContext(ctx, `SELECT id,schema_version,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,
storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,
content_checksum,content_size_bytes,object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_count,chunk_list_root,media_type,encryption,envelope_framing_version,
kek_identity_hash,kek_version,envelope_hash,redaction_classification,expires_at,created_at
FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE`, c.identity.ID).Scan(&id, &schema, &publicID, &ownerType, &owner, &evidenceType, &state, &failure, &health,
		&provider, &identity, &version, &key, &keyHash, &immutable, &contentHash, &contentSize, &objectHash, &objectSize, &chunkSize, &count, &root, &media, &encryption, &framing,
		&kekIdentity, &kekVersion, &envelopeHash, &classification, &expiry, &created)
	if err != nil || id < 1 || schema != "system-backup-evidence.v1" || publicID != c.identity.ID || ownerType != "system" || owner != c.identity.Installation || evidenceType != "diagnostic" || state != "ready" || failure != "none" || health != "healthy" || provider != "evidence" || identity != ref.Identity || version != ref.Version || key != ref.RelativeKey || keyHash != registrationHash(ref.RelativeKey) || immutable != ref.ImmutableVersion || contentHash != c.identity.ContentHash || contentSize != c.identity.ContentSize || objectHash != m.ObjectHash || objectSize != m.ObjectSize || chunkSize != ev.ChunkSize || count != 1 || root != m.ChunkRoot || media != "application/json" || encryption != "envelope_v1" || framing != ev.Framing || kekIdentity != m.Key.Identity || kekVersion != m.Key.Version || envelopeHash != m.EnvelopeHash || classification != "internal" || expiry.Before(c.retain) || created.Before(c.created) || created.After(now) {
		return 0, sec.ErrRegistrationUnavailable
	}
	var index, offset, length, frameOffset, frameLength int64
	var plainHash, cipherHash string
	var nonce, tag []byte
	chunk := m.Chunks[0]
	rows, err := tx.QueryContext(ctx, `SELECT chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE`, id)
	if err != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, sec.ErrRegistrationUnavailable
	}
	err = rows.Scan(&index, &offset, &length, &plainHash, &frameOffset, &frameLength, &cipherHash, &nonce, &tag)
	if err != nil || index != chunk.Index || offset != chunk.PlainOffset || length != chunk.PlainLength || plainHash != chunk.PlainHash || frameOffset != chunk.FrameOffset || frameLength != chunk.FrameLength || cipherHash != chunk.CipherHash || base64.RawURLEncoding.EncodeToString(nonce) != chunk.Nonce || base64.RawURLEncoding.EncodeToString(tag) != chunk.Tag || ctx.Err() != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	if rows.Next() || rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	return id, nil
}

func configMutationResponseRelativeKey(key string) bool {
	if len(key) < 1 || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return false
	}
	for _, ch := range key {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.' || ch == '-' || ch == '/') {
			return false
		}
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
