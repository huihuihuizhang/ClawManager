package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

var systemPendingImmutableColumns = []string{"schema_version", "public_id", "owner_target_type", "owner_target_public_id", "evidence_type", "storage_provider_role", "storage_identity_hash", "storage_ref_version", "storage_relative_key", "storage_relative_key_hash", "storage_immutable_version", "inline_payload", "content_checksum", "content_size_bytes", "object_checksum", "object_size_bytes", "plaintext_chunk_size_bytes", "chunk_count", "chunk_list_root", "media_type", "encryption", "envelope_framing_version", "kek_identity_hash", "kek_version", "envelope_hash", "redaction_classification", "expires_at", "protected_until", "created_at"}

const systemPendingMutableColumns = "storage_state,evidence_failure_code,claim_owner,claim_expires_at,row_version,observed_health,next_reconcile_at,last_checked_at"
const systemPendingChunkColumns = "chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag"

type systemPendingStored struct {
	ID, Version               int64
	State, Failure, Health    string
	Claim                     sql.NullString
	ClaimUntil, Next, Checked sql.NullTime
}

func systemPendingCounter(v int64) string { return strconv.FormatInt(v, 10) }
func systemPendingValues(r Record) []any {
	m, i := r.Manifest, r.Manifest.Identity
	return []any{"system-backup-evidence.v1", i.ID, i.OwnerType, i.OwnerID, i.Type, "evidence", r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), nil, nil, i.ContentHash, i.ContentSize, m.ObjectHash, m.ObjectSize, int64(ChunkSize), int64(len(m.Chunks)), m.ChunkRoot, i.Media, "envelope_v1", Framing, m.Key.Identity, m.Key.Version, m.EnvelopeHash, i.Classification, r.ExpiresAt, r.ProtectedUntil, r.CreatedAt}
}
func systemPendingChunkValues(c Chunk) []any {
	nonce, _ := base64.RawURLEncoding.DecodeString(c.Nonce)
	tag, _ := base64.RawURLEncoding.DecodeString(c.Tag)
	return []any{int64(c.Index), c.PlainOffset, c.PlainLength, c.PlainHash, c.FrameOffset, c.FrameLength, c.CipherHash, nonce, tag}
}
func equalSystemPendingValue(actual, expected any) bool {
	switch want := expected.(type) {
	case nil:
		return actual == nil
	case string:
		var v sql.NullString
		return v.Scan(actual) == nil && v.Valid && v.String == want
	case int64:
		var v sql.NullInt64
		return v.Scan(actual) == nil && v.Valid && v.Int64 == want
	case time.Time:
		var v sql.NullTime
		return v.Scan(actual) == nil && v.Valid && systemPeerTime(v.Time) && v.Time.Equal(want)
	case []byte:
		v, ok := actual.([]byte)
		return ok && bytes.Equal(v, want)
	}
	return false
}
func systemPendingScan(rows *sql.Rows, n int) ([]any, error) {
	values := make([]any, n)
	dest := make([]any, n)
	for i := range values {
		dest[i] = &values[i]
	}
	if rows.Scan(dest...) != nil {
		return nil, ErrUnavailable
	}
	return values, nil
}
func finishSystemPendingRows(rows *sql.Rows) error {
	if rows.Err() != nil {
		rows.Close()
		return ErrUnavailable
	}
	if rows.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

func loadSystemPending(ctx context.Context, tx pd.ReadSQL, r Record) (systemPendingStored, bool, error) {
	return loadSystemPublication(ctx, tx, r, "")
}

// exactReadyVersion is used for a final ready transition or guarded result
// admission. Pending/claim readers pass empty and still reject every ready row.
func loadSystemPublication(ctx context.Context, tx pd.ReadSQL, r Record, exactReadyVersion string) (systemPendingStored, bool, error) {
	var out systemPendingStored
	columns := "id," + strings.Join(systemPendingImmutableColumns, ",") + "," + systemPendingMutableColumns
	rows, err := tx.QueryContext(ctx, "SELECT "+columns+" FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", r.Manifest.Identity.ID)
	if err != nil {
		return out, false, ErrUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return out, false, finishSystemPendingRows(rows)
	}
	want := systemPendingValues(r)
	if exactReadyVersion != "" {
		if exactReadyVersion == "null" || len(exactReadyVersion) > 256 {
			return out, false, ErrIntegrity
		}
		for _, b := range []byte(exactReadyVersion) {
			if b < 0x20 || b > 0x7e {
				return out, false, ErrIntegrity
			}
		}
		// This is the sole mutable object locator column in the immutable set.
		for n, column := range systemPendingImmutableColumns {
			if column == "storage_immutable_version" {
				want[n] = exactReadyVersion
			}
		}
	}
	v, err := systemPendingScan(rows, 1+len(want)+8)
	if err != nil {
		return out, false, err
	}
	var id sql.NullInt64
	if id.Scan(v[0]) != nil || !id.Valid || id.Int64 <= 0 {
		return out, false, ErrIntegrity
	}
	out.ID = id.Int64
	for n, value := range want {
		if !equalSystemPendingValue(v[n+1], value) {
			return out, false, ErrIntegrity
		}
	}
	p := v[len(want)+1:]
	var state, failure, health sql.NullString
	var version sql.NullInt64
	if state.Scan(p[0]) != nil || failure.Scan(p[1]) != nil || out.Claim.Scan(p[2]) != nil || out.ClaimUntil.Scan(p[3]) != nil || version.Scan(p[4]) != nil || health.Scan(p[5]) != nil || out.Next.Scan(p[6]) != nil || out.Checked.Scan(p[7]) != nil {
		return out, false, ErrIntegrity
	}
	out.State, out.Failure, out.Version, out.Health = state.String, failure.String, version.Int64, health.String
	validState := out.State == "pending" && out.Failure == "none" || out.State == "write_unknown" && oneOf(out.Failure, "provider_unavailable", "deadline_exceeded")
	if exactReadyVersion != "" {
		validState = out.State == "ready" && out.Failure == "none"
	}
	if !state.Valid || !failure.Valid || !version.Valid || version.Int64 < 1 || !health.Valid || !oneOf(out.Health, "unknown", "healthy", "degraded") || out.Claim.Valid != out.ClaimUntil.Valid || out.Claim.Valid && out.Claim.String == "" || !validState {
		return out, false, ErrIntegrity
	}
	for _, stamp := range []sql.NullTime{out.ClaimUntil, out.Next, out.Checked} {
		if stamp.Valid && !systemPeerTime(stamp.Time) {
			return out, false, ErrIntegrity
		}
	}
	if rows.Next() {
		return out, false, ErrIntegrity
	}
	if finishSystemPendingRows(rows) != nil {
		return out, false, ErrUnavailable
	}
	chunks, err := tx.QueryContext(ctx, "SELECT "+systemPendingChunkColumns+" FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE", out.ID)
	if err != nil {
		return out, false, ErrUnavailable
	}
	defer chunks.Close()
	n := 0
	for chunks.Next() {
		if n >= len(r.Manifest.Chunks) {
			return out, false, ErrIntegrity
		}
		v, err := systemPendingScan(chunks, 9)
		if err != nil {
			return out, false, err
		}
		for j, want := range systemPendingChunkValues(r.Manifest.Chunks[n]) {
			if !equalSystemPendingValue(v[j], want) {
				return out, false, ErrIntegrity
			}
		}
		n++
	}
	if finishSystemPendingRows(chunks) != nil {
		return out, false, ErrUnavailable
	}
	if n != len(r.Manifest.Chunks) {
		return out, false, ErrIntegrity
	}
	return out, true, nil
}

func insertSystemPending(ctx context.Context, tx *pd.Transaction, r Record) (int64, error) {
	values := append(systemPendingValues(r), "pending", "none", nil, nil, int64(1), "unknown", nil, nil)
	columns := strings.Join(systemPendingImmutableColumns, ",") + "," + systemPendingMutableColumns
	query := "INSERT INTO system_backup_v2_evidence (" + columns + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + ")"
	if tx.CAS(ctx, query, values...) != nil {
		return 0, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", r.Manifest.Identity.ID)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer rows.Close()
	var id int64
	if !rows.Next() || rows.Scan(&id) != nil || id <= 0 {
		return 0, ErrIntegrity
	}
	if rows.Next() {
		return 0, ErrIntegrity
	}
	if finishSystemPendingRows(rows) != nil {
		return 0, ErrUnavailable
	}
	for _, c := range r.Manifest.Chunks {
		values := append([]any{id}, systemPendingChunkValues(c)...)
		if tx.CAS(ctx, "INSERT INTO system_backup_v2_evidence_chunks (evidence_id,"+systemPendingChunkColumns+") VALUES (?,?,?,?,?,?,?,?,?,?)", values...) != nil {
			return 0, ErrUnavailable
		}
	}
	return id, nil
}
