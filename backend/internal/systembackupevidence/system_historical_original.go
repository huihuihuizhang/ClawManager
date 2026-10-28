package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/base64"
	"reflect"
	"strconv"

	pd "clawreef/internal/systembackupproducer"
)

// loadSystemHistoricalRecord is a comparison primitive for a future
// independently authorized historical reader. The caller must already own D's
// transaction and current identity/reference locks. Neither a history value nor
// this reconstruction authorizes a provider call or recreates an ExecutionHandle.
// It reads the locked A registry/chunks, rebuilds the original manifest, then
// checks the complete D historical binding and rereads the same locked A rows.
func loadSystemHistoricalRecord(ctx context.Context, tx *pd.Transaction, history pd.HistoricalBindingRecord, channel ProducerEvidenceChannel) (Record, error) {
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(tx) {
		return Record{}, ErrDenied
	}
	var h pd.HistoricalBindingRecord
	if pd.DecodeRecord(canonical(history), &h) != nil || h.Evidence.ImmutableVersion != nil {
		return Record{}, ErrInvalid
	}
	contentBytes, e1 := strconv.ParseInt(string(h.Evidence.ContentBytes), 10, 64)
	objectBytes, e2 := strconv.ParseInt(string(h.Evidence.ObjectBytes), 10, 64)
	if e1 != nil || e2 != nil || contentBytes <= 0 || contentBytes > MaxCapabilityContent || objectBytes <= 0 {
		return Record{}, ErrIntegrity
	}
	const columns = "id,envelope_hash,chunk_list_root,storage_immutable_version"
	rows, err := tx.QueryContext(ctx, "SELECT "+columns+" FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", h.Evidence.EvidenceID)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	actualColumns, err := rows.Columns()
	if err != nil || !reflect.DeepEqual(actualColumns, []string{"id", "envelope_hash", "chunk_list_root", "storage_immutable_version"}) {
		rows.Close()
		return Record{}, ErrIntegrity
	}
	if !rows.Next() {
		err = finishSystemPendingRows(rows)
		if err != nil {
			return Record{}, err
		}
		return Record{}, ErrIntegrity
	}
	values, err := systemPendingScan(rows, 4)
	if err != nil {
		rows.Close()
		return Record{}, err
	}
	var id sql.NullInt64
	var envelope, root, immutable sql.NullString
	if id.Scan(values[0]) != nil || envelope.Scan(values[1]) != nil || root.Scan(values[2]) != nil || immutable.Scan(values[3]) != nil ||
		!id.Valid || id.Int64 <= 0 || !envelope.Valid || !root.Valid || !digestPattern.MatchString(envelope.String) || !digestPattern.MatchString(root.String) {
		rows.Close()
		return Record{}, ErrIntegrity
	}
	if rows.Next() {
		rows.Close()
		return Record{}, ErrIntegrity
	}
	if err := finishSystemPendingRows(rows); err != nil {
		return Record{}, err
	}
	chunkRows, err := tx.QueryContext(ctx, "SELECT "+systemPendingChunkColumns+" FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE", id.Int64)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	actualColumns, err = chunkRows.Columns()
	if err != nil || !reflect.DeepEqual(actualColumns, []string{"chunk_index", "plaintext_offset", "plaintext_length", "plaintext_sha256", "object_frame_offset", "object_frame_length", "ciphertext_sha256", "gcm_nonce", "gcm_tag"}) {
		chunkRows.Close()
		return Record{}, ErrIntegrity
	}
	chunks := make([]Chunk, 0, 1)
	for chunkRows.Next() {
		if len(chunks) >= 1024 {
			chunkRows.Close()
			return Record{}, ErrIntegrity
		}
		v, err := systemPendingScan(chunkRows, 9)
		if err != nil {
			chunkRows.Close()
			return Record{}, err
		}
		c, err := decodeSystemHistoricalChunk(v, string(h.Evidence.EvidenceID))
		if err != nil {
			chunkRows.Close()
			return Record{}, err
		}
		chunks = append(chunks, c)
	}
	if err := finishSystemPendingRows(chunkRows); err != nil {
		return Record{}, err
	}
	if len(chunks) == 0 {
		return Record{}, ErrIntegrity
	}
	manifest := Manifest{
		Identity: Identity{Installation: string(h.Scope.Installation), ID: string(h.Evidence.EvidenceID), OwnerType: h.Evidence.OwnerType,
			OwnerID: string(h.Evidence.OwnerID), Type: h.Evidence.EvidenceType, Media: "application/json", Classification: h.Evidence.Classification,
			ContentHash: string(h.Evidence.ContentHash), ContentSize: contentBytes},
		Key:          KeyRef{Identity: string(h.Evidence.KEKIdentityHash), Version: string(h.Evidence.KEKVersion)},
		EnvelopeHash: envelope.String, ObjectHash: string(h.Evidence.ObjectHash), ObjectSize: objectBytes,
		HeaderSize: chunks[0].FrameOffset, ChunkRoot: root.String, Chunks: chunks,
	}
	original, _, err := systemManifestRecord(manifest, channel, h)
	if err != nil {
		return Record{}, err
	}
	version := ""
	if immutable.Valid {
		version = immutable.String
	}
	stored, found, err := loadSystemPublication(ctx, tx, original, version)
	if err != nil || !found {
		if err != nil {
			return Record{}, err
		}
		return Record{}, ErrIntegrity
	}
	original.State, original.Failure, original.RowVersion = stored.State, stored.Failure, stored.Version
	original.Ref.ImmutableVersion = version
	if stored.Claim.Valid {
		original.Claim, original.ClaimUntil = stored.Claim.String, stored.ClaimUntil.Time
	}
	return original, nil
}

func decodeSystemHistoricalChunk(v []any, evidenceID string) (Chunk, error) {
	var numbers [5]sql.NullInt64
	var digests [2]sql.NullString
	var nonce, tag []byte
	for i, index := range []int{0, 1, 2, 4, 5} {
		if numbers[i].Scan(v[index]) != nil || !numbers[i].Valid {
			return Chunk{}, ErrIntegrity
		}
	}
	for i, index := range []int{3, 6} {
		if digests[i].Scan(v[index]) != nil || !digests[i].Valid {
			return Chunk{}, ErrIntegrity
		}
	}
	var ok bool
	if nonce, ok = v[7].([]byte); !ok || len(nonce) != 12 {
		return Chunk{}, ErrIntegrity
	}
	if tag, ok = v[8].([]byte); !ok || len(tag) != 16 {
		return Chunk{}, ErrIntegrity
	}
	return Chunk{EvidenceID: evidenceID, Index: numbers[0].Int64, PlainOffset: numbers[1].Int64,
		PlainLength: numbers[2].Int64, PlainHash: digests[0].String, FrameOffset: numbers[3].Int64,
		FrameLength: numbers[4].Int64, CipherHash: digests[1].String,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Tag: base64.RawURLEncoding.EncodeToString(tag)}, nil
}
