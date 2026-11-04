package systembackupkekadapter

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"strconv"
)

// The whole actual row/default/EOF universe. Owned IDs originate in original
// INSERT->registry readback, never from a prefix/type or supplied ID list.
func captureOriginalC1EvidenceRows(ctx context.Context, tx *sql.Tx, snapshot *OriginalC1SQLSnapshot) error {
	if tx == nil || snapshot == nil || len(snapshot.Sources) == 0 {
		return ErrAuthorityWrite
	}
	ids := map[string]string{}
	expectedChunks := map[string]int{}
	for _, s := range snapshot.Sources {
		id := strconv.FormatInt(s.EvidenceRowID, 10)
		if s.EvidenceRowID < 1 || ids[id] != "" {
			return ErrAuthorityWrite
		}
		ids[id] = s.Record.Manifest.Identity.ID
		expectedChunks[id] = len(s.Record.Manifest.Chunks)
	}
	read := func(query string, want []string) ([]string, [][]RuntimeInstalledSQLCell, error) {
		rows, e := tx.QueryContext(ctx, query)
		if e != nil {
			return nil, nil, ErrAuthorityWrite
		}
		defer rows.Close()
		columns, e := rows.Columns()
		if e != nil || !reflect.DeepEqual(columns, want) {
			return nil, nil, ErrAuthorityWrite
		}
		var result [][]RuntimeInstalledSQLCell
		for rows.Next() {
			if len(result) >= 20480 {
				return nil, nil, ErrAuthorityWrite
			}
			v := make([]sql.RawBytes, len(columns))
			dest := make([]any, len(v))
			for n := range v {
				dest[n] = &v[n]
			}
			if rows.Scan(dest...) != nil {
				return nil, nil, ErrAuthorityWrite
			}
			cells := make([]RuntimeInstalledSQLCell, len(v))
			for n, b := range v {
				cells[n] = RuntimeInstalledSQLCell{Null: b == nil, Value: bytes.Clone(b)}
			}
			result = append(result, cells)
		}
		if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
			return nil, nil, ErrAuthorityWrite
		}
		return columns, result, nil
	}
	cols, rows, e := read("SELECT * FROM system_backup_v2_evidence ORDER BY id FOR SHARE", runtimeInstalledEvidenceColumns)
	if e != nil || len(rows) != len(ids) {
		return ErrAuthorityWrite
	}
	index := map[string]int{}
	for n, c := range cols {
		index[c] = n
	}
	seen := map[string]bool{}
	for _, row := range rows {
		id := string(row[index["id"]].Value)
		if seen[id] || ids[id] == "" || string(row[index["public_id"]].Value) != ids[id] || !row[index["origin_installation_id"]].Null {
			return ErrAuthorityWrite
		}
		seen[id] = true
		created, e1 := runtimeInstalledSQLTime(string(row[index["created_at"]].Value))
		updated, e2 := runtimeInstalledSQLTime(string(row[index["updated_at"]].Value))
		if e1 != nil || e2 != nil || updated.Before(created) || updated.After(snapshot.ObservedAt) {
			return ErrAuthorityWrite
		}
	}
	chunkColumns := []string{"id", "evidence_id", "chunk_index", "plaintext_offset", "plaintext_length", "plaintext_sha256", "object_frame_offset", "object_frame_length", "ciphertext_sha256", "gcm_nonce", "gcm_tag"}
	cc, cr, e := read("SELECT * FROM system_backup_v2_evidence_chunks ORDER BY evidence_id,chunk_index FOR SHARE", chunkColumns)
	if e != nil {
		return ErrAuthorityWrite
	}
	counts := map[string]int{}
	chunkIDs := map[uint64]bool{}
	for _, row := range cr {
		chunkID, ie := strconv.ParseUint(string(row[0].Value), 10, 64)
		if ie != nil || chunkID == 0 || chunkIDs[chunkID] {
			return ErrAuthorityWrite
		}
		chunkIDs[chunkID] = true
		id := string(row[1].Value)
		n, e := strconv.Atoi(string(row[2].Value))
		if e != nil || ids[id] == "" || n != counts[id] || n >= expectedChunks[id] {
			return ErrAuthorityWrite
		}
		counts[id]++
	}
	for id, n := range expectedChunks {
		if counts[id] != n {
			return ErrAuthorityWrite
		}
	}
	snapshot.EvidenceColumns, snapshot.EvidenceRows = cols, rows
	snapshot.ChunkColumns, snapshot.ChunkRows = cc, cr
	return nil
}
