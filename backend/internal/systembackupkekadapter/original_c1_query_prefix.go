package systembackupkekadapter

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
)

// Comparison only: the installer independently authenticates the signed mixed
// receipt. This does not construct a producer, coverage source or authority.
// The complete protocol prefix is already locked by the caller. Match the
// original source order: its known evidence row, then only that row's existing chunk primary keys.
// Unknown rows and the three runtime capabilities are still checked by the
// complete mixed reader AFTER the KEK fence; never lock their gaps here.
func lockOriginalC1ComparisonRows(ctx context.Context, tx *sql.Tx, c1 *OriginalC1SQLSnapshot) error {
	chunkColumns := []string{"id", "evidence_id", "chunk_index", "plaintext_offset", "plaintext_length", "plaintext_sha256", "object_frame_offset", "object_frame_length", "ciphertext_sha256", "gcm_nonce", "gcm_tag"}
	if ctx == nil || ctx.Err() != nil || tx == nil || c1 == nil || len(c1.Sources) == 0 || len(c1.Sources) > 20 || !reflect.DeepEqual(c1.EvidenceColumns, runtimeInstalledEvidenceColumns) || !reflect.DeepEqual(c1.ChunkColumns, chunkColumns) || len(c1.EvidenceRows) != len(c1.Sources) {
		return ErrAuthorityWrite
	}
	evidence := map[string][]RuntimeInstalledSQLCell{}
	for _, row := range c1.EvidenceRows {
		if len(row) != len(c1.EvidenceColumns) || row[0].Null || evidence[string(row[0].Value)] != nil {
			return ErrAuthorityWrite
		}
		evidence[string(row[0].Value)] = row
	}
	chunks := map[string][][]RuntimeInstalledSQLCell{}
	chunkIDs := map[string]bool{}
	for _, row := range c1.ChunkRows {
		if len(row) != len(chunkColumns) || row[1].Null || evidence[string(row[1].Value)] == nil {
			return ErrAuthorityWrite
		}
		chunkID, err := strconv.ParseUint(string(row[0].Value), 10, 64)
		if err != nil || chunkID == 0 || row[0].Null || row[2].Null || chunkIDs[string(row[0].Value)] || strconv.FormatUint(chunkID, 10) != string(row[0].Value) || string(row[2].Value) != strconv.Itoa(len(chunks[string(row[1].Value)])) {
			return ErrAuthorityWrite
		}
		chunkIDs[string(row[0].Value)] = true
		chunks[string(row[1].Value)] = append(chunks[string(row[1].Value)], row)
	}
	validatedSources := map[string]bool{}
	for _, source := range c1.Sources {
		id := strconv.FormatInt(source.EvidenceRowID, 10)
		row := evidence[id]
		if source.EvidenceRowID < 1 || validatedSources[id] || len(row) != len(c1.EvidenceColumns) || row[2].Null || string(row[2].Value) != source.Record.Manifest.Identity.ID || len(chunks[id]) != len(source.Record.Manifest.Chunks) {
			return ErrAuthorityWrite
		}
		validatedSources[id] = true
	}
	readExact := func(query string, args []any, columns []string, want [][]RuntimeInstalledSQLCell) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return ErrAuthorityWrite
		}
		defer rows.Close()
		got, err := rows.Columns()
		if err != nil || !reflect.DeepEqual(got, columns) {
			return ErrAuthorityWrite
		}
		n := 0
		for rows.Next() {
			if n >= len(want) {
				return ErrAuthorityWrite
			}
			values := make([]sql.RawBytes, len(columns))
			dest := make([]any, len(values))
			for j := range values {
				dest[j] = &values[j]
			}
			if rows.Scan(dest...) != nil || !originalC1ExactCells(want[n], values) {
				return ErrAuthorityWrite
			}
			n++
		}
		if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || n != len(want) {
			return ErrAuthorityWrite
		}
		return nil
	}
	seen := map[string]bool{}
	for _, source := range c1.Sources {
		id := strconv.FormatInt(source.EvidenceRowID, 10)
		row := evidence[id]
		if source.EvidenceRowID < 1 || seen[id] || len(row) != len(c1.EvidenceColumns) || row[2].Null || string(row[2].Value) != source.Record.Manifest.Identity.ID || len(chunks[id]) != len(source.Record.Manifest.Chunks) {
			return ErrAuthorityWrite
		}
		seen[id] = true
		// Existing unique primary key equality avoids scanning any cap range.
		if readExact("SELECT * FROM system_backup_v2_evidence FORCE INDEX (PRIMARY) WHERE id=? AND public_id=? FOR SHARE", []any{source.EvidenceRowID, source.Record.Manifest.Identity.ID}, c1.EvidenceColumns, [][]RuntimeInstalledSQLCell{row}) != nil {
			return ErrAuthorityWrite
		}
		// Do not take an evidence_id range/gap before the fence: its final
		// next-key lock could cover a later capability's future chunk insert.
		// The original source writer first owns the parent evidence row, so
		// its existing child rows can be compared with unique primary points.
		for n, chunk := range chunks[id] {
			chunkID, err := strconv.ParseUint(string(chunk[0].Value), 10, 64)
			if err != nil || chunkID == 0 || chunk[0].Null || chunk[1].Null || chunk[2].Null || string(chunk[1].Value) != id || string(chunk[2].Value) != strconv.Itoa(n) {
				return ErrAuthorityWrite
			}
			if readExact("SELECT * FROM system_backup_v2_evidence_chunks FORCE INDEX (PRIMARY) WHERE id=? AND evidence_id=? AND chunk_index=? FOR SHARE", []any{strconv.FormatUint(chunkID, 10), source.EvidenceRowID, n}, c1.ChunkColumns, [][]RuntimeInstalledSQLCell{chunk}) != nil {
				return ErrAuthorityWrite
			}
		}
	}
	return nil
}
