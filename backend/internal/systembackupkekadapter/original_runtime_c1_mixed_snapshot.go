package systembackupkekadapter

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Only the original live C1 producer's opaque complete source enters staging.
// C1 prefix is authenticated/locked BEFORE the original KEK fence/cap writes.
func (w *InstallationAuthorityWriter) StageInitialRuntimeAuthoritiesWithC1Snapshot(ctx context.Context, tx *sql.Tx, raw, signature []byte, caps []OriginalRuntimeCapabilityImport, now time.Time, c1 *OriginalC1SQLClosure) (RuntimeInstalledSQLSnapshot, error) {
	var zero RuntimeInstalledSQLSnapshot
	if w == nil || tx == nil || c1 == nil {
		return zero, ErrAuthorityWrite
	}
	source, e := c1.ReadCurrent(ctx, tx)
	if e != nil || source.Database != w.database || source.InstallationID != w.installation {
		return zero, ErrAuthorityWrite
	}
	var before uint64
	e = tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, w.installation).Scan(&before)
	if e != nil && e != sql.ErrNoRows {
		return zero, ErrAuthorityWrite
	}
	if w.StageInitialRuntimeAuthorities(ctx, tx, raw, signature, caps, now) != nil {
		return zero, ErrAuthorityWrite
	}
	r, e := readRuntimeInstalledSQLSnapshotTx(ctx, tx, w.database, w.installation, raw, signature, caps, true, false, &source)
	if e != nil || before == ^uint64(0) || r.FenceAfter != before+1 {
		return zero, ErrAuthorityWrite
	}
	r.FenceBefore = before
	return r, nil
}

// Comparison read, NOT a receipt/DTO authentication constructor. Installer must
// first authenticate the actual purpose-signed mixed receipt through its
// independently enrolled Plan/material. Every original C1 byte stays checked.
func ReadMixedRuntimeInstalledSQLSnapshotTx(ctx context.Context, tx *sql.Tx, database reg.DatabaseIdentity, installation string, mapping, signature []byte, caps []OriginalRuntimeCapabilityImport, locked bool, c1 *OriginalC1SQLSnapshot, controls ...*OriginalAdoptionControlCut) (RuntimeInstalledSQLSnapshot, error) {
	if c1 == nil {
		return RuntimeInstalledSQLSnapshot{}, ErrAuthorityWrite
	}
	return readRuntimeInstalledSQLSnapshotTx(ctx, tx, database, installation, mapping, signature, caps, locked, false, c1, controls...)
}

func QueryMixedRuntimeInstalledSQLSnapshotTx(ctx context.Context, tx *sql.Tx, database reg.DatabaseIdentity, installation string, mapping, signature []byte, caps []OriginalRuntimeCapabilityImport, c1 *OriginalC1SQLSnapshot) (RuntimeInstalledSQLSnapshot, error) {
	if c1 == nil {
		return RuntimeInstalledSQLSnapshot{}, ErrAuthorityWrite
	}
	return readRuntimeInstalledSQLSnapshotTx(ctx, tx, database, installation, mapping, signature, caps, true, true, c1)
}

func originalC1EvidenceRow(c1 *OriginalC1SQLSnapshot, id, publicID string) ([]RuntimeInstalledSQLCell, bool) {
	if c1 == nil || len(c1.EvidenceColumns) != len(runtimeInstalledEvidenceColumns) || !reflect.DeepEqual(c1.EvidenceColumns, runtimeInstalledEvidenceColumns) {
		return nil, false
	}
	for _, row := range c1.EvidenceRows {
		if len(row) != len(c1.EvidenceColumns) {
			return nil, false
		}
		if string(row[0].Value) == id && string(row[2].Value) == publicID {
			return row, true
		}
	}
	return nil, false
}

func originalC1ExactCells(cells []RuntimeInstalledSQLCell, values []sql.RawBytes) bool {
	if len(cells) != len(values) {
		return false
	}
	for n, v := range values {
		if cells[n].Null != (v == nil) || !bytes.Equal(cells[n].Value, v) {
			return false
		}
	}
	return true
}

func verifyOriginalC1ExactChunks(ctx context.Context, tx *sql.Tx, c1 OriginalC1SQLSnapshot) error {
	rows, e := tx.QueryContext(ctx, "SELECT * FROM system_backup_v2_evidence_chunks ORDER BY evidence_id,chunk_index FOR SHARE")
	if e != nil {
		return ErrAuthorityWrite
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil || !reflect.DeepEqual(cols, c1.ChunkColumns) || len(cols) != 11 {
		return ErrAuthorityWrite
	}
	n := 0
	for rows.Next() {
		if n >= len(c1.ChunkRows) {
			return ErrAuthorityWrite
		}
		v := make([]sql.RawBytes, len(cols))
		dest := make([]any, len(v))
		for j := range v {
			dest[j] = &v[j]
		}
		if rows.Scan(dest...) != nil || !originalC1ExactCells(c1.ChunkRows[n], v) {
			return ErrAuthorityWrite
		}
		n++
	}
	if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || n != len(c1.ChunkRows) {
		return ErrAuthorityWrite
	}
	return nil
}
