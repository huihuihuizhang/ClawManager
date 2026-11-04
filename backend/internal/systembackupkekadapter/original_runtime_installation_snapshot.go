package systembackupkekadapter

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
)

type RuntimeInstalledSQLCell struct {
	Null  bool
	Value []byte
}
type RuntimeInstalledSQLRow struct {
	ID       uint64
	PublicID string
	Cells    []RuntimeInstalledSQLCell
}
type RuntimeInstalledSQLSnapshot struct {
	C1                              *OriginalC1SQLSnapshot `json:",omitempty"`
	Database                        reg.DatabaseIdentity
	InstallationID                  string
	ObservedAt                      time.Time
	FenceBefore, FenceAfter         uint64
	Evidence, Chunks                SQLCoverageTable
	Columns                         []string
	Rows                            []RuntimeInstalledSQLRow
	Capabilities                    []OriginalRuntimeCapabilityImport
	MappingRecord, MappingSignature []byte
}

var runtimeInstalledEvidenceColumns = []string{"id", "schema_version", "public_id", "owner_target_type", "owner_target_public_id", "evidence_type", "storage_state", "evidence_failure_code", "storage_provider_role", "storage_identity_hash", "storage_ref_version", "storage_relative_key", "storage_relative_key_hash", "storage_immutable_version", "inline_payload", "content_checksum", "content_size_bytes", "object_checksum", "object_size_bytes", "plaintext_chunk_size_bytes", "chunk_count", "chunk_list_root", "media_type", "encryption", "envelope_framing_version", "kek_identity_hash", "kek_version", "envelope_hash", "redaction_classification", "observed_health", "claim_owner", "claim_expires_at", "next_reconcile_at", "last_checked_at", "expires_at", "protected_until", "row_version", "created_at", "updated_at", "origin_installation_id"}

// Exact full-row/default/EOF receipt from the SAME actual staging transaction.
// The caller must sign this source with its actual purpose issuer and bind it
// to the original Plan/material. A snapshot DTO alone is never authority.
func (w *InstallationAuthorityWriter) StageInitialRuntimeAuthoritiesWithSnapshot(ctx context.Context, tx *sql.Tx, raw, signature []byte, caps []OriginalRuntimeCapabilityImport, now time.Time) (RuntimeInstalledSQLSnapshot, error) {
	var zero RuntimeInstalledSQLSnapshot
	if w == nil || tx == nil {
		return zero, ErrAuthorityWrite
	}
	var before uint64
	e := tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, w.installation).Scan(&before)
	if e != nil && e != sql.ErrNoRows {
		return zero, ErrAuthorityWrite
	}
	if w.StageInitialRuntimeAuthorities(ctx, tx, raw, signature, caps, now) != nil {
		return zero, ErrAuthorityWrite
	}
	r, e := ReadRuntimeInstalledSQLSnapshotTx(ctx, tx, w.database, w.installation, raw, signature, caps, true)
	if e != nil || before == ^uint64(0) || r.FenceAfter != before+1 {
		return zero, ErrAuthorityWrite
	}
	r.FenceBefore = before
	return r, nil
}

// Reread only the original known ranges (locked=true only after those source
// ranges already belong to the caller). No table/prefix exemption is granted.
func ReadRuntimeInstalledSQLSnapshotTx(ctx context.Context, tx *sql.Tx, database reg.DatabaseIdentity, installation string, mapping, signature []byte, caps []OriginalRuntimeCapabilityImport, locked bool, controls ...*OriginalAdoptionControlCut) (RuntimeInstalledSQLSnapshot, error) {
	return readRuntimeInstalledSQLSnapshotTx(ctx, tx, database, installation, mapping, signature, caps, locked, false, nil, controls...)
}

// Query ONLY original inert rows; expired original windows are reported by the
// authenticated installer query, never renewed or promoted into permission.
func QueryRuntimeInstalledSQLSnapshotTx(ctx context.Context, tx *sql.Tx, database reg.DatabaseIdentity, installation string, mapping, signature []byte, caps []OriginalRuntimeCapabilityImport) (RuntimeInstalledSQLSnapshot, error) {
	return readRuntimeInstalledSQLSnapshotTx(ctx, tx, database, installation, mapping, signature, caps, true, true, nil)
}
func readRuntimeInstalledSQLSnapshotTx(ctx context.Context, tx *sql.Tx, database reg.DatabaseIdentity, installation string, mapping, signature []byte, caps []OriginalRuntimeCapabilityImport, locked, historical bool, c1 *OriginalC1SQLSnapshot, controls ...*OriginalAdoptionControlCut) (RuntimeInstalledSQLSnapshot, error) {
	r := RuntimeInstalledSQLSnapshot{Database: database, InstallationID: installation, MappingRecord: bytes.Clone(mapping), MappingSignature: bytes.Clone(signature)}
	bad := func() (RuntimeInstalledSQLSnapshot, error) { return RuntimeInstalledSQLSnapshot{}, ErrAuthorityWrite }
	if tx == nil || ctx == nil || ctx.Err() != nil || len(caps) != 3 {
		return bad()
	}
	if c1 != nil {
		if c1.Database != database || c1.InstallationID != installation {
			return bad()
		}
		tables, _, err := scanOriginalC1ProtocolClosure(ctx, tx, *c1)
		if err != nil || !reflect.DeepEqual(tables, c1.Tables) {
			return bad()
		}
		r.C1 = c1
	}
	var cut *OriginalAdoptionControlCut
	if len(controls) > 1 {
		return bad()
	}
	if len(controls) == 1 {
		cut = controls[0]
		if !locked || cut == nil {
			return bad()
		}
		cut.mu.Lock()
		defer cut.mu.Unlock()
		if !cut.good(ctx) || !cut.staged || cut.original.tx != tx || cut.recheck(ctx) != nil {
			return bad()
		}
	}
	var mappingRecord OriginalRecord
	if json.Unmarshal(mapping, &mappingRecord) != nil || mappingRecord.Binding.InstallationID != installation {
		return bad()
	}
	var server, name string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &name, &r.ObservedAt) != nil || database.ServerUUID != server || database.Database != name {
		return bad()
	}
	fenceQuery := `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?`
	if c1 != nil {
		// Original source rereads hold their evidence/chunks before the KEK
		// fence. Lock only those known C1 ranges here, never capability gaps.
		if lockOriginalC1ComparisonRows(ctx, tx, c1) != nil {
			return bad()
		}
		fenceQuery += " FOR SHARE"
	}
	if tx.QueryRowContext(ctx, fenceQuery, installation).Scan(&r.FenceAfter) != nil {
		return bad()
	}
	expected := map[string]OriginalRuntimeCapabilityImport{}
	for _, c := range caps {
		if expected[c.Pin.Source.RecordID].Raw != nil {
			return bad()
		}
		c.Raw = bytes.Clone(c.Raw)
		c.Pin.Issuer = bytes.Clone(c.Pin.Issuer)
		expected[c.Pin.Source.RecordID] = c
		r.Capabilities = append(r.Capabilities, c)
	}
	suffix := ""
	if locked {
		suffix = " FOR SHARE"
	}
	rows, e := tx.QueryContext(ctx, `SELECT * FROM system_backup_v2_evidence ORDER BY id`+suffix)
	if e != nil {
		return bad()
	}
	defer rows.Close()
	r.Columns, e = rows.Columns()
	if e != nil || !reflect.DeepEqual(r.Columns, runtimeInstalledEvidenceColumns) {
		return bad()
	}
	values := make([]sql.RawBytes, len(r.Columns))
	dest := make([]any, len(values))
	for n := range dest {
		dest[n] = &values[n]
	}
	index := map[string]int{}
	for n, col := range r.Columns {
		index[col] = n
	}
	seenControls := map[string]bool{}
	seenC1 := map[string]bool{}
	for rows.Next() {
		if rows.Scan(dest...) != nil {
			return bad()
		}
		text := func(col string) string { return string(values[index[col]]) }
		isNull := func(col string) bool { return values[index[col]] == nil }
		if cut != nil {
			if owned, exists := cut.rows[text("public_id")]; exists {
				if seenControls[owned.publicID] || originalControlRowSHA(r.Columns, values) != owned.rowSHA || !cut.exactControlRow(r.Columns, values, owned) {
					return bad()
				}
				seenControls[owned.publicID] = true
				continue
			}
		}
		if c1 != nil {
			owned, found := originalC1EvidenceRow(c1, text("id"), text("public_id"))
			if found {
				if seenC1[text("id")] || !reflect.DeepEqual(r.Columns, c1.EvidenceColumns) || !originalC1ExactCells(owned, values) {
					return bad()
				}
				seenC1[text("id")] = true
				continue
			}
		}
		if len(r.Rows) >= 3 {
			return bad()
		}
		id, e := strconv.ParseUint(text("id"), 10, 64)
		c, exists := expected[text("public_id")]
		if e != nil || id == 0 || !exists || !bytes.Equal(values[index["inline_payload"]], c.Raw) || coveragePayloadSHA(c.Raw) != text("content_checksum") || text("content_size_bytes") != strconv.Itoa(len(c.Raw)) {
			return bad()
		}
		delete(expected, text("public_id"))
		for col, want := range map[string]string{"schema_version": "system-backup-evidence.v1", "owner_target_type": "system", "owner_target_public_id": installation, "evidence_type": "capability_snapshot", "storage_state": "inline", "evidence_failure_code": "none", "chunk_count": "0", "media_type": "application/json", "encryption": "none", "redaction_classification": "internal", "observed_health": "healthy", "row_version": "1"} {
			if text(col) != want {
				return bad()
			}
		}
		for _, col := range []string{"storage_provider_role", "storage_identity_hash", "storage_ref_version", "storage_relative_key", "storage_relative_key_hash", "storage_immutable_version", "object_checksum", "object_size_bytes", "plaintext_chunk_size_bytes", "chunk_list_root", "envelope_framing_version", "kek_identity_hash", "kek_version", "envelope_hash", "claim_owner", "claim_expires_at", "next_reconcile_at", "last_checked_at", "protected_until", "origin_installation_id"} {
			if !isNull(col) {
				return bad()
			}
		}
		for _, col := range []string{"expires_at", "created_at", "updated_at"} {
			if isNull(col) || text(col) == "" {
				return bad()
			}
		}
		expires, exErr := runtimeInstalledSQLTime(text("expires_at"))
		created, crErr := runtimeInstalledSQLTime(text("created_at"))
		updated, upErr := runtimeInstalledSQLTime(text("updated_at"))
		if exErr != nil || crErr != nil || upErr != nil || !historical && !r.ObservedAt.Before(expires) || created.After(r.ObservedAt) || !created.Equal(updated) || created.Before(mappingRecord.NotBefore) || (!expires.Equal(mappingRecord.Until.Truncate(time.Microsecond)) && !expires.Equal(mappingRecord.Until.Round(time.Microsecond))) {
			return bad()
		}
		row := RuntimeInstalledSQLRow{ID: id, PublicID: text("public_id")}
		for _, v := range values {
			row.Cells = append(row.Cells, RuntimeInstalledSQLCell{Null: v == nil, Value: bytes.Clone(v)})
		}
		r.Rows = append(r.Rows, row)
	}
	if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || len(r.Rows) != 3 || len(expected) != 0 || cut != nil && len(seenControls) != len(cut.rows) || c1 != nil && len(seenC1) != len(c1.EvidenceRows) {
		return bad()
	}
	var total uint64
	if cut != nil {
		r.Evidence, e = cut.scanEvidenceWithoutExactControls(ctx, &total)
	} else {
		r.Evidence, e = scanSQLCensusTable(ctx, tx, "system_backup_v2_evidence", reg.RetainedArtifacts, locked, &total)
	}
	wantRows := uint64(3)
	if c1 != nil {
		wantRows += uint64(len(c1.EvidenceRows))
	}
	if e != nil || r.Evidence.Rows != wantRows {
		return bad()
	}
	r.Chunks, e = scanSQLCensusTable(ctx, tx, "system_backup_v2_evidence_chunks", reg.RetainedArtifacts, locked, &total)
	if e != nil {
		return bad()
	}
	if c1 != nil {
		if r.Chunks.Rows != uint64(len(c1.ChunkRows)) || verifyOriginalC1ExactChunks(ctx, tx, *c1) != nil {
			return bad()
		}
	} else if r.Chunks.Rows != 0 || r.Chunks.Bytes != 0 {
		return bad()
	}
	var actual, actualSignature []byte
	if tx.QueryRowContext(ctx, originalQuery+suffix, installation, originalRuntimeMappingRef(mapping).IdentityHash, originalRuntimeMappingRef(mapping).Version).Scan(&actual, &actualSignature) != nil || !bytes.Equal(actual, mapping) || !bytes.Equal(actualSignature, signature) {
		return bad()
	}
	return r, nil
}

func originalRuntimeMappingRef(raw []byte) reg.ReferencePin {
	var record OriginalRecord
	_ = json.Unmarshal(raw, &record)
	return record.Binding.ConfigRef
}

func SameRuntimeInstalledSQLRows(a, b RuntimeInstalledSQLSnapshot) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	a.FenceBefore, b.FenceBefore = 0, 0
	a.FenceAfter, b.FenceAfter = 0, 0
	return reflect.DeepEqual(a, b)
}

func runtimeInstalledSQLTime(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999"} {
		t, e := time.Parse(layout, raw)
		if e == nil {
			_, offset := t.Zone()
			if !t.IsZero() && offset == 0 {
				return t, nil
			}
		}
	}
	return time.Time{}, ErrAuthorityWrite
}

// DATA-derived deadline cap, after the caller authenticated the complete rows.
func RuntimeInstalledSnapshotUntil(snapshot RuntimeInstalledSQLSnapshot) (time.Time, error) {
	if len(snapshot.Rows) != 3 || !reflect.DeepEqual(snapshot.Columns, runtimeInstalledEvidenceColumns) {
		return time.Time{}, ErrAuthorityWrite
	}
	var until time.Time
	for _, row := range snapshot.Rows {
		if len(row.Cells) != len(snapshot.Columns) || row.Cells[34].Null {
			return time.Time{}, ErrAuthorityWrite
		}
		expiry, e := runtimeInstalledSQLTime(string(row.Cells[34].Value))
		if e != nil {
			return time.Time{}, e
		}
		if until.IsZero() || expiry.Before(until) {
			until = expiry
		}
	}
	if snapshot.C1 != nil {
		if len(snapshot.C1.Sources) == 0 {
			return time.Time{}, ErrAuthorityWrite
		}
		for _, s := range snapshot.C1.Sources {
			retention, e := s.Receipt.RetentionExpiresAt.Time()
			if e != nil {
				return time.Time{}, ErrAuthorityWrite
			}
			for _, cap := range []time.Time{s.Record.ExpiresAt, s.Record.ProtectedUntil, retention} {
				if cap.IsZero() {
					return time.Time{}, ErrAuthorityWrite
				}
				if cap.Before(until) {
					until = cap
				}
			}
		}
	}
	return until, nil
}

// The original maintenance gate is the FIRST lock prefix, before admin/head
// and before KEK/source writes. A live acquiring/held/releasing owner refuses.
func LockOriginalRuntimeInstallationGate(ctx context.Context, tx *sql.Tx, installation string) error {
	if tx == nil || ctx == nil || ctx.Err() != nil || installation == "" {
		return ErrAuthorityWrite
	}
	var state string
	e := tx.QueryRowContext(ctx, "SELECT gate_state FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE", installation, c.CaptureGateScope).Scan(&state)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil || state != string(c.GateIdle) {
		return ErrAuthorityWrite
	}
	return nil
}
