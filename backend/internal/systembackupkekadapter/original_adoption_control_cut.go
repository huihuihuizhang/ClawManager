package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Deployment-owned independent ORIGINAL issuer/source pins. These select the
// existing four-partition/16-witness protocol; they are not decoded approvals.
type OriginalAdoptionControlPins struct {
	Adoption  CoverageOwnerPin
	Witnesses []CoverageWitnessPin
}

// Inert authenticated transport candidates only. This type is deliberately NOT
// PreparedCoverage, a physical fence, an immutable snapshot or backfill proof.
type OriginalAdoptionControlRecords map[string]SignedCoverageOwnerRecord

type originalAdoptionControlRow struct {
	publicID string
	id       uint64
	envelope []byte
	expires  time.Time
	rowSHA   string
}

// OriginalAdoptionControlCut owns an exact originating RR transaction but
// exposes neither its SQL handle nor Commit. This first slice stages/rechecks
// ORIGINAL signed controls and can only be aborted. It cannot adopt coverage.
// Actual authenticated Installer construction is wired in install separately.
type OriginalAdoptionControlCut struct {
	mu                      sync.Mutex
	origin                  *OriginalAdoptionControlCut
	ctx                     context.Context
	original                *OriginalSQLCoverageTransaction
	locked                  *LockedSQLCoverageCensus
	observed                SQLCoverageCensusFacts
	pins                    OriginalAdoptionControlPins
	ids                     []string
	rows                    map[string]*originalAdoptionControlRow
	until, floor            time.Time
	failed, staged, aborted bool
	abortErr                error
}

func (*OriginalAdoptionControlCut) MarshalJSON() ([]byte, error) { return nil, ErrSQLCoverageCensus }

// All selected proof record gaps precede ALL original source ranges and KEK
// Bind. Existing rows reject: overwriting/replay resolution is not this slice.
// The transaction itself must come from scanner.BeginOriginalTransaction.
func (s *SQLCoverageCensus) PrepareOriginalAdoptionControlCut(ctx context.Context, original *OriginalSQLCoverageTransaction, expected *UnadmittedSQLCoverageCensus, pins OriginalAdoptionControlPins, until time.Time) (*OriginalAdoptionControlCut, error) {
	if s == nil || nilSource(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || original == nil || original.owner != s || original.tx == nil || expected == nil || expected.owner != s {
		return nil, ErrSQLCoverageCensus
	}
	deadline, ok := ctx.Deadline()
	if !ok || until.IsZero() || deadline.Before(until) || !time.Now().Before(until) {
		return nil, ErrSQLCoverageCensus
	}
	checked, e := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: s.db, Database: s.database, InstallationID: s.installation, Adoption: pins.Adoption, Witnesses: pins.Witnesses})
	if e != nil {
		return nil, ErrSQLCoverageCensus
	}
	pins = OriginalAdoptionControlPins{Adoption: checked.cfg.Adoption, Witnesses: checked.cfg.Witnesses}
	ids := []string{pins.Adoption.Source.RecordID}
	for _, pin := range pins.Witnesses {
		ids = append(ids, pin.Source.RecordID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var existing uint64
		e := original.tx.QueryRowContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&existing)
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, ErrSQLCoverageCensus
		}
	}
	locked, e := s.LockOriginalSources(ctx, original, expected)
	if e != nil {
		return nil, e
	}
	o := &OriginalAdoptionControlCut{ctx: ctx, original: original, locked: locked, observed: expected.Facts(), pins: pins, ids: ids, rows: map[string]*originalAdoptionControlRow{}, until: until}
	o.origin = o
	return o, nil
}

func (p *OriginalAdoptionControlCut) good(ctx context.Context) bool {
	return p != nil && p.origin == p && !p.failed && !p.aborted && !nilSource(ctx) && reflect.TypeOf(ctx).Comparable() && ctx == p.ctx && ctx.Err() == nil && p.original != nil && p.original.tx != nil && p.locked != nil && time.Now().Before(p.until)
}
func (p *OriginalAdoptionControlCut) poison() error {
	if p != nil {
		p.failed = true
	}
	return ErrSQLCoverageCensus
}
func (p *OriginalAdoptionControlCut) now(ctx context.Context) (time.Time, error) {
	var actual reg.DatabaseIdentity
	var now time.Time
	if !p.good(ctx) || p.original.tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&actual.ServerUUID, &actual.Database, &now) != nil || actual != p.original.owner.database || now.Before(p.observed.ObservedAt) || !p.floor.IsZero() && now.Before(p.floor) || !now.Before(p.until) {
		return time.Time{}, p.poison()
	}
	p.floor = now
	return now, nil
}

// This does NOT sign records or infer physical facts. Every envelope must
// authenticate against independent installed pins and the real original SQL
// witness must exactly describe THIS full pre-write source observation.
func (p *OriginalAdoptionControlCut) authenticateBatch(records OriginalAdoptionControlRecords, now time.Time) (map[string]*originalAdoptionControlRow, error) {
	if len(records) != 17 {
		return nil, ErrSQLCoverageCensus
	}
	rows := map[string]*originalAdoptionControlRow{}
	decode := func(pin CoverageOwnerPin) (capabilityEvidence, error) {
		signed, ok := records[pin.Source.RecordID]
		if !ok || len(signed.Record) == 0 || len(signed.Signature) != ed25519.SignatureSize {
			return capabilityEvidence{}, ErrSQLCoverageCensus
		}
		raw, e := json.Marshal(signed)
		if e != nil || len(raw) > 8192 {
			return capabilityEvidence{}, ErrSQLCoverageCensus
		}
		return capabilityEvidence{raw: raw, until: p.until}, nil
	}
	e, e0 := decode(p.pins.Adoption)
	if e0 != nil {
		return nil, e0
	}
	adoption, e0 := authenticateCoverageAdoption(e, p.pins.Adoption, now)
	if e0 != nil || adoption.Facts.Database != p.original.owner.database || adoption.Facts.InstallationID != p.original.owner.installation {
		return nil, ErrSQLCoverageCensus
	}
	parts := map[reg.Partition]CoveragePartitionAdoption{}
	for _, part := range adoption.Facts.Partitions {
		if !coveragePartition(part.Partition) || parts[part.Partition].SourceID != "" || part.SourceID == "" || !authorityExact(part.SnapshotRevision) || !authorityExact(part.FenceRevision) || !authorityHash.MatchString(part.ReferencesSHA256) {
			return nil, ErrSQLCoverageCensus
		}
		parts[part.Partition] = part
	}
	rows[p.pins.Adoption.Source.RecordID] = &originalAdoptionControlRow{publicID: p.pins.Adoption.Source.RecordID, envelope: bytes.Clone(e.raw), expires: adoption.Until.UTC().Truncate(time.Microsecond)}
	for _, pin := range p.pins.Witnesses {
		e, e0 := decode(pin.CoverageOwnerPin)
		if e0 != nil {
			return nil, e0
		}
		w, e0 := authenticateCoverageWitness(e, pin, now)
		part := parts[pin.Partition]
		want := map[string]reg.SourceRecord{"original_sql_census": part.SQLCensus, "immutable_external_snapshot": part.ImmutableExternalSnapshot, "original_writer_fence": part.WriterFence, "historical_backfill": part.HistoricalBackfill}[pin.Kind]
		if e0 != nil || w.Facts.Database != p.original.owner.database || w.Facts.InstallationID != p.original.owner.installation || want != pin.Source || w.Facts.SnapshotRevision != part.SnapshotRevision || w.Facts.FenceRevision != part.FenceRevision {
			return nil, ErrSQLCoverageCensus
		}
		if pin.Kind == "original_sql_census" {
			facts := OriginalSQLPartitionCensus{Database: p.observed.Database, InstallationID: p.observed.InstallationID, Partition: pin.Partition, ObservedAt: p.observed.ObservedAt, Tables: []SQLCoverageTable{}}
			for _, table := range p.observed.Tables {
				if table.Partition == pin.Partition {
					facts.Tables = append(facts.Tables, table)
				}
			}
			scope := struct {
				Database       reg.DatabaseIdentity
				InstallationID string
				Partition      reg.Partition
			}{facts.Database, facts.InstallationID, pin.Partition}
			if len(facts.Tables) == 0 || !w.NotBefore.Equal(p.observed.ObservedAt) || w.Facts.ScopeSHA256 != coverageFactsHash(scope) || w.Facts.ObservationSHA256 != coverageFactsHash(facts) {
				return nil, ErrSQLCoverageCensus
			}
		}
		rows[pin.Source.RecordID] = &originalAdoptionControlRow{publicID: pin.Source.RecordID, envelope: bytes.Clone(e.raw), expires: w.Until.UTC().Truncate(time.Microsecond)}
	}
	return rows, nil
}

// Stage appends only the selected seventeen signed, inline original controls.
// It records the COMPLETE server-returned row, including every default column;
// no caller skip-ID list or expected row hash is accepted. Original rows and
// chunks are never updated, deleted, excluded by prefix, or relabelled.
func (p *OriginalAdoptionControlCut) Stage(ctx context.Context, records OriginalAdoptionControlRecords) error {
	if p == nil {
		return ErrSQLCoverageCensus
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.good(ctx) || p.staged || len(records) != 17 {
		return p.poison()
	}
	frozen := OriginalAdoptionControlRecords{}
	for id, signed := range records {
		frozen[id] = SignedCoverageOwnerRecord{Record: bytes.Clone(signed.Record), Signature: bytes.Clone(signed.Signature)}
	}
	now, e := p.now(ctx)
	if e != nil {
		return e
	}
	rows, e := p.authenticateBatch(frozen, now)
	if e != nil {
		return p.poison()
	}
	for _, row := range rows {
		if row.expires.Before(p.until) {
			p.until = row.expires
		}
	}
	if !p.good(ctx) {
		return p.poison()
	}
	for _, id := range p.ids {
		row := rows[id]
		if row == nil || !now.Before(row.expires) {
			return p.poison()
		}
		result, e := p.original.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at,created_at,updated_at) VALUES (?,'system',?,'catalog_scan_receipt','inline',?,?,?,'application/json','none','internal','healthy',?,?,?)`, id, p.original.owner.installation, row.envelope, coveragePayloadSHA(row.envelope), len(row.envelope), row.expires, now, now)
		if e != nil {
			return p.poison()
		}
		affected, e := result.RowsAffected()
		if e != nil || affected != 1 {
			return p.poison()
		}
		inserted, e := result.LastInsertId()
		if e != nil || inserted <= 0 {
			return p.poison()
		}
		row.id = uint64(inserted)
		query, e := p.original.tx.QueryContext(ctx, "SELECT * FROM system_backup_v2_evidence WHERE public_id=? FOR SHARE", id)
		if e != nil {
			return p.poison()
		}
		columns, e := query.Columns()
		if e != nil {
			query.Close()
			return p.poison()
		}
		values := make([]sql.RawBytes, len(columns))
		targets := make([]any, len(values))
		for n := range values {
			targets[n] = &values[n]
		}
		if !query.Next() || query.Scan(targets...) != nil || !p.exactControlRow(columns, values, row) {
			query.Close()
			return p.poison()
		}
		row.rowSHA = originalControlRowSHA(columns, values)
		if query.Next() || query.Err() != nil || query.NextResultSet() {
			query.Close()
			return p.poison()
		}
		if query.Close() != nil {
			return p.poison()
		}
		p.rows[id] = row
	}
	p.staged = true
	return p.recheck(ctx)
}

func coveragePayloadSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func originalControlRowSHA(columns []string, values []sql.RawBytes) string {
	h := sha256.New()
	censusFrame(h, []byte("original-adoption-exact-control-row.v1"))
	for n, column := range columns {
		censusFrame(h, []byte(column))
		if values[n] == nil {
			censusFrame(h, []byte("null"))
		} else {
			censusFrame(h, []byte("bytes"))
			censusFrame(h, values[n])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (p *OriginalAdoptionControlCut) exactControlRow(columns []string, values []sql.RawBytes, row *originalAdoptionControlRow) bool {
	if len(columns) != len(values) || row == nil {
		return false
	}
	fields := map[string]sql.RawBytes{}
	for n, col := range columns {
		fields[col] = values[n]
	}
	want := map[string]string{"public_id": row.publicID, "owner_target_type": "system", "owner_target_public_id": p.original.owner.installation, "evidence_type": "catalog_scan_receipt", "storage_state": "inline", "content_checksum": coveragePayloadSHA(row.envelope), "content_size_bytes": strconv.Itoa(len(row.envelope)), "media_type": "application/json", "encryption": "none", "redaction_classification": "internal", "observed_health": "healthy", "evidence_failure_code": "none", "row_version": "1", "chunk_count": "0"}
	for col, value := range want {
		if string(fields[col]) != value {
			return false
		}
	}
	id, e := strconv.ParseUint(string(fields["id"]), 10, 64)
	if e != nil || id != row.id || !bytes.Equal(fields["inline_payload"], row.envelope) {
		return false
	}
	for _, col := range []string{"storage_provider_role", "storage_identity_hash", "storage_ref_version", "storage_relative_key", "storage_relative_key_hash", "storage_immutable_version", "object_checksum", "object_size_bytes", "plaintext_chunk_size_bytes", "chunk_list_root", "envelope_framing_version", "kek_identity_hash", "kek_version", "envelope_hash", "claim_owner", "claim_expires_at", "protected_until"} {
		v, exists := fields[col]
		if !exists || v != nil {
			return false
		}
	}
	expires, e := time.Parse(time.RFC3339Nano, string(fields["expires_at"]))
	if e != nil {
		expires, e = time.ParseInLocation("2006-01-02 15:04:05.999999", string(fields["expires_at"]), time.UTC)
	}
	return e == nil && expires.Equal(row.expires)
}

func (p *OriginalAdoptionControlCut) recheck(ctx context.Context) error {
	if !p.good(ctx) || !p.staged || len(p.rows) != 17 {
		return p.poison()
	}
	if _, e := p.now(ctx); e != nil {
		return e
	}
	current, e := p.original.owner.scan(ctx, p.original.tx, true)
	if e != nil {
		return p.poison()
	}
	var total uint64
	filtered, e := p.scanEvidenceWithoutExactControls(ctx, &total)
	if e != nil {
		return p.poison()
	}
	found := false
	for n, table := range current.Tables {
		if table.Table == "system_backup_v2_evidence" {
			current.Tables[n] = filtered
			found = true
		}
	}
	if !found || !sameSQLCensus(current, p.observed) {
		return p.poison()
	}
	_, e = p.now(ctx)
	return e
}
func (p *OriginalAdoptionControlCut) Recheck(ctx context.Context) error {
	if p == nil {
		return ErrSQLCoverageCensus
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recheck(ctx)
}

// Abort is the ONLY completion operation in this source slice. Physical B/C
// recovery remains separately owned: SQL rollback is never permission to thaw.
func (p *OriginalAdoptionControlCut) Abort() error {
	if p == nil {
		return ErrSQLCoverageCensus
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p {
		return ErrSQLCoverageCensus
	}
	if p.aborted {
		return p.abortErr
	}
	p.aborted = true
	p.failed = true
	if p.original == nil || p.original.tx == nil {
		p.abortErr = ErrSQLCoverageCensus
		return p.abortErr
	}
	p.abortErr = p.original.tx.Rollback()
	return p.abortErr
}

// OriginalAdoptionSQLCutData is diagnostic comparison data, not a source proof.
type OriginalAdoptionSQLCutData struct {
	Database                                reg.DatabaseIdentity
	InstallationID, OriginalSQLSHA256       string
	OriginalSourceTables, StagedControlRows int
	ObservedAt, CheckedAt, Until            time.Time
}

func (p *OriginalAdoptionControlCut) InspectionData() (OriginalAdoptionSQLCutData, error) {
	if p == nil {
		return OriginalAdoptionSQLCutData{}, ErrSQLCoverageCensus
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.good(p.ctx) || !p.staged || len(p.rows) != 17 {
		return OriginalAdoptionSQLCutData{}, p.poison()
	}
	return OriginalAdoptionSQLCutData{Database: p.observed.Database, InstallationID: p.observed.InstallationID, OriginalSQLSHA256: coverageFactsHash(p.observed), OriginalSourceTables: len(p.observed.Tables), StagedControlRows: len(p.rows), ObservedAt: p.observed.ObservedAt, CheckedAt: p.floor, Until: p.until}, nil
}

func (p *OriginalAdoptionControlCut) scanEvidenceWithoutExactControls(ctx context.Context, total *uint64) (SQLCoverageTable, error) {
	tx := p.original.tx
	name := "system_backup_v2_evidence"
	partition := reg.RetainedArtifacts
	locked := true
	seenControls := map[string]bool{}

	bad := func() (SQLCoverageTable, error) { return SQLCoverageTable{}, ErrSQLCoverageCensus }
	var schema sqlCensusSchema
	columns, err := tx.QueryContext(ctx, `SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,EXTRA,COALESCE(CHARACTER_SET_NAME,''),COALESCE(COLLATION_NAME,'') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION`, name)
	if err != nil {
		return bad()
	}
	for columns.Next() {
		var c sqlCensusColumn
		if columns.Scan(&c.Name, &c.Type, &c.Nullable, &c.Extra, &c.Charset, &c.Collation) != nil || len(schema.Columns) >= 256 || !sqlCensusIdentifier(c.Name) {
			columns.Close()
			return bad()
		}
		schema.Columns = append(schema.Columns, c)
	}
	err = columns.Err()
	closeErr := columns.Close()
	if err != nil || closeErr != nil || len(schema.Columns) == 0 {
		return bad()
	}
	keys, err := tx.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND CONSTRAINT_NAME='PRIMARY' ORDER BY ORDINAL_POSITION`, name)
	if err != nil {
		return bad()
	}
	for keys.Next() {
		var key string
		if keys.Scan(&key) != nil || !sqlCensusIdentifier(key) {
			keys.Close()
			return bad()
		}
		schema.Primary = append(schema.Primary, key)
	}
	err = keys.Err()
	closeErr = keys.Close()
	if err != nil || closeErr != nil || len(schema.Primary) == 0 {
		return bad()
	}
	raw, _ := json.Marshal(schema)
	schemaHash := sha256.Sum256(raw)
	table := SQLCoverageTable{Partition: partition, Table: name, SchemaSHA256: hex.EncodeToString(schemaHash[:])}
	order := make([]string, len(schema.Primary))
	for i, key := range schema.Primary {
		order[i] = "`" + key + "`"
	}
	query := "SELECT * FROM `" + name + "` ORDER BY " + strings.Join(order, ",")
	if locked {
		query += " FOR SHARE"
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return bad()
	}
	defer rows.Close()
	actual, err := rows.Columns()
	if err != nil || len(actual) != len(schema.Columns) {
		return bad()
	}
	for i, column := range actual {
		if column != schema.Columns[i].Name {
			return bad()
		}
	}
	h := sha256.New()
	censusFrame(h, []byte("original-backup-sql-census.v1"))
	censusFrame(h, []byte(name))
	censusFrame(h, raw)
	values := make([]sql.RawBytes, len(actual))
	targets := make([]any, len(values))
	for i := range values {
		targets[i] = &values[i]
	}
	publicIndex := -1
	for n, col := range actual {
		if col == "public_id" {
			publicIndex = n
		}
	}
	if publicIndex < 0 {
		return bad()
	}
	for rows.Next() {
		if table.Rows >= 1000000 || rows.Scan(targets...) != nil {
			return bad()
		}
		var rowBytes uint64
		for _, value := range values {
			rowBytes += uint64(len(value))
			if rowBytes > 16<<20 {
				return bad()
			}
		}
		if *total+rowBytes > 512<<20 {
			return bad()
		}
		if owned, exists := p.rows[string(values[publicIndex])]; exists {
			if seenControls[owned.publicID] || originalControlRowSHA(actual, values) != owned.rowSHA || !p.exactControlRow(actual, values, owned) {
				return bad()
			}
			seenControls[owned.publicID] = true
			continue
		}
		censusFrame(h, []byte("row"))
		for _, value := range values {
			censusFrame(h, value)
		}
		table.Rows++
		table.Bytes += rowBytes
		*total += rowBytes
	}
	if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || ctx.Err() != nil {
		return bad()
	}
	if len(seenControls) != len(p.rows) {
		return bad()
	}
	table.RowsSHA256 = hex.EncodeToString(h.Sum(nil))
	return table, nil
}
