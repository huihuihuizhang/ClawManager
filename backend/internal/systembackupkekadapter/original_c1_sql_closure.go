package systembackupkekadapter

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"time"

	ev "clawreef/internal/systembackupevidence"
	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
)

// Actual complete original source data, never caller-supplied authentication.
// All ciphertext/KEK/object/version/lifecycle relationships are preserved.
type OriginalC1SQLSnapshot struct {
	Database                      reg.DatabaseIdentity
	InstallationID                string
	ObservedAt                    time.Time
	Sources                       []ev.OriginalC1EvidenceFacts
	Tables                        []SQLCoverageTable
	EvidenceColumns, ChunkColumns []string
	EvidenceRows, ChunkRows       [][]RuntimeInstalledSQLCell
}

type OriginalC1SQLClosure struct {
	mu       sync.Mutex
	origin   *OriginalC1SQLClosure
	ctx      context.Context
	sources  []*ev.OriginalC1EvidenceSource
	snapshot OriginalC1SQLSnapshot
}

func (*OriginalC1SQLClosure) MarshalJSON() ([]byte, error) { return nil, ErrAuthorityWrite }

// Caller authenticates the original installer and owns the RR transaction.
// Only actual source objects minted by native Wrap+publication+Result guard
// are accepted; each independently rereads its committed original SQL rows.
// Unknown rows in ANY of the complete eight C1 tables reject, including rows
// for another installation. No table/type/ID prefix is exempted.
func PrepareOriginalC1SQLClosure(ctx context.Context, tx *sql.Tx, sources []*ev.OriginalC1EvidenceSource) (*OriginalC1SQLClosure, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || len(sources) == 0 || len(sources) > 20 {
		return nil, ErrAuthorityWrite
	}
	c := &OriginalC1SQLClosure{ctx: ctx, sources: append([]*ev.OriginalC1EvidenceSource(nil), sources...)}
	c.origin = c
	seen := map[*ev.OriginalC1EvidenceSource]bool{}
	for _, source := range c.sources {
		if source == nil || seen[source] {
			return nil, ErrAuthorityWrite
		}
		seen[source] = true
		f, e := source.OriginalGuardData(ctx)
		if e != nil {
			return nil, ErrAuthorityWrite
		}
		if len(c.snapshot.Sources) == 0 {
			c.snapshot.Database = reg.DatabaseIdentity{ServerUUID: string(f.History.Scope.ServerUUID), Database: string(f.History.Scope.Database)}
			c.snapshot.InstallationID = string(f.History.Scope.Installation)
		}
		if c.snapshot.Database != (reg.DatabaseIdentity{ServerUUID: string(f.History.Scope.ServerUUID), Database: string(f.History.Scope.Database)}) || c.snapshot.InstallationID != string(f.History.Scope.Installation) || f.Record.Manifest.Key != f.KeySource.Transit.Key || f.Record.Ref.ImmutableVersion == "" {
			return nil, ErrAuthorityWrite
		}
		c.snapshot.Sources = append(c.snapshot.Sources, f)
	}
	tables, now, e := scanOriginalC1ProtocolClosure(ctx, tx, c.snapshot)
	if e != nil {
		return nil, e
	}
	c.snapshot.Tables = tables
	c.snapshot.ObservedAt = now
	for n, source := range c.sources {
		f, e := source.ReadCommitted(ctx, tx)
		if e != nil || !reflect.DeepEqual(f, c.snapshot.Sources[n]) {
			return nil, ErrAuthorityWrite
		}
	}
	if captureOriginalC1EvidenceRows(ctx, tx, &c.snapshot) != nil {
		return nil, ErrAuthorityWrite
	}
	return c, nil
}

// Comparison snapshot is available only after current full original source
// reauthentication, never through a DTO constructor. The signed installation
// exporter must retain its independent original admin/enrollment validation.
func (c *OriginalC1SQLClosure) ReadCurrent(ctx context.Context, tx *sql.Tx) (OriginalC1SQLSnapshot, error) {
	var zero OriginalC1SQLSnapshot
	if c == nil {
		return zero, ErrAuthorityWrite
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.origin != c || tx == nil || ctx == nil || ctx.Err() != nil || !reflect.ValueOf(ctx).Comparable() || !reflect.ValueOf(c.ctx).Comparable() || ctx != c.ctx {
		return zero, ErrAuthorityWrite
	}
	tables, now, e := scanOriginalC1ProtocolClosure(ctx, tx, c.snapshot)
	if e != nil || now.Before(c.snapshot.ObservedAt) || !reflect.DeepEqual(tables, c.snapshot.Tables) {
		return zero, ErrAuthorityWrite
	}
	for n, source := range c.sources {
		f, e := source.ReadCommitted(ctx, tx)
		if e != nil || !reflect.DeepEqual(f, c.snapshot.Sources[n]) {
			return zero, ErrAuthorityWrite
		}
	}
	rows := c.snapshot
	if captureOriginalC1EvidenceRows(ctx, tx, &rows) != nil || !reflect.DeepEqual(rows.EvidenceColumns, c.snapshot.EvidenceColumns) || !reflect.DeepEqual(rows.ChunkColumns, c.snapshot.ChunkColumns) || !reflect.DeepEqual(rows.EvidenceRows, c.snapshot.EvidenceRows) || !reflect.DeepEqual(rows.ChunkRows, c.snapshot.ChunkRows) {
		return zero, ErrAuthorityWrite
	}
	// Copy source data deeply through its ordinary wire. It remains comparison
	// data and is not an independent current coverage or execution capability.
	raw, e := json.Marshal(c.snapshot)
	if e != nil || json.Unmarshal(raw, &zero) != nil {
		return OriginalC1SQLSnapshot{}, ErrAuthorityWrite
	}
	return zero, nil
}

var originalC1ProtocolTables = []struct {
	name      string
	partition reg.Partition
	newRecord func() any
}{
	{"system_backup_producer_domains", reg.InflightAndUnknownWrites, func() any { return new(pd.DomainRecord) }},
	{"system_backup_producer_result_receipts", reg.RetainedArtifacts, func() any { return new(pd.ReceiptRecord) }},
	{"system_backup_producer_command_receipts", reg.InflightAndUnknownWrites, func() any { return new(pd.CommandReceiptRecord) }},
	{"system_backup_producer_grants", reg.InflightAndUnknownWrites, func() any { return new(pd.GrantRecord) }},
	{"system_backup_producer_runs", reg.InflightAndUnknownWrites, func() any { return new(pd.RunRecord) }},
	{"system_backup_producer_targets", reg.InflightAndUnknownWrites, func() any { return new(pd.TargetRecord) }},
	{"system_backup_producer_evidence_bindings", reg.RetainedArtifacts, func() any { return new(pd.HistoricalBindingRecord) }},
	{"system_backup_producer_evidence_refs", reg.HoldsAndCatalog, func() any { return new(pd.ReferenceRecord) }},
}

func scanOriginalC1ProtocolClosure(ctx context.Context, tx *sql.Tx, snapshot OriginalC1SQLSnapshot) ([]SQLCoverageTable, time.Time, error) {
	bad := func() ([]SQLCoverageTable, time.Time, error) { return nil, time.Time{}, ErrAuthorityWrite }
	expected := map[string]map[string]pd.StoredRecord{}
	for _, source := range snapshot.Sources {
		records := []any{&source.Domain, &source.Grant, &source.Run, &source.History, &source.Target, &source.Receipt}
		for n := range source.Commands {
			records = append(records, &source.Commands[n])
		}
		for n := range source.References {
			records = append(records, &source.References[n])
		}
		for _, record := range records {
			row, e := pd.EncodeStoredRecord(record)
			if e != nil {
				return bad()
			}
			if expected[row.Table] == nil {
				expected[row.Table] = map[string]pd.StoredRecord{}
			}
			key := hex.EncodeToString(row.Columns["record_sha256"].([]byte))
			if prior, exists := expected[row.Table][key]; exists && !reflect.DeepEqual(prior, row) {
				return bad()
			}
			expected[row.Table][key] = row
		}
	}
	scope := pd.Scope{ServerUUID: pd.ServerUUID(snapshot.Database.ServerUUID), Database: pd.Database(snapshot.Database.Database), Installation: pd.Installation(snapshot.InstallationID)}
	var result []SQLCoverageTable
	var total uint64
	for _, table := range originalC1ProtocolTables {
		order := "scope_key"
		switch table.name {
		case "system_backup_producer_result_receipts", "system_backup_producer_command_receipts":
			order += ",receipt_key_hash"
		case "system_backup_producer_grants":
			order += ",grant_id"
		case "system_backup_producer_runs":
			order += ",run_id"
		case "system_backup_producer_targets":
			order += ",target_hash"
		case "system_backup_producer_evidence_bindings":
			order += ",evidence_id"
		case "system_backup_producer_evidence_refs":
			order += ",evidence_id,reference_kind,reference_key_hash"
		}
		order = "`" + strings.ReplaceAll(order, ",", "`,`") + "`"
		rows, e := tx.QueryContext(ctx, "SELECT * FROM `"+table.name+"` ORDER BY "+order+" FOR SHARE")
		if e != nil {
			return bad()
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			return bad()
		}
		seen := map[string]bool{}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for n := range values {
				dest[n] = &values[n]
			}
			if rows.Scan(dest...) != nil {
				rows.Close()
				return bad()
			}
			stored := pd.StoredRecord{Table: table.name, Columns: map[string]any{}}
			for n, col := range columns {
				if _, exists := stored.Columns[col]; exists {
					rows.Close()
					return bad()
				}
				if b, ok := values[n].([]byte); ok {
					stored.Columns[col] = bytes.Clone(b)
				} else {
					stored.Columns[col] = values[n]
				}
			}
			out := table.newRecord()
			if pd.DecodeStoredRecord(stored, scope, out) != nil {
				rows.Close()
				return bad()
			}
			actual, e := pd.EncodeStoredRecord(out)
			if e != nil {
				rows.Close()
				return bad()
			}
			key := hex.EncodeToString(actual.Columns["record_sha256"].([]byte))
			want, found := expected[table.name][key]
			if !found || seen[key] || !reflect.DeepEqual(want, actual) {
				rows.Close()
				return bad()
			}
			seen[key] = true
		}
		if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || len(seen) != len(expected[table.name]) {
			return bad()
		}
		fact, e := scanSQLCensusTable(ctx, tx, table.name, table.partition, true, &total)
		if e != nil || fact.Rows != uint64(len(seen)) {
			return bad()
		}
		result = append(result, fact)
	}
	var server, database string
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &now) != nil || server != snapshot.Database.ServerUUID || database != snapshot.Database.Database || now.IsZero() {
		return bad()
	}
	return result, now, nil
}
