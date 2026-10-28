package systembackupproducer

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// BootstrapInlineDomainFence is a negative legacy-entry fence, never bootstrap
// authority or a producer handle. A still authenticates the current grant,
// admin/RBAC and exact operation/config, owns the prefix and the sole commit.
// Copies share immutable facts bound to the original context and transaction.
type BootstrapInlineDomainFence struct{ state *bootstrapInlineDomainState }

type bootstrapInlineDomainState struct {
	ctx    context.Context
	tx     *sql.Tx
	scope  Scope
	absent bool
	domain *DomainRecord
}

func (BootstrapInlineDomainFence) String() string               { return "BootstrapInlineDomainFence" }
func (BootstrapInlineDomainFence) GoString() string             { return "BootstrapInlineDomainFence" }
func (BootstrapInlineDomainFence) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*BootstrapInlineDomainFence) UnmarshalJSON([]byte) error  { return ErrInvalid }

const bootstrapInlineSchemaSQL = "SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=? AND TABLE_NAME IN (?,?,?,?,?,?,?,?) ORDER BY TABLE_NAME"

func bootstrapInlineTables() []string {
	// Derive the closed eight-table set from the same storage definitions as
	// the canonical row codec. Table presence is not schema/authority approval.
	records := []any{&DomainRecord{}, &GrantRecord{}, &RunRecord{}, &TargetRecord{}, &HistoricalBindingRecord{}, &ReceiptRecord{}, &CommandReceiptRecord{}, &ReferenceRecord{}}
	tables := make([]string, 0, len(records))
	for _, record := range records {
		s, _ := storageFor(record)
		tables = append(tables, s.table)
	}
	return tables
}

func bootstrapInlineSchema(ctx context.Context, tx *sql.Tx, scope Scope) (bool, error) {
	tables := bootstrapInlineTables()
	args := []any{string(scope.Database)}
	wanted := make(map[string]bool, len(tables))
	for _, table := range tables {
		args = append(args, table)
		wanted[table] = true
	}
	rows, err := tx.QueryContext(ctx, bootstrapInlineSchemaSQL, args...)
	if err != nil {
		return false, ErrUnavailable
	}
	defer rows.Close()
	seen := make(map[string]bool, len(tables))
	for rows.Next() {
		var name, kind string
		var engine sql.NullString
		if rows.Scan(&name, &kind, &engine) != nil {
			return false, ErrUnavailable
		}
		if !wanted[name] || seen[name] || kind != "BASE TABLE" || !engine.Valid || engine.String != "InnoDB" {
			return false, ErrGuardRequired
		}
		seen[name] = true
	}
	if rows.Err() != nil || rows.Close() != nil {
		return false, ErrUnavailable
	}
	if len(seen) == 0 {
		// information_schema hides tables the SQL identity cannot see. Prove
		// absence independently for EVERY closed name; 1142/other errors deny.
		// LIMIT 0 resolves the exact table without reading or locking its rows.
		for _, table := range tables {
			probe, probeErr := tx.QueryContext(ctx, "SELECT 1 FROM "+table+" LIMIT 0")
			if probeErr == nil {
				probe.Close()
				return false, ErrGuardRequired
			}
			var missing *mysqldriver.MySQLError
			if !errors.As(probeErr, &missing) || missing.Number != 1146 {
				return false, ErrUnavailable
			}
		}
		return true, nil
	}
	if len(seen) != len(tables) {
		return false, ErrGuardRequired
	}
	return false, nil
}

func bootstrapInlineDomain(ctx context.Context, tx *sql.Tx, scope Scope) (*DomainRecord, error) {
	s, _ := storageFor(&DomainRecord{})
	keys, err := recordKeyValues(s, scope, RecordKey{})
	if err != nil {
		return nil, err
	}
	columns := recordColumns(s)
	query := "SELECT " + strings.Join(columns, ",") + " FROM " + s.table + " WHERE scope_key = ? FOR UPDATE"
	rows, err := tx.QueryContext(ctx, query, keys...)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || rows.Close() != nil {
			return nil, ErrUnavailable
		}
		return nil, nil
	}
	cells := make([]any, len(columns))
	dest := make([]any, len(cells))
	for i := range dest {
		dest[i] = &cells[i]
	}
	if rows.Scan(dest...) != nil {
		return nil, ErrUnavailable
	}
	row := StoredRecord{Table: s.table, Columns: make(map[string]any, len(columns))}
	for i, column := range columns {
		value := cells[i]
		if bytes, ok := value.([]byte); ok {
			value = append([]byte(nil), bytes...)
		}
		row.Columns[column] = value
	}
	if rows.Next() {
		return nil, ErrGuardRequired
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrUnavailable
	}
	var domain DomainRecord
	if err = DecodeStoredRecord(row, scope, &domain); err != nil {
		return nil, ErrGuardRequired
	}
	return &domain, nil
}

// LockBootstrapInlineDomain runs AFTER A's global installation/config L0/L1,
// before users L2. Only all eight tables independently proven absent retain the original
// non-C1 initialization path. Partial storage or metadata/query errors deny.
// A complete table set locks the exact domain row OR its PK absence range.
// No missing-table error is converted into permission. This cannot prove DDL
// safety or the behavior of writers that ignore the common prefix.
func LockBootstrapInlineDomain(ctx context.Context, tx *sql.Tx, scope Scope) (*BootstrapInlineDomainFence, error) {
	if tx == nil || !sameBootstrapContext(ctx, ctx) || ctx.Err() != nil || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != string(scope.ServerUUID) || database != string(scope.Database) {
		return nil, ErrUnavailable
	}
	absent, err := bootstrapInlineSchema(ctx, tx, scope)
	if err != nil {
		return nil, err
	}
	s := &bootstrapInlineDomainState{ctx: ctx, tx: tx, scope: scope, absent: absent}
	if !absent {
		s.domain, err = bootstrapInlineDomain(ctx, tx, scope)
		if err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		return nil, ErrExpired
	}
	return &BootstrapInlineDomainFence{state: s}, nil
}

func (f *BootstrapInlineDomainFence) bound(ctx context.Context, tx *sql.Tx) bool {
	return f != nil && f.state != nil && tx != nil && tx == f.state.tx && sameBootstrapContext(ctx, f.state.ctx) && ctx.Err() == nil
}

// CheckLegacyBranch only rejects unsafe fallback. Its nil result never grants
// an operation: A must separately verify all original offline/history facts.
// Full C1 storage always requires candidate assembly for FIRST initialization.
// An exact historical read may coexist with no domain or matching configured
// v1, including expired/revoked execution authority; it issues no execution.
func (f *BootstrapInlineDomainFence) CheckLegacyBranch(ctx context.Context, tx *sql.Tx, configHash Hash, historical bool) error {
	if !f.bound(ctx, tx) || !hashPattern.MatchString(string(configHash)) {
		return ErrGuardRequired
	}
	if f.state.absent {
		return nil
	}
	if !historical {
		return ErrGuardRequired
	}
	d := f.state.domain
	if d == nil {
		return nil
	}
	if d.Admission.Unconfigured != nil || d.Admission.Configured == nil || d.Admission.Configured.ConfigVersion != "1" || d.Admission.Configured.ConfigHash != configHash {
		return ErrGuardRequired
	}
	return nil
}

// Recheck uses only the same exact domain range and closed metadata facts.
// A calls this AFTER every resource/source callback and write, before its last
// shared SQL-time/context guard. It performs no file/network work or mutation.
func (f *BootstrapInlineDomainFence) Recheck(ctx context.Context, tx *sql.Tx) error {
	if !f.bound(ctx, tx) {
		return ErrGuardRequired
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != string(f.state.scope.ServerUUID) || database != string(f.state.scope.Database) {
		return ErrUnavailable
	}
	absent, err := bootstrapInlineSchema(ctx, tx, f.state.scope)
	if err != nil {
		return err
	}
	if absent != f.state.absent {
		return ErrConflict
	}
	if !absent {
		domain, err := bootstrapInlineDomain(ctx, tx, f.state.scope)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(domain, f.state.domain) {
			return ErrConflict
		}
	}
	if ctx.Err() != nil {
		return ErrExpired
	}
	return nil
}
