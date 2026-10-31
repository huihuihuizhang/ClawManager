package systembackupkekadapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"reflect"
	"sort"
	"strings"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

var ErrSQLCoverageCensus = errors.New("original backup SQL source census incomplete or changed")

// SQLCoverageCensus inventories ORIGINAL source rows, including legacy rows,
// failed/deleted tasks, unknown calls and expired leases. It never scans only
// the new KEK index and never treats status/TTL as an absence or release proof.
// This is one input to original-owner adoption, NOT PreparedCoverage or a key
// grant: external immutable storage/catalog EOF and historical expected-request
// provenance must still be reconciled by their original owners.
type SQLCoverageCensus struct {
	db           *sql.DB
	database     reg.DatabaseIdentity
	installation string
}

type SQLCoverageTable struct {
	Partition                       reg.Partition
	Table, SchemaSHA256, RowsSHA256 string
	Rows, Bytes                     uint64
}

type SQLCoverageCensusFacts struct {
	Database       reg.DatabaseIdentity
	InstallationID string
	ObservedAt     time.Time
	Tables         []SQLCoverageTable
}

// UnadmittedSQLCoverageCensus has private construction. Facts contain hashes
// and counts only; source config/manifest/encrypted payload bytes never escape.
type UnadmittedSQLCoverageCensus struct {
	owner *SQLCoverageCensus
	facts SQLCoverageCensusFacts
}

func (p *UnadmittedSQLCoverageCensus) Facts() SQLCoverageCensusFacts {
	if p == nil {
		return SQLCoverageCensusFacts{}
	}
	f := p.facts
	f.Tables = append([]SQLCoverageTable(nil), f.Tables...)
	return f
}

func NewSQLCoverageCensus(db *sql.DB, database reg.DatabaseIdentity, installation string) (*SQLCoverageCensus, error) {
	if db == nil || !authorityVersion.MatchString(database.Database) || strings.ContainsAny(database.Database, ".:-") || len(database.Database) > 64 || database.ServerUUID == "" || installation == "" || len(installation) > 128 {
		return nil, ErrSQLCoverageCensus
	}
	return &SQLCoverageCensus{db: db, database: database, installation: installation}, nil
}

// Observe uses one original database read view and consumes every cursor to
// verified EOF. Fixed bounds are refusal limits, never a successful page cap.
// Source inventory is database-wide conservatively, including other installs;
// it is NOT an installation-filtered claim about absent external artifacts.
func (s *SQLCoverageCensus) Observe(ctx context.Context) (*UnadmittedSQLCoverageCensus, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSQLCoverageCensus
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrSQLCoverageCensus
	}
	defer tx.Rollback()
	facts, err := s.scan(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	return &UnadmittedSQLCoverageCensus{owner: s, facts: facts}, nil
}

// LockedSQLCoverageCensus keeps all original source row/range locks in the
// CALLER's original maintenance/adoption transaction. It owns no commit and
// must be obtained BEFORE SQLStore.Bind takes the shared KEK fence. Old SQL
// writers cannot slip an insertion into an empty source range during adoption.
type LockedSQLCoverageCensus struct {
	owner *SQLCoverageCensus
	tx    *sql.Tx
	facts SQLCoverageCensusFacts
}

// OriginalSQLCoverageTransaction creates the caller's ONE original transaction
// at the specified isolation. The owner gets Tx() to acquire original business
// authorization/domain locks BEFORE LockOriginalSources and owns Commit/Rollback.
// There is no adopter-created second transaction inside an existing boundary.
// Private construction is essential: @@transaction_isolation reports the
// session default and cannot authenticate an externally supplied tx's isolation.
type OriginalSQLCoverageTransaction struct {
	owner *SQLCoverageCensus
	tx    *sql.Tx
}

func (s *SQLCoverageCensus) BeginOriginalTransaction(ctx context.Context) (*OriginalSQLCoverageTransaction, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSQLCoverageCensus
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrSQLCoverageCensus
	}
	return &OriginalSQLCoverageTransaction{owner: s, tx: tx}, nil
}

func (t *OriginalSQLCoverageTransaction) Tx() *sql.Tx {
	if t == nil {
		return nil
	}
	return t.tx
}

func (s *SQLCoverageCensus) LockOriginalSources(ctx context.Context, original *OriginalSQLCoverageTransaction, expected *UnadmittedSQLCoverageCensus) (*LockedSQLCoverageCensus, error) {
	if s == nil || original == nil || original.owner != s || original.tx == nil || expected == nil || expected.owner != s || ctx == nil || ctx.Err() != nil {
		return nil, ErrSQLCoverageCensus
	}
	tx := original.tx
	facts, err := s.scan(ctx, tx, true)
	if err != nil || !sameSQLCensus(facts, expected.facts) {
		return nil, ErrSQLCoverageCensus
	}
	return &LockedSQLCoverageCensus{owner: s, tx: tx, facts: facts}, nil
}

func (l *LockedSQLCoverageCensus) Facts() SQLCoverageCensusFacts {
	if l == nil {
		return SQLCoverageCensusFacts{}
	}
	f := l.facts
	f.Tables = append([]SQLCoverageTable(nil), f.Tables...)
	return f
}

// Recheck uses precisely the originating transaction and already-locked source
// ranges. It detects the owner's own subsequent mutations too. It must not be
// replaced by a new connection, a MAX(id), a COUNT or an operator completion bit.
func (l *LockedSQLCoverageCensus) Recheck(ctx context.Context, tx *sql.Tx) error {
	if l == nil || tx == nil || tx != l.tx || ctx == nil || ctx.Err() != nil {
		return ErrSQLCoverageCensus
	}
	facts, err := l.owner.scan(ctx, tx, true)
	if err != nil || !sameSQLCensus(facts, l.facts) {
		return ErrSQLCoverageCensus
	}
	return nil
}

func sameSQLCensus(a, b SQLCoverageCensusFacts) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

// Every installed backup table has an explicit disposition. Unknown future
// backup tables fail closed. Excluded tables contain authentication/coordination
// or the derived KEK index, not original artifact/reference lifecycle sources.
// Exclusion is code-reviewed here, never caller-configurable.
func sqlCensusSources() (map[string]reg.Partition, map[string]bool) {
	groups := map[reg.Partition]string{
		reg.RetainedArtifacts:        `system_backup_artifacts system_backup_config_versions system_backup_installation_state system_backup_v2_backups system_backup_v2_configs system_backup_v2_installation_state system_backup_v2_execution_inputs system_backup_v2_execution_plans system_backup_v2_execution_records system_backup_v2_evidence system_backup_v2_evidence_chunks system_team_data_backup_jobs`,
		reg.InflightAndUnknownWrites: `system_backup_tasks system_backup_attempts system_backup_capture_aborts system_backup_capture_jobs system_backup_capture_plans system_backup_external_actions system_backup_job_sends system_backup_stage_resources system_backup_operations system_backup_v2_attempts system_backup_v2_external_actions system_backup_v2_import_journal system_backup_v2_job_observations system_backup_v2_job_send_intents system_backup_v2_operations system_backup_v2_runtime_captures system_backup_v2_runtime_controls system_backup_v2_runtime_resources system_backup_v2_runtime_stop_proofs system_backup_v2_runtime_writers system_backup_v2_staging_resources system_backup_v2_relay_receipts system_backup_v2_gateway_proofs`,
		reg.HoldsAndCatalog:          `system_backup_v2_promotions system_backup_v2_artifact_lease_states system_backup_v2_artifact_leases`,
		reg.RestoreAndPrune:          `system_backup_restore_jobs system_backup_restore_evidence system_backup_quarantine system_backup_v2_restore_drills system_backup_v2_restore_drill_resources system_backup_v2_preflights system_backup_v2_artifact_verifications system_backup_v2_prune_runs system_backup_v2_prune_items system_backup_v2_compact_tombstones system_backup_v2_check_results`,
	}
	sources := map[string]reg.Partition{}
	for partition, names := range groups {
		for _, name := range strings.Fields(names) {
			sources[name] = partition
		}
	}
	excluded := map[string]bool{}
	for _, name := range strings.Fields(`system_backup_controller_leases system_backup_dependency_health system_backup_events system_backup_gate system_backup_gate_admissions system_backup_mutation_leases system_backup_participants system_backup_strong_auth_nonces system_backup_installation_kek_authority system_backup_installation_kek_authority_history system_backup_v2_admin_revocations system_backup_v2_admin_sessions system_backup_v2_alert_states system_backup_v2_config_maintenance_receipts system_backup_v2_control_health system_backup_v2_dependency_health system_backup_v2_download_admission_receipts system_backup_v2_download_result_receipts system_backup_v2_engine_bindings system_backup_v2_events system_backup_v2_execution_readiness system_backup_v2_kek_admissions system_backup_v2_kek_bindings system_backup_v2_kek_coverage system_backup_v2_kek_fences system_backup_v2_kek_references system_backup_v2_log_chunks system_backup_v2_maintenance_locks system_backup_v2_maintenance_mutation_leases system_backup_v2_maintenance_participants system_backup_v2_metadata_reservations system_backup_v2_producer_recovery_revocations system_backup_v2_provider_capabilities system_backup_v2_recovery_deployments system_backup_v2_recovery_managers system_backup_v2_source_writer_check_states system_backup_v2_strong_auth_nonces system_backup_v2_totp_credentials`) {
		excluded[name] = true
	}
	return sources, excluded
}

type sqlCensusColumn struct{ Name, Type, Nullable, Extra, Charset, Collation string }
type sqlCensusSchema struct {
	Columns []sqlCensusColumn
	Primary []string
}

func censusFrame(h hash.Hash, raw []byte) {
	if raw == nil {
		h.Write([]byte{0})
		return
	}
	h.Write([]byte{1})
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(raw)))
	h.Write(size[:])
	h.Write(raw)
}

func (s *SQLCoverageCensus) scan(ctx context.Context, tx *sql.Tx, locked bool) (SQLCoverageCensusFacts, error) {
	facts := SQLCoverageCensusFacts{InstallationID: s.installation, Tables: []SQLCoverageTable{}}
	var zone string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),@@session.time_zone").Scan(&facts.Database.ServerUUID, &facts.Database.Database, &facts.ObservedAt, &zone) != nil || facts.Database != s.database || zone != "+00:00" {
		return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
	}
	sources, excluded := sqlCensusSources()
	rows, err := tx.QueryContext(ctx, `SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND (LEFT(TABLE_NAME,13)='system_backup' OR TABLE_NAME='system_team_data_backup_jobs') ORDER BY TABLE_NAME`)
	if err != nil {
		return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var engine sql.NullString
		if rows.Scan(&name, &engine) != nil || len(seen) >= 128 || seen[name] || !engine.Valid || engine.String != "InnoDB" {
			rows.Close()
			return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
		}
		if _, ok := sources[name]; !ok && !excluded[name] {
			rows.Close()
			return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
		}
		seen[name] = true
	}
	err = rows.Err()
	extra := rows.NextResultSet()
	closeErr := rows.Close()
	if err != nil || extra || closeErr != nil {
		return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		if !seen[name] {
			return SQLCoverageCensusFacts{}, ErrSQLCoverageCensus
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var total uint64
	for _, name := range names {
		table, err := scanSQLCensusTable(ctx, tx, name, sources[name], locked, &total)
		if err != nil {
			return SQLCoverageCensusFacts{}, err
		}
		facts.Tables = append(facts.Tables, table)
	}
	return facts, nil
}

func scanSQLCensusTable(ctx context.Context, tx *sql.Tx, name string, partition reg.Partition, locked bool, total *uint64) (SQLCoverageTable, error) {
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
	table.RowsSHA256 = hex.EncodeToString(h.Sum(nil))
	return table, nil
}

func sqlCensusIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if b != '_' && (b < 'a' || b > 'z') && (b < '0' || b > '9') {
			return false
		}
	}
	return true
}
