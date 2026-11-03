package install

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"strings"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

const originalHistorySingletonTable = "system_backup_installation_state"

// This classifies ONE actual original, unconfigured installation singleton.
// It is not an S3-absence claim, a complete history universe or PreparedCoverage.
// No factory accepts supplied row values, reference lists or an empty flag.
type originalHistorySQLMetadata struct {
	origin         *originalHistorySQLMetadata
	ctx, sourceCtx context.Context
	cancel         context.CancelFunc
	prep           *PreparedOriginalAdoptionSQLCut
	hold           *OriginalWriterHold
	installed      *originalInstalledBackupConfiguration
	row            originalHistorySingletonRow
	original       a.SQLCoverageCensusFacts
	until, floor   time.Time
	revision       string
	boundTx        *sql.Tx
	coverage       *PreparedOriginalAdoptionCoverage
	epoch          uint64
	failed         bool
}

type originalHistorySingletonRow struct{ cells [][]byte }

func (*originalHistorySQLMetadata) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalHistorySQLMetadata) String() string               { return "OriginalHistorySQLMetadata" }
func (*originalHistorySQLMetadata) GoString() string             { return "OriginalHistorySQLMetadata" }

func prepareOriginalHistorySQLMetadata(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold) (*originalHistorySQLMetadata, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	return prepareOriginalHistorySQLMetadataLocked(ctx, p, h)
}

// Caller already holds original set.mu -> prep.mu. Actual native reads and
// short independent SQL observations here precede the final source lock prefix.
func prepareOriginalHistorySQLMetadataLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold) (result *originalHistorySQLMetadata, err error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	for _, cap := range []time.Time{p.until, h.set.owner.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	if !time.Now().Before(until) {
		return nil, ErrInstall
	}
	// This child only bounds SQL SOURCE DATA I/O. Admission and this private
	// classification remain tied to ctx, p and h; no authorization is renewed.
	sourceCtx, cancel := context.WithDeadline(ctx, until)
	r := &originalHistorySQLMetadata{ctx: ctx, sourceCtx: sourceCtx, cancel: cancel, prep: p, hold: h, until: until, original: p.observed.Facts()}
	r.origin = r
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if !originalHistorySingletonOnly(r.original) {
		return nil, ErrInstall
	}
	r.installed, err = readOriginalInstalledBackupConfiguration(ctx, p.operator.installer.db, until)
	if err != nil || !r.installedMatchesOriginal() {
		return nil, ErrInstall
	}
	r.row, r.floor, err = r.readCurrentSingleton()
	if err != nil || r.floor.Before(r.original.ObservedAt) {
		return nil, ErrInstall
	}
	r.revision = originalObjectSHA(struct {
		Version      string
		Database     reg.DatabaseIdentity
		Installation string
		Tables       []a.SQLCoverageTable
		Row          [][]byte
	}{"original-unconfigured-singleton-classification.v1", r.original.Database, r.original.InstallationID, r.original.Tables, r.row.cells})
	if r.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	return r, nil
}

func (r *originalHistorySQLMetadata) local(ctx context.Context, final bool) bool {
	return r != nil && r.origin == r && !r.failed && r.sourceCtx != nil && r.sourceCtx.Err() == nil &&
		consumerSameContext(ctx, r.ctx) && originalEmptyHistoryOwner(ctx, r.prep, r.hold, final) &&
		time.Now().Before(r.until) && r.installedMatchesOriginal()
}

func (r *originalHistorySQLMetadata) installedMatchesOriginal() bool {
	if r == nil || r.installed == nil || r.prep == nil || r.prep.operator == nil || r.installed.origin != r.installed || !r.installed.local(r.ctx) {
		return false
	}
	i := r.prep.operator.installer
	s := r.installed
	return i != nil && s.db == i.db && s.serverUUID == r.original.Database.ServerUUID && s.database == r.original.Database.Database &&
		s.account == i.plan.InstallerDatabaseAccount && s.installation == r.original.InstallationID && s.installation == r.prep.reservation.InstallationID &&
		s.version == 0 && len(s.versions) == 0
}

// This finite reviewed branch accounts for the exact singleton as non-key
// control metadata. All other ORIGINAL source tables, including all config
// versions/tasks/unknown writes, must be genuinely empty. It excludes no table
// from the original scan and does not account for the later17 staged controls.
func originalHistorySingletonOnly(f a.SQLCoverageCensusFacts) bool {
	if f.Database.ServerUUID == "" || f.Database.Database == "" || f.InstallationID == "" || f.ObservedAt.IsZero() || len(f.Tables) < 4 {
		return false
	}
	seen := make(map[string]bool, len(f.Tables))
	for _, table := range f.Tables {
		if table.Table == "" || seen[table.Table] || !digestPattern.MatchString(table.SchemaSHA256) || !digestPattern.MatchString(table.RowsSHA256) {
			return false
		}
		seen[table.Table] = true
		if table.Table == originalHistorySingletonTable {
			if table.Partition != reg.RetainedArtifacts || table.Rows != 1 || table.Bytes == 0 {
				return false
			}
		} else if table.Rows != 0 || table.Bytes != 0 {
			return false
		}
	}
	return seen[originalHistorySingletonTable] && seen["system_backup_config_versions"] && seen["system_backup_v2_configs"] && seen["system_backup_tasks"]
}

func sameOriginalHistorySQLFacts(want, actual a.SQLCoverageCensusFacts) bool {
	want.ObservedAt, actual.ObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(want, actual)
}

// C's private FS-only branch can compare its ACTUAL original scanner result
// against this classification. This predicate grants neither filesystem nor
// S3 absence. It must not be used with synthesized facts or outside SourceSet.
func (r *originalHistorySQLMetadata) classifiesOriginalSQL(ctx context.Context, actual a.SQLCoverageCensusFacts) bool {
	return r.local(ctx, false) && originalHistorySingletonOnly(actual) && !actual.ObservedAt.IsZero() &&
		!actual.ObservedAt.Before(r.original.ObservedAt) && actual.ObservedAt.Before(r.until) && sameOriginalHistorySQLFacts(r.original, actual)
}

func (r *originalHistorySQLMetadata) readCurrentSingleton() (row originalHistorySingletonRow, now time.Time, err error) {
	if r == nil || r.prep == nil || r.installed == nil {
		return row, now, ErrInstall
	}
	i := r.prep.operator.installer
	tx, err := i.db.BeginTx(r.sourceCtx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return row, now, ErrInstall
	}
	defer tx.Rollback()
	now, err = i.database(r.sourceCtx, tx, r.until)
	if err != nil {
		return row, now, ErrInstall
	}
	row, err = readOriginalHistorySingletonRow(r.sourceCtx, tx, r.installed.installation, false)
	if err != nil || tx.Rollback() != nil {
		row.clear()
		return originalHistorySingletonRow{}, time.Time{}, ErrInstall
	}
	return row, now, nil
}

// Re-read actual config/body and the complete original census before SQL locks.
func (r *originalHistorySQLMetadata) recheckBeforeSQL(ctx context.Context) (err error) {
	if r == nil {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if !r.local(ctx, false) || r.hold.recheckBeforeSQL(ctx) != nil || r.prep.operator.authority(ctx, r.prep.enrollment) != nil {
		return ErrInstall
	}
	fresh, err := readOriginalInstalledBackupConfiguration(ctx, r.prep.operator.installer.db, r.until)
	if err != nil {
		return ErrInstall
	}
	defer fresh.close()
	if !r.installed.same(fresh) || fresh.checkedAt.Before(r.floor) {
		return ErrInstall
	}
	row, now, err := r.readCurrentSingleton()
	if err != nil {
		return ErrInstall
	}
	defer row.clear()
	if now.Before(r.floor) || now.Before(fresh.checkedAt) || !reflect.DeepEqual(row.cells, r.row.cells) {
		return ErrInstall
	}
	tail, err := r.prep.scanner.Observe(r.sourceCtx)
	if err != nil || !r.classifiesOriginalSQL(ctx, tail.Facts()) || tail.Facts().ObservedAt.Before(now) || !r.local(ctx, false) {
		return ErrInstall
	}
	r.floor = tail.Facts().ObservedAt
	return nil
}

// Bind from the actual source-consuming PreparedCoverage constructor after
// Stage/Bind/authentication, not from a supplied tx or first-observed epoch.
// The owner set/preparation locks must already be held. This grants no new tx.
func (r *originalHistorySQLMetadata) bindOriginalCoverage(ctx context.Context, coverage *PreparedOriginalAdoptionCoverage) error {
	if !r.local(ctx, true) || coverage == nil || coverage.origin != coverage || coverage.hold != r.hold || !consumerSameContext(ctx, coverage.ctx) ||
		coverage.tx == nil || coverage.cut == nil || coverage.authenticated == nil || coverage.native == nil || coverage.native.set != r.hold.set ||
		coverage.until.IsZero() || coverage.until.After(r.until) || coverage.until.After(coverage.authenticated.ValidUntil()) || coverage.epoch == ^uint64(0) ||
		coverage.refs == nil || len(coverage.refs) != 0 || len(coverage.sources) != 4 {
		return ErrInstall
	}
	source, ok := coverage.history.(*originalEmptyHistorySource)
	if !ok || source == nil || source.origin != source || source.prep != r.prep || source.hold != r.hold || !consumerSameContext(ctx, source.ctx) ||
		(r.coverage != nil && (r.coverage != coverage || r.boundTx != coverage.tx || r.epoch != coverage.epoch)) {
		return ErrInstall
	}
	r.coverage, r.boundTx, r.epoch = coverage, coverage.tx, coverage.epoch
	return nil
}

// Only call AFTER the real PreparedCoverage/cut has authenticated this exact
// original transaction and locked ALL original source ranges. These reads
// only revisit those held ranges; they do not reacquire an earlier prefix.
// No new tx, provider/Kubernetes/filesystem read, authority renewal or generic
// zero-table exemption occurs here. A's source rows are already locked ranges.
func (r *originalHistorySQLMetadata) recheckLocked(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time) (err error) {
	if r == nil {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if !r.local(ctx, true) || tx == nil || r.coverage == nil || r.coverage.origin != r.coverage || r.coverage.hold != r.hold ||
		r.coverage.authenticated == nil || r.coverage.cut == nil || r.coverage.native == nil || r.coverage.native.set != r.hold.set ||
		r.boundTx != tx || r.coverage.tx != tx || r.coverage.epoch != r.epoch || !consumerSameContext(ctx, r.coverage.ctx) ||
		now.IsZero() || now.Before(r.floor) || !now.Before(r.until) || !now.Before(r.coverage.until) {
		return ErrInstall
	}
	facts := locked.Facts()
	if facts.Database != r.original.Database || facts.InstallationID != r.original.InstallationID || facts.References == nil || len(facts.References) != 0 ||
		facts.Epoch == ^uint64(0) || r.epoch != facts.Epoch {
		return ErrInstall
	}
	if r.coverage.authenticated.Recheck(ctx, tx, locked, now) != nil || r.coverage.cut.Recheck(ctx) != nil ||
		r.installed.recheckLocked(ctx, tx) != nil || !r.installedMatchesOriginal() {
		return ErrInstall
	}
	row, err := readOriginalHistorySingletonRow(r.sourceCtx, tx, r.installed.installation, true)
	if err != nil {
		return ErrInstall
	}
	defer row.clear()
	if !reflect.DeepEqual(row.cells, r.row.cells) || !r.local(ctx, true) {
		return ErrInstall
	}
	stamp, err := r.prep.operator.installer.database(r.sourceCtx, tx, r.until)
	if err != nil || stamp.Before(now) || stamp.Before(r.floor) {
		return ErrInstall
	}
	return nil
}

func (r *originalHistorySQLMetadata) close() {
	if r == nil {
		return
	}
	r.failed = true
	if r.origin != r {
		return
	}
	r.row.clear()
	if r.installed != nil {
		r.installed.close()
	}
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *originalHistorySingletonRow) clear() {
	for _, cell := range r.cells {
		clear(cell)
	}
	r.cells = nil
}

// Exact published079 schema; unknown/missing/extra columns are not silently
// dropped. Every row is read to EOF without WHERE, so malformed extra rows do
// not disappear behind singleton_id=1. NULL and timestamp bytes stay distinct.
func readOriginalHistorySingletonRow(ctx context.Context, tx *sql.Tx, installation string, locked bool) (result originalHistorySingletonRow, err error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || installation == "" {
		return result, ErrInstall
	}
	columns, err := tx.QueryContext(ctx, `SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,EXTRA,COALESCE(CHARACTER_SET_NAME,''),COALESCE(COLLATION_NAME,'') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_installation_state' ORDER BY ORDINAL_POSITION`)
	if err != nil {
		return result, ErrInstall
	}
	expected := [][3]string{{"singleton_id", "tinyint", "NO"}, {"origin_installation_id", "varchar(64)", "NO"}, {"config_version", "bigint unsigned", "NO"}, {"controller_seen_at", "datetime(6)", "YES"}}
	n := 0
	for columns.Next() {
		var name, kind, nullable, extra, charset, collation string
		if n >= len(expected) || columns.Scan(&name, &kind, &nullable, &extra, &charset, &collation) != nil ||
			[3]string{name, kind, nullable} != expected[n] || extra != "" ||
			(name == "origin_installation_id" && (charset != "utf8mb4" || !strings.HasPrefix(collation, "utf8mb4_"))) ||
			(name != "origin_installation_id" && (charset != "" || collation != "")) {
			columns.Close()
			return result, ErrInstall
		}
		n++
	}
	if columns.Err() != nil || columns.NextResultSet() || columns.Close() != nil || n != len(expected) {
		return result, ErrInstall
	}
	keys, err := tx.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_installation_state' AND CONSTRAINT_NAME='PRIMARY' ORDER BY ORDINAL_POSITION`)
	if err != nil {
		return result, ErrInstall
	}
	var key string
	if !keys.Next() || keys.Scan(&key) != nil || key != "singleton_id" || keys.Next() || keys.Err() != nil || keys.NextResultSet() || keys.Close() != nil {
		keys.Close()
		return result, ErrInstall
	}
	query := `SELECT * FROM system_backup_installation_state ORDER BY singleton_id`
	if locked {
		query += " FOR SHARE"
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return result, ErrInstall
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil || !reflect.DeepEqual(names, []string{"singleton_id", "origin_installation_id", "config_version", "controller_seen_at"}) || !rows.Next() {
		return result, ErrInstall
	}
	values := make([]sql.RawBytes, 4)
	if rows.Scan(&values[0], &values[1], &values[2], &values[3]) != nil || string(values[0]) != "1" || string(values[1]) != installation || string(values[2]) != "0" {
		return result, ErrInstall
	}
	if values[3] != nil {
		text := string(values[3])
		_, one := time.Parse(time.RFC3339Nano, text)
		_, two := time.Parse("2006-01-02 15:04:05.999999", text)
		if one != nil && two != nil {
			return result, ErrInstall
		}
	}
	for _, value := range values {
		result.cells = append(result.cells, bytes.Clone(value))
	}
	if rows.Next() || rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil || ctx.Err() != nil {
		result.clear()
		return originalHistorySingletonRow{}, ErrInstall
	}
	return result, nil
}
