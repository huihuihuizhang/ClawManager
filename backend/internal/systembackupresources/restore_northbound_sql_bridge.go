package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// These are declarations and lossless data, not source authentication, target
// permissions, a NodePort allocation, or a complete physical isolation proof.
// The ordinary worker must authenticate its input before calling this bridge;
// its authority/target checks remain required before writes and COMMIT.
type NorthboundRestoreScope struct{ Database, ServerUUID string }
type NorthboundRestoreRange struct{ Min, Max int64 }
type NorthboundRestoreDeclarations struct {
	ExternalNodePort                  int64
	Limits                            map[string]NorthboundRestoreRange // CPU is exact hundredths, not float.
	AllowedLiteTypes, AllowedProTypes []string
}
type NorthboundRestoreBudget struct{ Rows, Bytes int64 }
type NorthboundRestoreTable struct {
	Columns []string
	Rows    []map[string]*string
}
type NorthboundRestoreBinding struct {
	Kind           string
	Source, Target int64
}
type NorthboundRestoreSource struct {
	Settings, Audit NorthboundRestoreTable
	Bindings        []NorthboundRestoreBinding
}

// No JSON/DTO constructor can create an observed version or transaction-bound
// CAS candidate. Both types carry data correspondence, never restore authority.
type NorthboundTargetObservation struct {
	scope           NorthboundRestoreScope
	settings        restoreFieldTable
	policy          restoreNorthboundPolicy
	bootstrapActors map[string]bool
	writeTx         *sql.Tx
}
type NorthboundCASCandidate struct {
	tx                                                *sql.Tx
	scope                                             NorthboundRestoreScope
	before, after, audit, sourceSettings, sourceAudit restoreFieldTable
	bootstrapActors                                   map[string]bool
	sourceBindings                                    []restoreIDBinding
	budget                                            restoreFieldBudget
	bootstrapDeleted                                  bool
}

var northboundRestoreDatabase = regexp.MustCompile(`^cm_drill_[a-z0-9_]{1,54}$`)

func bridgeBudget(b NorthboundRestoreBudget) (restoreFieldBudget, error) {
	if b.Rows <= 0 || b.Rows >= math.MaxInt64 || b.Rows > 100000 || b.Bytes <= 0 || b.Bytes > 32<<20 {
		return restoreFieldBudget{}, errors.New("northbound bounded capacity is required")
	}
	return restoreFieldBudget{Rows: b.Rows, Bytes: b.Bytes}, nil
}
func bridgePolicy(d NorthboundRestoreDeclarations) (restoreNorthboundPolicy, error) {
	p := restoreNorthboundPolicy{ExternalNodePort: d.ExternalNodePort, Limits: map[string]restoreNorthboundRange{}, AllowedLiteTypes: append([]string(nil), d.AllowedLiteTypes...), AllowedProTypes: append([]string(nil), d.AllowedProTypes...)}
	base := restoreNorthboundBounds()
	if len(d.Limits) != len(base) || p.ExternalNodePort != 0 && (p.ExternalNodePort < 30000 || p.ExternalNodePort > 32767) || !validRestoreNorthboundTypes(p.AllowedLiteTypes, nil) || !validRestoreNorthboundTypes(p.AllowedProTypes, nil) {
		return p, errors.New("northbound target declarations are incomplete")
	}
	for name, bounds := range base {
		limit, ok := d.Limits[name]
		if !ok || limit.Min < bounds.Min || limit.Max > bounds.Max || limit.Min > limit.Max {
			return p, errors.New("northbound target declarations exceed reviewed bounds")
		}
		p.Limits[name] = restoreNorthboundRange{Min: limit.Min, Max: limit.Max}
	}
	return p, nil
}
func bridgeScope(ctx context.Context, tx *sql.Tx, scope NorthboundRestoreScope) error {
	if ctx == nil || tx == nil || !northboundRestoreDatabase.MatchString(scope.Database) || scope.ServerUUID == "" {
		return errors.New("northbound isolated SQL identity is required")
	}
	var name, uuid, zone string
	if tx.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid, @@session.time_zone").Scan(&name, &uuid, &zone) != nil || name != scope.Database || uuid != scope.ServerUUID || zone != "+00:00" {
		return errors.New("northbound actual SQL identity or UTC session differs")
	}
	return ctx.Err()
}
func bridgeTable(name string, data NorthboundRestoreTable) restoreFieldTable {
	t := restoreFieldTable{Name: name, Columns: append([]string(nil), data.Columns...)}
	for _, row := range data.Rows {
		t.Rows = append(t.Rows, cloneRestoreAuditRow(restoreFieldRow(row)))
	}
	return t
}
func exportBridgeTable(t restoreFieldTable) NorthboundRestoreTable {
	out := NorthboundRestoreTable{Columns: append([]string(nil), t.Columns...)}
	for _, row := range t.Rows {
		out.Rows = append(out.Rows, map[string]*string(cloneRestoreAuditRow(row)))
	}
	return out
}
func equalBridgeTable(a, b restoreFieldTable) bool {
	if a.Name != b.Name || len(a.Columns) != len(b.Columns) || len(a.Rows) != len(b.Rows) {
		return false
	}
	for i, name := range a.Columns {
		if b.Columns[i] != name {
			return false
		}
	}
	for i, row := range a.Rows {
		if !restoreWriteRowsEqual(a.Columns, row, b.Rows[i]) {
			return false
		}
	}
	return true
}

// Read only the two scoped tables. The nine-table writer is not invoked with
// fabricated empty scan/egress/image rows or callbacks that merely return nil.
func readNorthboundBridgeTable(ctx context.Context, tx *sql.Tx, name string, budget restoreFieldBudget, lock bool) (restoreFieldTable, error) {
	if name != "northbound_admin_settings" && name != "northbound_settings_audit" {
		return restoreFieldTable{}, errors.New("northbound table is outside the bridge")
	}
	columns := restoreFieldColumns()[name]
	if e := inspectRestoreFieldTable(ctx, tx, name, columns); e != nil {
		return restoreFieldTable{}, e
	}
	projection := make([]string, len(columns))
	for i, column := range columns {
		projection[i] = "CAST(`" + column + "` AS CHAR CHARACTER SET utf8mb4) AS `" + column + "`"
	}
	query := "SELECT " + strings.Join(projection, ",") + " FROM `" + name + "` ORDER BY `id` LIMIT " + strconv.FormatInt(budget.Rows+1, 10)
	if lock {
		query += " FOR UPDATE"
	}
	rows, e := tx.QueryContext(ctx, query)
	if e != nil {
		return restoreFieldTable{}, errors.New("northbound actual row read failed")
	}
	values, e := scanRestoreFieldRows(ctx, rows, columns, &budget)
	if e != nil {
		return restoreFieldTable{}, e
	}
	return restoreFieldTable{Name: name, Columns: append([]string(nil), columns...), Rows: values}, nil
}
func bridgeSingleton(t restoreFieldTable) (*int64, error) {
	if len(t.Rows) == 0 {
		return nil, nil
	}
	if len(t.Rows) != 1 || t.Rows[0]["id"] == nil || *t.Rows[0]["id"] != "1" {
		return nil, errors.New("northbound target singleton differs")
	}
	version, e := parseRestoreNorthboundInteger(t.Rows[0]["version"])
	if e != nil || version < 1 || version == math.MaxInt64 {
		return nil, errors.New("northbound target version is unavailable or exhausted")
	}
	return &version, nil
}
func readNorthboundBootstrapActors(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, e := tx.QueryContext(ctx, "SELECT id FROM users WHERE username='admin' AND role='admin' ORDER BY id LIMIT 2")
	if e != nil {
		return nil, errors.New("northbound bootstrap identity read failed")
	}
	defer rows.Close()
	result := map[string]bool{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil || id <= 0 || id > math.MaxInt32 || len(result) >= 1 {
			return nil, errors.New("northbound bootstrap identity differs")
		}
		result[strconv.FormatInt(id, 10)] = true
	}
	if rows.Err() != nil {
		return nil, errors.New("northbound bootstrap identity read failed")
	}
	return result, ctx.Err()
}

// ObserveNorthboundRestoreTarget reads actual target data in one read-only RR
// transaction. Read-only transaction mode does not assert read-only IAM grants.
// Prepare repeats the complete observation under the common writable TX locks.
func ObserveNorthboundRestoreTarget(ctx context.Context, db *sql.DB, scope NorthboundRestoreScope, declarations NorthboundRestoreDeclarations, b NorthboundRestoreBudget) (*NorthboundTargetObservation, error) {
	if ctx == nil || db == nil {
		return nil, errors.New("northbound target observation requires context and database")
	}
	budget, e := bridgeBudget(b)
	if e != nil {
		return nil, e
	}
	policy, e := bridgePolicy(declarations)
	if e != nil {
		return nil, e
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, errors.New("northbound target observation begin failed")
	}
	defer tx.Rollback()
	if e = bridgeScope(ctx, tx, scope); e != nil {
		return nil, e
	}
	settings, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", budget, false)
	if e != nil {
		return nil, e
	}
	if _, e = bridgeSingleton(settings); e != nil {
		return nil, e
	}
	audit, e := readNorthboundBridgeTable(ctx, tx, "northbound_settings_audit", budget, false)
	if e != nil {
		return nil, e
	}
	if len(audit.Rows) != 0 {
		return nil, errors.New("northbound target audit must be empty")
	}
	actors, e := readNorthboundBootstrapActors(ctx, tx)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, errors.New("northbound target observation completion is unconfirmed")
	}
	return &NorthboundTargetObservation{scope: scope, settings: settings, policy: policy, bootstrapActors: actors}, nil
}

// BeginNorthboundRestoreTransaction is the only constructor of a writable
// observation. It opens the common transaction explicitly as SERIALIZABLE;
// Prepare refuses an arbitrary external TX, including READ COMMITTED. A session
// transaction_isolation variable would not prove the active transaction level
// after SET TRANSACTION, so it is deliberately not used as such a proof.
func BeginNorthboundRestoreTransaction(ctx context.Context, conn *sql.Conn, observation *NorthboundTargetObservation) (*sql.Tx, *NorthboundTargetObservation, error) {
	if ctx == nil || conn == nil || observation == nil || observation.writeTx != nil {
		return nil, nil, errors.New("northbound fresh target observation and connection are required")
	}
	tx, e := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return nil, nil, errors.New("northbound SERIALIZABLE transaction begin failed")
	}
	if e = bridgeScope(ctx, tx, observation.scope); e != nil {
		tx.Rollback()
		return nil, nil, e
	}
	bound := *observation
	bound.writeTx = tx
	return tx, &bound, nil
}

func boundNorthboundSource(ctx context.Context, source NorthboundRestoreSource, budget restoreFieldBudget) error {
	remainingRows, remainingBytes := budget.Rows, budget.Bytes
	for _, entry := range []struct {
		table   NorthboundRestoreTable
		columns int
	}{{source.Settings, 35}, {source.Audit, 6}} {
		if len(entry.table.Columns) != entry.columns || int64(len(entry.table.Rows)) > remainingRows {
			return errors.New("northbound source shape or row capacity differs")
		}
		remainingRows -= int64(len(entry.table.Rows))
		for _, row := range entry.table.Rows {
			if e := ctx.Err(); e != nil {
				return e
			}
			if len(row) != entry.columns {
				return errors.New("northbound source column count differs")
			}
			for _, cell := range row {
				if cell != nil {
					if int64(len(*cell)) > remainingBytes {
						return errors.New("northbound source byte capacity exceeded")
					}
					remainingBytes -= int64(len(*cell))
				}
			}
		}
	}
	// There can be at most one actor binding per settings/audit row plus one
	// owner creation user and one stable audit-ID binding per audit row.
	if int64(len(source.Bindings)) > 2*int64(len(source.Audit.Rows))+2 {
		return errors.New("northbound source identity mapping capacity exceeded")
	}
	return ctx.Err()
}
func freezeNorthboundSource(source NorthboundRestoreSource) (restoreFieldTable, restoreFieldTable, []restoreIDBinding, error) {
	settings, audit := bridgeTable("northbound_admin_settings", source.Settings), bridgeTable("northbound_settings_audit", source.Audit)
	// Current deployments always have the singleton. Absence cannot safely be
	// treated as API-disabled: Current() has an API-enabled fallback.
	if len(settings.Rows) != 1 {
		return settings, audit, nil, errors.New("northbound source singleton material is required")
	}
	var bindings []restoreIDBinding
	for _, b := range source.Bindings {
		kind := restoreIDKind(b.Kind)
		if kind != restoreUserID && kind != restoreNBAuditID || b.Source != b.Target {
			return settings, audit, nil, errors.New("northbound bridge requires explicit stable identity mappings")
		}
		bindings = append(bindings, restoreIDBinding{Kind: kind, Source: b.Source, Target: b.Target})
	}
	if _, e := newRestoreIDMap(bindings); e != nil {
		return settings, audit, nil, e
	}
	return settings, audit, bindings, nil
}

// PrepareNorthboundRestoreInTransaction must precede every DML in the common
// restore TX. Source data is copied before IO. Only actual locked target state
// supplies ObservedVersion; source version never becomes target version+1.
func PrepareNorthboundRestoreInTransaction(ctx context.Context, tx *sql.Tx, observation *NorthboundTargetObservation, source NorthboundRestoreSource, b NorthboundRestoreBudget) (*NorthboundCASCandidate, error) {
	if ctx == nil || tx == nil || observation == nil || observation.writeTx != tx {
		return nil, errors.New("northbound controlled SERIALIZABLE transaction and observation are required")
	}
	budget, e := bridgeBudget(b)
	if e != nil {
		return nil, e
	}
	if e = boundNorthboundSource(ctx, source, budget); e != nil {
		return nil, e
	}
	settings, audit, bindings, e := freezeNorthboundSource(source)
	if e != nil {
		return nil, e
	}
	if e = bridgeScope(ctx, tx, observation.scope); e != nil {
		return nil, e
	}
	before, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", budget, true)
	if e != nil {
		return nil, e
	}
	if !equalBridgeTable(before, observation.settings) {
		return nil, errors.New("northbound target changed since observation")
	}
	occupied, e := readNorthboundBridgeTable(ctx, tx, "northbound_settings_audit", budget, true)
	if e != nil {
		return nil, e
	}
	if len(occupied.Rows) != 0 {
		return nil, errors.New("northbound target audit is occupied")
	}
	version, e := bridgeSingleton(before)
	if e != nil {
		return nil, e
	}
	policy := observation.policy
	policy.ObservedVersion = version
	for name, out := range map[string]*string{"allowed_lite_types": &policy.ProjectedLiteTypesJSON, "allowed_pro_types": &policy.ProjectedProTypesJSON} {
		value := settings.Rows[0][name]
		if value == nil || tx.QueryRowContext(ctx, "SELECT CAST(? AS JSON)", *value).Scan(out) != nil {
			return nil, errors.New("northbound actual target JSON projection failed")
		}
	}
	normalized, e := normalizeRestoreNorthbound(ctx, restoreNorthboundInput{Source: settings, Bindings: bindings, Policy: &policy, Budget: budget})
	if e != nil {
		return nil, e
	}
	// This scoped call normalizes existing northbound audit only. The source
	// audit_logs domain is not claimed or silently replaced by this empty input.
	auditor, e := normalizeRestoreAudit(ctx, restoreAuditInput{Audit: restoreFieldTable{Name: "audit_logs", Columns: restoreFieldColumns()["audit_logs"]}, Northbound: audit, Bindings: bindings, Budget: budget})
	if e != nil {
		return nil, e
	}
	actors := map[string]bool{}
	for id, v := range observation.bootstrapActors {
		actors[id] = v
	}
	return &NorthboundCASCandidate{tx: tx, scope: observation.scope, before: before, after: normalized.Table, audit: auditor.Northbound, sourceSettings: settings, sourceAudit: audit, bootstrapActors: actors, sourceBindings: bindings, budget: budget}, nil
}

// Projections are independent inert data. They cannot be serialized back into
// a candidate, mint source authorization, or certify target/credential cleanup.
func (p *NorthboundCASCandidate) SettingsProjection() NorthboundRestoreTable {
	if p == nil {
		return NorthboundRestoreTable{}
	}
	return exportBridgeTable(p.after)
}
func (p *NorthboundCASCandidate) AuditProjection() NorthboundRestoreTable {
	if p == nil {
		return NorthboundRestoreTable{}
	}
	return exportBridgeTable(p.audit)
}
func (p *NorthboundCASCandidate) MatchesSource(source NorthboundRestoreSource) error {
	if p == nil || p.tx == nil {
		return errors.New("northbound concrete candidate is missing")
	}
	if e := boundNorthboundSource(context.Background(), source, p.budget); e != nil {
		return e
	}
	settings, audit, bindings, e := freezeNorthboundSource(source)
	if e != nil || !equalBridgeTable(settings, p.sourceSettings) || !equalBridgeTable(audit, p.sourceAudit) || !slices.Equal(bindings, p.sourceBindings) {
		return errors.New("northbound source differs from prepared rows")
	}
	return nil
}
func (p *NorthboundCASCandidate) CheckBefore(ctx context.Context, tx *sql.Tx, scope NorthboundRestoreScope) error {
	if p == nil || p.tx != tx || p.scope != scope {
		return errors.New("northbound candidate belongs to another transaction or target")
	}
	if e := bridgeScope(ctx, tx, scope); e != nil {
		return e
	}
	actual, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", restoreFieldBudget{Rows: 2, Bytes: 32 << 20}, true)
	if e != nil || !equalBridgeTable(actual, p.before) {
		return errors.New("northbound singleton changed before common DML")
	}
	audit, e := readNorthboundBridgeTable(ctx, tx, "northbound_settings_audit", p.budget, true)
	if e != nil || len(audit.Rows) != 0 {
		return errors.New("northbound audit changed before common DML")
	}
	return nil
}

// DeleteNorthboundBootstrapInTransaction performs the actual users deletion
// after the common worker's unchanged user_quotas deletion. A caller cannot
// manufacture the SET NULL exception by
// merely updating updated_by, nor by passing a deleted/passed boolean. Recording
// the real deletion before source users are inserted also supports a source user
// whose ID happens to equal the deleted bootstrap administrator's ID.
func DeleteNorthboundBootstrapInTransaction(ctx context.Context, tx *sql.Tx, p *NorthboundCASCandidate) error {
	if p == nil || p.tx != tx || p.bootstrapDeleted {
		return errors.New("northbound bootstrap deletion candidate differs")
	}
	if e := p.CheckBefore(ctx, tx, p.scope); e != nil {
		return e
	}
	actors, e := readNorthboundBootstrapActors(ctx, tx)
	if e != nil || len(actors) != len(p.bootstrapActors) {
		return errors.New("northbound bootstrap identities changed")
	}
	for id := range actors {
		if !p.bootstrapActors[id] {
			return errors.New("northbound bootstrap identities changed")
		}
	}
	result, e := tx.ExecContext(ctx, "DELETE FROM `users`")
	if e != nil {
		return errors.New("northbound bootstrap deletion failed")
	}
	n, e := result.RowsAffected()
	if e != nil || n != int64(len(actors)) {
		return errors.New("northbound bootstrap deletion outcome differs")
	}
	var remaining int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `users`").Scan(&remaining) != nil || remaining != 0 {
		return errors.New("northbound bootstrap deletion was not observed")
	}
	expected := cloneRestoreFieldTables([]restoreFieldTable{p.before})[0]
	if len(expected.Rows) == 1 {
		if actor := expected.Rows[0]["updated_by"]; actor != nil && actors[*actor] {
			expected.Rows[0]["updated_by"] = nil
		}
	}
	actual, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", restoreFieldBudget{Rows: 2, Bytes: 32 << 20}, true)
	if e != nil || !equalBridgeTable(actual, expected) {
		return errors.New("northbound bootstrap SET NULL transition differs")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	p.bootstrapDeleted = true
	return nil
}

// CheckApplied repeats the entire scoped current row set before the common
// COMMIT. Locked singleton/audit ranges remain held by the same SERIALIZABLE TX.
func (p *NorthboundCASCandidate) CheckApplied(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.tx != tx || !p.bootstrapDeleted {
		return errors.New("northbound completed transaction candidate is missing")
	}
	if e := bridgeScope(ctx, tx, p.scope); e != nil {
		return e
	}
	for _, expected := range []restoreFieldTable{p.after, p.audit} {
		actual, e := readNorthboundBridgeTable(ctx, tx, expected.Name, p.budget, true)
		if e != nil || !equalBridgeTable(actual, expected) {
			return errors.New("northbound final actual raw rows differ")
		}
	}
	return ctx.Err()
}

// ApplyNorthboundSettingsCAS is called at the settings node of the common FK
// write order, after users are restored. User bootstrap deletion can SET NULL
// the old actor in this same TX; only that exact recorded bootstrap transition
// is tolerated. No other before-row change or version drift is ignored.
func ApplyNorthboundSettingsCAS(ctx context.Context, tx *sql.Tx, p *NorthboundCASCandidate, expected NorthboundRestoreTable) error {
	if p == nil || p.tx != tx || !p.bootstrapDeleted {
		return errors.New("northbound CAS candidate or expected row differs")
	}
	if e := boundNorthboundSource(ctx, NorthboundRestoreSource{Settings: expected, Audit: NorthboundRestoreTable{Columns: restoreFieldColumns()["northbound_settings_audit"]}}, p.budget); e != nil {
		return e
	}
	if !equalBridgeTable(bridgeTable("northbound_admin_settings", expected), p.after) {
		return errors.New("northbound CAS expected row differs")
	}
	if e := bridgeScope(ctx, tx, p.scope); e != nil {
		return e
	}
	current, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", restoreFieldBudget{Rows: 2, Bytes: 32 << 20}, true)
	if e != nil {
		return e
	}
	before := cloneRestoreFieldTables([]restoreFieldTable{p.before})[0]
	if len(before.Rows) == 1 && len(current.Rows) == 1 {
		oldActor, newActor := before.Rows[0]["updated_by"], current.Rows[0]["updated_by"]
		if oldActor != nil && newActor == nil && p.bootstrapActors[*oldActor] {
			before.Rows[0]["updated_by"] = nil
		}
	}
	if !equalBridgeTable(before, current) {
		return errors.New("northbound target drifted before CAS")
	}
	audit, e := readNorthboundBridgeTable(ctx, tx, "northbound_settings_audit", p.budget, true)
	if e != nil || len(audit.Rows) != 0 {
		return errors.New("northbound audit occupied before CAS")
	}
	if len(p.after.Rows) != 1 {
		return errors.New("northbound disabled singleton candidate is missing")
	}
	columns := restoreFieldColumns()["northbound_admin_settings"]
	row := p.after.Rows[0]
	var fields, marks []string
	var args []any
	exists := len(p.before.Rows) == 1
	for _, column := range columns {
		if exists && column == "id" {
			continue
		}
		field := "`" + column + "`"
		if exists {
			field += "=?"
		}
		fields = append(fields, field)
		marks = append(marks, "?")
		var value any
		if row[column] != nil {
			value = *row[column]
		}
		args = append(args, value)
	}
	query := "INSERT INTO `northbound_admin_settings` (" + strings.Join(fields, ",") + ") VALUES (" + strings.Join(marks, ",") + ")"
	if exists {
		query = "UPDATE `northbound_admin_settings` SET " + strings.Join(fields, ",") + " WHERE `id`=1 AND `version`=?"
		args = append(args, *p.before.Rows[0]["version"])
	}
	if e = execRestoreWrite(ctx, tx, query, args); e != nil {
		return e
	}
	actual, e := readNorthboundBridgeTable(ctx, tx, "northbound_admin_settings", restoreFieldBudget{Rows: 2, Bytes: 32 << 20}, true)
	if e != nil || !equalBridgeTable(actual, p.after) {
		return errors.New("northbound actual CAS readback differs")
	}
	return ctx.Err()
}
