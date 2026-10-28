package systembackupevidence

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Mandatory collector wiring for the published direct-reference catalog. This
// is not the complete Policy: owner/artifact/evidence dependencies, current GC
// authority, complete privileged metadata visibility and DDL freeze remain the
// caller's obligations. No metadata-derived identifier is ever executed.
type DownloadGCDirectReferencesConfig struct {
	Database                          sec.DatabaseIdentity
	Installation, MaintenanceReceipts string
}

type SQLDownloadGCDirectReferences struct {
	c DownloadGCDirectReferencesConfig
}

func NewSQLDownloadGCDirectReferences(c DownloadGCDirectReferencesConfig) (*SQLDownloadGCDirectReferences, error) {
	if c.Database.ServerUUID == "" || !gcSQLName.MatchString(c.Database.Database) || !installationPattern.MatchString(c.Installation) || !oneOf(c.MaintenanceReceipts, "absent", "installed") {
		return nil, ErrDenied
	}
	return &SQLDownloadGCDirectReferences{c: c}, nil
}

const downloadGCDirectColumnsSQL = `SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND ((LEFT(TABLE_NAME,7)='system_' AND COLUMN_NAME REGEXP '(^|_)(operation(_public)?_id|audit(_log)?_id|nonce_id)$|^operation_identity$') OR (TABLE_NAME='system_backup_v2_check_results' AND COLUMN_NAME='cleanup_target_public_id') OR (TABLE_NAME='system_backup_v2_compact_tombstones' AND COLUMN_NAME='gc_batch_id') OR (TABLE_NAME='system_backup_v2_artifact_leases' AND COLUMN_NAME='holder_public_id') OR (TABLE_NAME='audit_logs' AND COLUMN_NAME IN ('details','resource_id'))) ORDER BY BINARY TABLE_NAME,BINARY COLUMN_NAME LIMIT 10001`
const downloadGCDirectForeignKeysSQL = `SELECT k.TABLE_SCHEMA,k.TABLE_NAME,k.CONSTRAINT_NAME,CAST(k.ORDINAL_POSITION AS CHAR),k.COLUMN_NAME,k.REFERENCED_TABLE_SCHEMA,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.DELETE_RULE FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.REFERENCED_TABLE_NAME IN ('system_backup_v2_operations','audit_logs','system_backup_v2_strong_auth_nonces','system_backup_v2_download_admission_receipts','system_backup_v2_download_result_receipts') AND k.REFERENCED_TABLE_SCHEMA=DATABASE() ORDER BY BINARY k.TABLE_SCHEMA,BINARY k.TABLE_NAME,BINARY k.CONSTRAINT_NAME,k.ORDINAL_POSITION LIMIT 10001`

type gcDirectReference struct {
	stage              int
	table, column, key string
	// value is a CLOSED selector, not a SQL expression. Own row exemptions are
	// only independently reconstructed original group PKs, never actor/state.
	value string
	own   bool
}

func gcDirectReferences(maintenance bool) []gcDirectReference {
	r := []gcDirectReference{
		{1, "system_backup_v2_installation_state", "matrix_transition_operation_public_id", "origin_installation_id", "public", false},
		{1, "system_backup_v2_maintenance_mutation_leases", "operation_identity", "id", "public", false},
		{3, "system_backup_v2_operations", "retry_of_operation_public_id", "id", "public", false},
		{3, "system_backup_v2_compact_tombstones", "gc_batch_id", "id", "public", false},
		{3, "system_backup_v2_download_admission_receipts", "operation_public_id", "operation_id", "public", true},
		{3, "system_backup_v2_download_result_receipts", "operation_public_id", "operation_id", "public", true},
		{3, "system_backup_v2_download_admission_receipts", "intent_audit_id", "operation_id", "audits", true},
		{3, "system_backup_v2_download_result_receipts", "intent_audit_id", "operation_id", "audits", true},
		{3, "system_backup_v2_download_result_receipts", "result_audit_id", "operation_id", "audits", true},
		{5, "system_backup_v2_events", "detail_operation_public_id", "id", "public", false},
		{5, "system_backup_v2_prune_runs", "last_operation_public_id", "id", "public", false},
		{5, "system_backup_v2_prune_items", "last_operation_public_id", "id", "public", false},
		{5, "system_backup_v2_external_actions", "operation_public_id", "id", "public", false},
		{5, "system_backup_v2_check_results", "cleanup_target_public_id", "id", "public", false},
		{5, "system_backup_v2_staging_resources", "cleanup_operation_id", "id", "numeric", false},
		{5, "system_backup_v2_staging_resources", "ownership_resolution_operation_id", "id", "numeric", false},
		{5, "system_backup_v2_restore_drill_resources", "cleanup_operation_id", "id", "numeric", false},
		{5, "system_backup_v2_restore_drill_resources", "ownership_resolution_operation_id", "id", "numeric", false},
		{5, "system_backup_v2_artifact_leases", "holder_public_id", "id", "public", false},
		{5, "system_backup_v2_strong_auth_nonces", "audit_log_id", "id", "audits", true},
	}
	if maintenance {
		r = append(r, gcDirectReference{1, "system_backup_v2_config_maintenance_receipts", "intent_audit_id", "id", "audits", false}, gcDirectReference{1, "system_backup_v2_config_maintenance_receipts", "result_audit_id", "id", "audits", false})
	}
	for _, field := range []string{"operation_public_id", "intent_audit_id", "result_audit_id", "audit_log_id", "nonce_id"} {
		value := "audits"
		if field == "operation_public_id" {
			value = "public"
		}
		if field == "nonce_id" {
			value = "nonce"
		}
		r = append(r, gcDirectReference{7, "audit_logs", "json:" + field, "id", value, true})
	}
	sort.Slice(r, func(i, j int) bool {
		a, b := r[i], r[j]
		if a.stage != b.stage {
			return a.stage < b.stage
		}
		if a.table != b.table {
			return a.table < b.table
		}
		return a.column < b.column
	})
	return r
}

func gcDirectQuery(r gcDirectReference) string {
	column := r.column
	if strings.HasPrefix(column, "json:") {
		column = "JSON_UNQUOTE(JSON_EXTRACT(details,'$." + strings.TrimPrefix(column, "json:") + "'))"
	}
	q := "SELECT " + r.key + " FROM " + r.table + " WHERE " + column + "=?"
	if r.own {
		q += " AND " + r.key + "<>?"
		if r.table == "audit_logs" {
			q += " AND id<>?"
		}
	}
	return q + " LIMIT 1 FOR UPDATE"
}

func gcDirectColumns(maintenance bool) map[string]string {
	out := map[string]string{
		"system_backup_v2_download_admission_receipts.operation_id": "bigint",
		"system_backup_v2_download_result_receipts.operation_id":    "bigint",
		"system_backup_v2_strong_auth_nonces.operation_id":          "bigint",
		"audit_logs.details": "json",
		// Generic resource IDs in published 001 are INTs, not typed Operation
		// links. Equal numeric IDs in unrelated resource domains prove nothing.
		"audit_logs.resource_id": "int",
	}
	for _, r := range gcDirectReferences(maintenance) {
		if strings.HasPrefix(r.column, "json:") {
			continue
		}
		kind := "char"
		switch r.value {
		case "numeric":
			kind = "bigint"
		case "audits":
			kind = "int"
		}
		if oneOf(r.column, "matrix_transition_operation_public_id", "operation_identity", "gc_batch_id", "cleanup_target_public_id", "operation_public_id") {
			kind = "varchar"
		}
		out[r.table+"."+r.column] = kind
	}
	return out
}

func gcDirectFKEdges(maintenance bool) map[string]bool {
	out := map[string]bool{}
	add := func(table, column, target, field string) { out[table+"."+column+">"+target+"."+field] = true }
	for _, r := range gcDirectReferences(maintenance) {
		switch r.value {
		case "numeric":
			add(r.table, r.column, "system_backup_v2_operations", "id")
		case "audits":
			if !strings.HasPrefix(r.column, "json:") {
				add(r.table, r.column, "audit_logs", "id")
			}
		case "public":
			if oneOf(r.table, "system_backup_v2_operations", "system_backup_v2_prune_runs", "system_backup_v2_prune_items", "system_backup_v2_external_actions") {
				add(r.table, r.column, "system_backup_v2_operations", "public_id")
			}
		}
	}
	for _, table := range []string{"system_backup_v2_operations", "system_backup_v2_strong_auth_nonces", "system_backup_v2_download_admission_receipts", "system_backup_v2_check_results"} {
		add(table, "origin_installation_id", "system_backup_v2_operations", "origin_installation_id")
	}
	add("system_backup_v2_strong_auth_nonces", "operation_id", "system_backup_v2_operations", "id")
	for _, pair := range [][2]string{{"operation_id", "id"}, {"operation_public_id", "public_id"}, {"evidence_id", "download_evidence_id"}} {
		add("system_backup_v2_download_admission_receipts", pair[0], "system_backup_v2_operations", pair[1])
	}
	for _, column := range []string{"origin_installation_id", "operation_id", "operation_public_id", "evidence_id", "evidence_public_id", "intent_audit_id", "retain_until"} {
		add("system_backup_v2_download_result_receipts", column, "system_backup_v2_download_admission_receipts", column)
	}
	add("system_backup_v2_check_results", "cleanup_target_public_id", "system_backup_v2_operations", "public_id")
	add("system_backup_v2_check_results", "cleanup_operation_type", "system_backup_v2_operations", "operation_type")
	return out
}

// This closes the known structured reference namespace and rejects any unknown
// incoming FK, including foreign-schema references and references to nonce or
// result PKs for which no data guard exists. Exact complete schema/grants pins
// and privileged visibility/DDL freeze are ALSO required by Policy.Early.
func (s *SQLDownloadGCDirectReferences) metadata(ctx context.Context, tx *sql.Tx) (string, error) {
	maintenance := s.c.MaintenanceReceipts == "installed"
	expected := gcDirectColumns(maintenance)
	tables := map[string]bool{}
	for key := range expected {
		tables[strings.SplitN(key, ".", 2)[0]] = true
	}
	var records []string
	for _, def := range []struct {
		query string
		width int
		kind  string
	}{{downloadGCEarlyTablesSQL, 4, "tables"}, {downloadGCDirectColumnsSQL, 3, "columns"}, {downloadGCDirectForeignKeysSQL, 9, "foreign_keys"}} {
		rows, err := tx.QueryContext(ctx, def.query)
		if err != nil {
			return "", ErrDenied
		}
		seen := map[string]bool{}
		count := 0
		edges := gcDirectFKEdges(maintenance)
		for rows.Next() {
			v := make([]string, def.width)
			dest := make([]any, def.width)
			for i := range v {
				dest[i] = &v[i]
			}
			if rows.Scan(dest...) != nil || count >= 10000 {
				rows.Close()
				return "", ErrDenied
			}
			count++
			for _, field := range v {
				if len(field) > 512 {
					rows.Close()
					return "", ErrDenied
				}
			}
			key := string(canonical(v))
			if def.kind == "tables" {
				key = v[0]
			}
			if def.kind == "columns" {
				key = v[0] + "." + v[1]
			}
			if def.kind == "foreign_keys" {
				key = strings.Join(v[:4], "\x00")
			}
			if seen[key] {
				rows.Close()
				return "", ErrDenied
			}
			seen[key] = true
			switch def.kind {
			case "tables":
				if tables[v[0]] {
					if v[1] != "BASE TABLE" || v[2] != "InnoDB" {
						rows.Close()
						return "", ErrDenied
					}
					delete(tables, v[0])
				}
				if v[0] == "system_backup_v2_config_maintenance_receipts" && !maintenance {
					rows.Close()
					return "", ErrDenied
				}
			case "columns":
				key = v[0] + "." + v[1]
				if expected[key] != v[2] {
					rows.Close()
					return "", ErrDenied
				}
				delete(expected, key)
			case "foreign_keys":
				key = v[1] + "." + v[4] + ">" + v[6] + "." + v[7]
				if v[0] != s.c.Database.Database || v[5] != s.c.Database.Database || !edges[key] || !oneOf(v[8], "RESTRICT", "NO ACTION") {
					rows.Close()
					return "", ErrDenied
				}
			}
			records = append(records, def.kind+":"+string(canonical(v)))
		}
		if rows.Err() != nil || rows.Close() != nil {
			return "", ErrDenied
		}
	}
	if len(expected) != 0 || len(tables) != 0 {
		return "", ErrDenied
	}
	sort.Strings(records)
	return hash([]byte(strings.Join(records, "\n"))), nil
}

type gcDirectRange struct {
	query string
	args  []any
	stage int
}
type gcDirectReferenceState struct {
	sync.Mutex
	failed bool
	stage  int
	last   time.Time
}
type downloadGCDirectGuard struct {
	source   *SQLDownloadGCDirectReferences
	tx       *sql.Tx
	hint     DownloadGCEarlyScope
	scope    DownloadRetentionGCScope
	metadata string
	ranges   []gcDirectRange
	nonceID  int64
	state    *gcDirectReferenceState
}

func (downloadGCDirectGuard) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (downloadGCDirectGuard) String() string               { return "downloadGCDirectGuard" }
func (downloadGCDirectGuard) GoString() string             { return "downloadGCDirectGuard" }

func (s *SQLDownloadGCDirectReferences) early(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope, now time.Time) (*downloadGCDirectGuard, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil || !downloadAdmissionContentTime(now) || !validGCEarlyScope(DownloadGCEarlyReferenceConfig{Database: s.c.Database, Installation: s.c.Installation}, h) {
		return nil, ErrDenied
	}
	g := &downloadGCDirectGuard{source: s, tx: tx, hint: h, state: &gcDirectReferenceState{last: now}}
	if g.database(ctx) != nil {
		return nil, ErrDenied
	}
	pin, err := s.metadata(ctx, tx)
	if err != nil {
		return nil, err
	}
	g.metadata = pin
	if g.lock(ctx, 1) != nil {
		return nil, ErrDenied
	}
	g.state.stage = 1
	return g, nil
}

func (g *downloadGCDirectGuard) database(ctx context.Context) error {
	var server, database string
	if g.tx.QueryRowContext(ctx, downloadGCTaskDatabaseSQL).Scan(&server, &database) != nil || server != g.source.c.Database.ServerUUID || database != g.source.c.Database.Database {
		return ErrDenied
	}
	return nil
}

func (g *downloadGCDirectGuard) lock(ctx context.Context, stage int) error {
	for _, r := range gcDirectReferences(g.source.c.MaintenanceReceipts == "installed") {
		if r.stage != stage {
			continue
		}
		values := []any{g.hint.Operation}
		switch r.value {
		case "numeric":
			values = []any{g.hint.OperationID}
		case "audits":
			ids := []int64{g.hint.IntentAuditID, g.hint.ResultAuditID}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			values = []any{ids[0], ids[1]}
		case "nonce":
			if g.nonceID < 1 {
				return ErrDenied
			}
			values = []any{strconv.FormatInt(g.nonceID, 10)}
		}
		for _, value := range values {
			if strings.HasPrefix(r.column, "json:") {
				if id, ok := value.(int64); ok {
					value = strconv.FormatInt(id, 10)
				}
			}
			args := []any{value}
			if r.own {
				own := g.hint.OperationID
				if r.table == "system_backup_v2_strong_auth_nonces" {
					own = g.nonceID
				}
				if r.table == "audit_logs" {
					own = g.hint.IntentAuditID
				}
				if own < 1 {
					return ErrDenied
				}
				args = append(args, own)
				if r.table == "audit_logs" {
					args = append(args, g.hint.ResultAuditID)
				}
			}
			q := gcDirectQuery(r)
			if gcDirectEmpty(ctx, g.tx, q, args) != nil {
				return ErrDenied
			}
			g.ranges = append(g.ranges, gcDirectRange{q, args, stage})
		}
	}
	return nil
}

func gcDirectEmpty(ctx context.Context, tx *sql.Tx, q string, args []any) error {
	var key string
	if tx.QueryRowContext(ctx, q, args...).Scan(&key) != sql.ErrNoRows {
		return ErrDenied
	}
	return nil
}

func (g *downloadGCDirectGuard) bindL3(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, group *DownloadRetentionGroup) error {
	return g.advance(ctx, tx, 3, func() error {
		h := g.hint
		if s.Database != h.Database || s.Installation != h.Installation || s.WorkerOperation != h.WorkerOperation || s.PrincipalSHA256 != h.PrincipalSHA256 || s.Operation != h.Operation || s.OperationID != h.OperationID || s.ActorID != h.ActorID || s.IntentAuditID != h.IntentAuditID || s.ResultAuditID != h.ResultAuditID || group == nil || group.tx != tx || group.operationID != s.OperationID || group.receipt.IntentAuditID != s.IntentAuditID || group.result == nil || group.result.resultID != s.ResultAuditID {
			return ErrDenied
		}
		g.scope = s
		return g.lock(ctx, 3)
	})
}
func (g *downloadGCDirectGuard) lockL5(ctx context.Context, tx *sql.Tx, group *DownloadRetentionGroup) error {
	return g.advance(ctx, tx, 5, func() error {
		if group == nil || group.tx != tx || group.operationID != g.scope.OperationID || group.nonce == nil || group.nonce.id < 1 || group.nonce.operationID != g.scope.OperationID || group.nonce.auditID != g.scope.IntentAuditID {
			return ErrDenied
		}
		g.nonceID = group.nonce.id
		return g.lock(ctx, 5)
	})
}
func (g *downloadGCDirectGuard) lockL7(ctx context.Context, tx *sql.Tx) error {
	return g.advance(ctx, tx, 7, func() error { return g.lock(ctx, 7) })
}
func (g *downloadGCDirectGuard) advance(ctx context.Context, tx *sql.Tx, stage int, run func() error) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	if g.state.failed || ctx == nil || ctx.Err() != nil || tx != g.tx || stage != g.state.stage+2 {
		g.state.failed = true
		return ErrDenied
	}
	if run() != nil {
		g.state.failed = true
		return ErrDenied
	}
	g.state.stage = stage
	return nil
}
func (g *downloadGCDirectGuard) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	fail := func() error { g.state.failed = true; return ErrDenied }
	if g.state.failed || g.state.stage != 7 || ctx == nil || ctx.Err() != nil || tx != g.tx || s != g.scope || !downloadAdmissionContentTime(now) || now.Before(g.state.last) || g.database(ctx) != nil {
		return fail()
	}
	pin, err := g.source.metadata(ctx, tx)
	if err != nil || pin != g.metadata {
		return fail()
	}
	for _, r := range g.ranges {
		if gcDirectEmpty(ctx, tx, r.query, r.args) != nil {
			return fail()
		}
	}
	g.state.last = now
	return nil
}

var _ DownloadRetentionGCGuard = (*downloadGCDirectGuard)(nil)
