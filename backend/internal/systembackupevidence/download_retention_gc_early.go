package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sec "clawreef/internal/systembackupsecurity"
)

// Hints select early lock ranges only. Collect must compare every field with
// the independently locked original group before any capacity or deletion.
type DownloadGCEarlyScope struct {
	Database                                                  sec.DatabaseIdentity
	Installation, WorkerOperation, PrincipalSHA256, Operation string
	OperationID, ActorID, IntentAuditID, ResultAuditID        int64
}

func (DownloadGCEarlyScope) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// This component covers current direct SQL grants, a reviewed structural
// fingerprint and L1 maintenance-receipt incoming audit links. It does NOT
// replace owner/artifact/ref/hold eligibility or a privileged review/DDL freeze
// of triggers and stored programs. No GRANT, DDL, commit or provider call occurs.
type DownloadGCEarlyReferenceConfig struct {
	Database                            sec.DatabaseIdentity
	Installation, Account, GrantsSHA256 string
	Metadata                            DownloadGCMetadataPins
	// Explicit reviewed state: an omitted value must not silently mean absent.
	MaintenanceReceipts string
}
type DownloadGCMetadataPins struct{ Tables, Columns, ForeignKeys, Indexes string }
type SQLDownloadGCEarlyReferences struct {
	c DownloadGCEarlyReferenceConfig
}

func (DownloadGCEarlyReferenceConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadGCEarlyReferenceConfig) GoString() string             { return "DownloadGCEarlyReferenceConfig" }
func (DownloadGCEarlyReferenceConfig) String() string               { return "DownloadGCEarlyReferenceConfig" }

var gcSQLName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var gcSQLAccount = regexp.MustCompile(`^([A-Za-z0-9_]{1,32})@([A-Za-z0-9_.:%-]{1,255})$`)
var gcSQLTable = regexp.MustCompile("^`([A-Za-z0-9_]+)`\\.`([A-Za-z0-9_]+)`$")

const downloadGCEarlyAccountSQL = `SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE()`
const downloadGCEarlyGrantsSQL = `SHOW GRANTS`
const downloadGCEarlyTablesSQL = `SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,''),COALESCE(TABLE_COLLATION,'') FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME LIMIT 10001`
const downloadGCEarlyColumnsSQL = `SELECT TABLE_NAME,COLUMN_NAME,CAST(ORDINAL_POSITION AS CHAR),COLUMN_TYPE,IS_NULLABLE,IF(COLUMN_DEFAULT IS NULL,'null','value'),COALESCE(COLUMN_DEFAULT,''),COALESCE(CHARACTER_SET_NAME,''),COALESCE(COLLATION_NAME,''),EXTRA,COALESCE(GENERATION_EXPRESSION,'') FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME,ORDINAL_POSITION LIMIT 10001`

// Include incoming cross-schema FKs. Schema-local metadata visibility alone
// must not make a foreign-schema CASCADE invisible to a deleting worker.
const downloadGCEarlyForeignKeysSQL = `SELECT k.TABLE_SCHEMA,k.TABLE_NAME,k.CONSTRAINT_NAME,CAST(k.ORDINAL_POSITION AS CHAR),k.COLUMN_NAME,k.REFERENCED_TABLE_SCHEMA,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.REFERENCED_TABLE_NAME IS NOT NULL AND (k.TABLE_SCHEMA=DATABASE() OR k.REFERENCED_TABLE_SCHEMA=DATABASE()) ORDER BY BINARY k.TABLE_SCHEMA,BINARY k.TABLE_NAME,BINARY k.CONSTRAINT_NAME,k.ORDINAL_POSITION LIMIT 10001`
const downloadGCEarlyIndexesSQL = `SELECT TABLE_NAME,INDEX_NAME,CAST(SEQ_IN_INDEX AS CHAR),CAST(NON_UNIQUE AS CHAR),COALESCE(COLUMN_NAME,''),COALESCE(COLLATION,''),COALESCE(CAST(SUB_PART AS CHAR),''),INDEX_TYPE,IS_VISIBLE,COALESCE(EXPRESSION,'') FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=DATABASE() ORDER BY BINARY TABLE_NAME,BINARY INDEX_NAME,SEQ_IN_INDEX LIMIT 10001`
const downloadGCEarlyIntentReferenceSQL = `SELECT id FROM system_backup_v2_config_maintenance_receipts WHERE intent_audit_id=? LIMIT 1 FOR UPDATE`
const downloadGCEarlyResultReferenceSQL = `SELECT id FROM system_backup_v2_config_maintenance_receipts WHERE result_audit_id=? LIMIT 1 FOR UPDATE`

type gcMetadataDefinition struct {
	query, domain string
	width         int
}

func gcMetadataDefinitions() []gcMetadataDefinition {
	return []gcMetadataDefinition{
		{downloadGCEarlyTablesSQL, "tables", 4}, {downloadGCEarlyColumnsSQL, "columns", 11},
		{downloadGCEarlyForeignKeysSQL, "foreign_keys", 10}, {downloadGCEarlyIndexesSQL, "indexes", 10},
	}
}

func gcMetadataDigest(domain string, records []string) string {
	sort.Strings(records)
	return hash([]byte("clawmanager.download-gc.metadata.v1/" + domain + "\n" + strings.Join(records, "\n") + "\n"))
}

func NewSQLDownloadGCEarlyReferences(c DownloadGCEarlyReferenceConfig) (*SQLDownloadGCEarlyReferences, error) {
	account := gcSQLAccount.FindStringSubmatch(c.Account)
	if c.Database.ServerUUID == "" || !gcSQLName.MatchString(c.Database.Database) || !installationPattern.MatchString(c.Installation) ||
		len(account) != 3 || strings.EqualFold(account[1], "root") || !digestPattern.MatchString(c.GrantsSHA256) ||
		!oneOf(c.MaintenanceReceipts, "absent", "installed") {
		return nil, ErrDenied
	}
	for _, pin := range []string{c.Metadata.Tables, c.Metadata.Columns, c.Metadata.ForeignKeys, c.Metadata.Indexes} {
		if !digestPattern.MatchString(pin) {
			return nil, ErrDenied
		}
	}
	return &SQLDownloadGCEarlyReferences{c: c}, nil
}

var gcDeleteTables = map[string]bool{
	"audit_logs": true, "system_backup_v2_operations": true, "system_backup_v2_strong_auth_nonces": true,
	"system_backup_v2_download_admission_receipts": true, "system_backup_v2_download_result_receipts": true,
}

func gcRequiredReadTables(maintenance bool) []string {
	tables := []string{"audit_logs", "system_backup_v2_installation_state", "system_backup_v2_configs", "system_backup_v2_operations", "system_backup_v2_strong_auth_nonces", "system_backup_v2_download_admission_receipts", "system_backup_v2_download_result_receipts", "system_backup_v2_metadata_reservations", "system_backup_v2_compact_tombstones"}
	if maintenance {
		tables = append(tables, "system_backup_v2_config_maintenance_receipts")
	}
	return tables
}

// A pinned statement set is still subject to the safety shape. SELECT(id) on
// users is sufficient; no user-data SELECT, owner UPDATE, audit INSERT/UPDATE,
// provider credential, DDL, role, proxy or GRANT OPTION authority is accepted.
// Global REFERENCES is a candidate metadata-visibility prerequisite for cross-
// database incoming FKs, not permission to create one (CREATE/ALTER are denied).
// It needs its own role review and restricted MySQL proof before deployment.
func (s *SQLDownloadGCEarlyReferences) grants(statements []string) error {
	if len(statements) < 1 || len(statements) > 256 {
		return ErrDenied
	}
	account := gcSQLAccount.FindStringSubmatch(s.c.Account)
	recipients := []string{"'" + account[1] + "'@'" + account[2] + "'", "`" + account[1] + "`@`" + account[2] + "`"}
	seen, privileges := map[string]bool{}, map[string]map[string]bool{}
	usage := false
	for _, statement := range statements {
		if len(statement) > 2048 || seen[statement] || !strings.HasPrefix(statement, "GRANT ") {
			return ErrDenied
		}
		seen[statement] = true
		to := strings.LastIndex(statement, " TO ")
		if to < 0 || !oneOf(statement[to+4:], recipients...) {
			return ErrDenied
		}
		body := strings.TrimPrefix(statement[:to], "GRANT ")
		parts := strings.Split(body, " ON ")
		if len(parts) != 2 {
			return ErrDenied
		}
		object := parts[1]
		fields := strings.Split(parts[0], ",")
		if object == "*.*" && parts[0] == "USAGE" {
			if usage {
				return ErrDenied
			}
			usage = true
			continue
		}
		for _, raw := range fields {
			privilege := strings.TrimSpace(raw)
			if privileges[object] == nil {
				privileges[object] = map[string]bool{}
			}
			if privileges[object][privilege] {
				return ErrDenied
			}
			privileges[object][privilege] = true
			switch object {
			case "*.*":
				if privilege != "REFERENCES" {
					return ErrDenied
				}
			case "`" + s.c.Database.Database + "`.*":
				if privilege != "LOCK TABLES" {
					return ErrDenied
				}
			default:
				match := gcSQLTable.FindStringSubmatch(object)
				if len(match) != 3 || match[1] != s.c.Database.Database {
					return ErrDenied
				}
				table := match[2]
				if table == "users" {
					if privilege != "SELECT (`id`)" {
						return ErrDenied
					}
					continue
				}
				if table == "system_backup_v2_config_maintenance_receipts" && s.c.MaintenanceReceipts != "installed" {
					return ErrDenied
				}
				if table != "audit_logs" && !strings.HasPrefix(table, "system_") {
					return ErrDenied
				}
				allowed := privilege == "SELECT" || privilege == "DELETE" && gcDeleteTables[table] || privilege == "INSERT" && table == "system_backup_v2_compact_tombstones" || privilege == "UPDATE" && table == "system_backup_v2_metadata_reservations"
				if !allowed {
					return ErrDenied
				}
			}
		}
	}
	object := func(t string) string { return "`" + s.c.Database.Database + "`.`" + t + "`" }
	if !privileges["*.*"]["REFERENCES"] || !privileges["`"+s.c.Database.Database+"`.*"]["LOCK TABLES"] || !privileges[object("users")]["SELECT (`id`)"] {
		return ErrDenied
	}
	for _, table := range gcRequiredReadTables(s.c.MaintenanceReceipts == "installed") {
		if !privileges[object(table)]["SELECT"] {
			return ErrDenied
		}
	}
	for table := range gcDeleteTables {
		if !privileges[object(table)]["DELETE"] {
			return ErrDenied
		}
	}
	if !privileges[object("system_backup_v2_compact_tombstones")]["INSERT"] || !privileges[object("system_backup_v2_metadata_reservations")]["UPDATE"] {
		return ErrDenied
	}
	return nil
}

func (s *SQLDownloadGCEarlyReferences) authority(ctx context.Context, tx *sql.Tx) error {
	var server, database, account, role string
	if tx.QueryRowContext(ctx, downloadGCEarlyAccountSQL).Scan(&server, &database, &account, &role) != nil || server != s.c.Database.ServerUUID || database != s.c.Database.Database || account != s.c.Account || role != "NONE" {
		return ErrDenied
	}
	rows, err := tx.QueryContext(ctx, downloadGCEarlyGrantsSQL)
	if err != nil {
		return ErrDenied
	}
	var statements []string
	for rows.Next() {
		var statement string
		if rows.Scan(&statement) != nil || len(statements) >= 256 {
			rows.Close()
			return ErrDenied
		}
		statements = append(statements, statement)
	}
	read, closed := rows.Err(), rows.Close()
	if read != nil || closed != nil || s.grants(statements) != nil {
		return ErrDenied
	}
	sort.Strings(statements)
	if hash(canonical(statements)) != s.c.GrantsSHA256 {
		return ErrDenied
	}
	return nil
}

func (s *SQLDownloadGCEarlyReferences) metadata(ctx context.Context, tx *sql.Tx) error {
	pins := []string{s.c.Metadata.Tables, s.c.Metadata.Columns, s.c.Metadata.ForeignKeys, s.c.Metadata.Indexes}
	bytesRead := 0
	for n, definition := range gcMetadataDefinitions() {
		rows, err := tx.QueryContext(ctx, definition.query)
		if err != nil {
			return ErrDenied
		}
		var records []string
		tables := map[string]bool{}
		for rows.Next() {
			values := make([]string, definition.width)
			args := make([]any, len(values))
			for k := range args {
				args[k] = &values[k]
			}
			if rows.Scan(args...) != nil || len(records) >= 10000 {
				rows.Close()
				return ErrDenied
			}
			for _, value := range values {
				bytesRead += len(value)
				if len(value) > 16384 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || bytesRead > 16777216 {
					rows.Close()
					return ErrDenied
				}
			}
			if n == 0 {
				if tables[values[0]] {
					rows.Close()
					return ErrDenied
				}
				tables[values[0]] = values[1] == "BASE TABLE" && values[2] == "InnoDB"
			}
			if n == 2 && values[5] == s.c.Database.Database && gcDeleteTables[values[6]] && (values[0] != s.c.Database.Database || !oneOf(values[9], "RESTRICT", "NO ACTION")) {
				rows.Close()
				return ErrDenied
			}
			records = append(records, string(canonical(values)))
		}
		read, closed := rows.Err(), rows.Close()
		if read != nil || closed != nil || gcMetadataDigest(definition.domain, records) != pins[n] {
			return ErrDenied
		}
		if n == 0 {
			for _, table := range append(gcRequiredReadTables(s.c.MaintenanceReceipts == "installed"), "users") {
				if !tables[table] {
					return ErrDenied
				}
			}
			_, present := tables["system_backup_v2_config_maintenance_receipts"]
			if present != (s.c.MaintenanceReceipts == "installed") {
				return ErrDenied
			}
		}
	}
	return nil
}

func validGCEarlyScope(c DownloadGCEarlyReferenceConfig, h DownloadGCEarlyScope) bool {
	return h.Database == c.Database && h.Installation == c.Installation && digestPattern.MatchString(h.PrincipalSHA256) &&
		downloadAdmissionOperationID.MatchString(h.Operation) && downloadAdmissionOperationID.MatchString(h.WorkerOperation) && h.Operation != h.WorkerOperation &&
		h.OperationID > 0 && h.OperationID <= 9007199254740991 && h.ActorID > 0 && h.ActorID <= 2147483647 &&
		h.IntentAuditID > 0 && h.IntentAuditID <= 2147483647 && h.ResultAuditID > 0 && h.ResultAuditID <= 2147483647 && h.IntentAuditID != h.ResultAuditID
}

type downloadGCEarlyReferenceState struct {
	sync.Mutex
	failed bool
}
type DownloadGCEarlyReferenceGuard struct {
	source *SQLDownloadGCEarlyReferences
	tx     *sql.Tx
	hint   DownloadGCEarlyScope
	state  *downloadGCEarlyReferenceState
}

func (DownloadGCEarlyReferenceGuard) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadGCEarlyReferenceGuard) String() string               { return "DownloadGCEarlyReferenceGuard" }
func (DownloadGCEarlyReferenceGuard) GoString() string             { return "DownloadGCEarlyReferenceGuard" }

func (s *SQLDownloadGCEarlyReferences) Lock(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope) (*DownloadGCEarlyReferenceGuard, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil || !validGCEarlyScope(s.c, h) || s.authority(ctx, tx) != nil || s.metadata(ctx, tx) != nil {
		return nil, ErrDenied
	}
	g := &DownloadGCEarlyReferenceGuard{source: s, tx: tx, hint: h, state: &downloadGCEarlyReferenceState{}}
	if g.references(ctx, tx) != nil {
		return nil, ErrDenied
	}
	return g, nil
}
func (g *DownloadGCEarlyReferenceGuard) references(ctx context.Context, tx *sql.Tx) error {
	if g.source.c.MaintenanceReceipts == "absent" {
		return nil
	}
	ids := []int64{g.hint.IntentAuditID, g.hint.ResultAuditID}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, query := range []string{downloadGCEarlyIntentReferenceSQL, downloadGCEarlyResultReferenceSQL} {
		for _, id := range ids {
			var row int64
			if err := tx.QueryRowContext(ctx, query, id).Scan(&row); !errors.Is(err, sql.ErrNoRows) {
				return ErrDenied
			}
		}
	}
	return nil
}
func (g *DownloadGCEarlyReferenceGuard) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, _ time.Time) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	fail := func() error { g.state.failed = true; return ErrDenied }
	if g.state.failed || g.source == nil || ctx == nil || ctx.Err() != nil || tx != g.tx ||
		s.Database != g.hint.Database || s.Installation != g.hint.Installation || s.WorkerOperation != g.hint.WorkerOperation || s.PrincipalSHA256 != g.hint.PrincipalSHA256 ||
		s.Operation != g.hint.Operation || s.OperationID != g.hint.OperationID || s.ActorID != g.hint.ActorID || s.IntentAuditID != g.hint.IntentAuditID || s.ResultAuditID != g.hint.ResultAuditID {
		return fail()
	}
	// Repeat the SAME four already-held L1 ranges as current locking reads; do
	// not replace them with an older RR consistent-read snapshot after L7/L9.
	if g.source.authority(ctx, tx) != nil || g.source.metadata(ctx, tx) != nil || g.references(ctx, tx) != nil {
		return fail()
	}
	return nil
}

var _ DownloadRetentionGCGuard = (*DownloadGCEarlyReferenceGuard)(nil)
