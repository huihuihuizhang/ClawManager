package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Synthetic direct-grant/catalog/receipt transport only. The production
// authority/fingerprint/range guard executes; no real SQL role is installed.
type gcEarlyModel struct {
	d               *retentionGCModel
	service         *SQLDownloadGCEarlyReferences
	account, role   string
	grants          []string
	catalog         map[string][][]driver.Value
	refs, savedRefs [][]driver.Value
	locked          map[string]bool
	initialLocks    []string
	accountReads    int
	nilEarly        bool
}

func (m *gcEarlyModel) begin() {
	m.savedRefs = cloneGCEarlyRows(m.refs)
	m.locked = map[string]bool{}
	m.initialLocks = nil
	m.accountReads = 0
}
func (m *gcEarlyModel) rollback() { m.refs = cloneGCEarlyRows(m.savedRefs) }
func cloneGCEarlyRows(rows [][]driver.Value) [][]driver.Value {
	var out [][]driver.Value
	for _, r := range rows {
		out = append(out, append([]driver.Value(nil), r...))
	}
	return out
}
func (m *gcEarlyModel) query(q string, a []driver.NamedValue) (driver.Rows, bool, error) {
	switch q {
	case downloadGCEarlyAccountSQL:
		m.accountReads++
		if !m.d.installationLocked || m.accountReads == 1 && m.d.opKeyLocked {
			return nil, true, errors.New("early GC authority outside L1")
		}
		return admissionTxRow(m.d.identity.ServerUUID, m.d.identity.Database, m.account, m.role), true, nil
	case downloadGCEarlyGrantsSQL:
		var values [][]driver.Value
		for _, grant := range m.grants {
			values = append(values, []driver.Value{grant})
		}
		return &admissionTxRows{width: 1, data: values}, true, nil
	case downloadGCEarlyIntentReferenceSQL, downloadGCEarlyResultReferenceSQL:
		if len(a) != 1 {
			return nil, true, errors.New("early GC audit range shape")
		}
		id, ok := a[0].Value.(int64)
		if !ok {
			return nil, true, errors.New("early GC non-integer audit")
		}
		key := q + "|" + strconv.FormatInt(id, 10)
		if !m.locked[key] {
			if m.d.opKeyLocked || m.d.ownerLocked {
				return nil, true, errors.New("new L1 range after L3")
			}
			m.locked[key] = true
			m.initialLocks = append(m.initialLocks, key)
		}
		column := 1
		if q == downloadGCEarlyResultReferenceSQL {
			column = 2
		}
		for _, row := range m.refs {
			if row[column] == id {
				return admissionTxRow(row[0]), true, nil
			}
		}
		return &admissionTxRows{width: 1}, true, nil
	}
	for _, def := range gcMetadataDefinitions() {
		if q == def.query {
			return &admissionTxRows{width: def.width, data: cloneGCEarlyRows(m.catalog[q])}, true, nil
		}
	}
	return nil, false, nil
}
func (p *retentionGCPolicy) Early(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope, _ time.Time) (DownloadRetentionGCGuard, error) {
	if p == nil || p.d == nil || p.d.early == nil {
		return nil, ErrDenied
	}
	if p.d.early.nilEarly {
		return (*DownloadGCEarlyReferenceGuard)(nil), nil
	}
	return p.d.early.service.Lock(ctx, tx, h)
}
func (m *gcEarlyModel) pins() DownloadGCMetadataPins {
	var digests []string
	for _, def := range gcMetadataDefinitions() {
		var records []string
		for _, r := range m.catalog[def.query] {
			v := make([]string, len(r))
			for k := range r {
				v[k] = fmt.Sprint(r[k])
			}
			records = append(records, string(canonical(v)))
		}
		digests = append(digests, gcMetadataDigest(def.domain, records))
	}
	return DownloadGCMetadataPins{digests[0], digests[1], digests[2], digests[3]}
}
func (m *gcEarlyModel) grantsPin() string {
	v := append([]string(nil), m.grants...)
	sort.Strings(v)
	return hash(canonical(v))
}
func newGCEarlyModel(t *testing.T, d *retentionGCModel, maintenance bool) *gcEarlyModel {
	t.Helper()
	m := &gcEarlyModel{d: d, account: "download_gc@localhost", role: "NONE", catalog: map[string][][]driver.Value{}}
	database := d.identity.Database
	target := func(table string) string { return "`" + database + "`.`" + table + "` TO 'download_gc'@'localhost'" }
	m.grants = []string{"GRANT REFERENCES ON *.* TO 'download_gc'@'localhost'", "GRANT LOCK TABLES ON `" + database + "`.* TO 'download_gc'@'localhost'", "GRANT SELECT (`id`) ON " + target("users")}
	tables := append(gcRequiredReadTables(maintenance), "users")
	known := map[string]bool{}
	for _, table := range tables {
		known[table] = true
	}
	for key := range gcDirectColumns(maintenance) {
		table := strings.SplitN(key, ".", 2)[0]
		if !known[table] {
			tables = append(tables, table)
			known[table] = true
		}
	}
	sort.Strings(tables)
	for _, table := range tables {
		m.catalog[downloadGCEarlyTablesSQL] = append(m.catalog[downloadGCEarlyTablesSQL], []driver.Value{table, "BASE TABLE", "InnoDB", "utf8mb4_unicode_ci"})
		m.catalog[downloadGCEarlyColumnsSQL] = append(m.catalog[downloadGCEarlyColumnsSQL], []driver.Value{table, "id", "1", "bigint unsigned", "NO", "null", "", "", "", "", ""})
		m.catalog[downloadGCEarlyIndexesSQL] = append(m.catalog[downloadGCEarlyIndexesSQL], []driver.Value{table, "PRIMARY", "1", "0", "id", "A", "", "BTREE", "YES", ""})
		if table == "users" {
			continue
		}
		privileges := "SELECT"
		if gcDeleteTables[table] {
			privileges += ", DELETE"
		}
		if table == "system_backup_v2_metadata_reservations" {
			privileges += ", UPDATE"
		}
		if table == "system_backup_v2_compact_tombstones" {
			privileges += ", INSERT"
		}
		m.grants = append(m.grants, "GRANT "+privileges+" ON "+target(table))
	}
	var columns []string
	for key := range gcDirectColumns(maintenance) {
		columns = append(columns, key)
	}
	sort.Strings(columns)
	for n, key := range columns {
		parts := strings.SplitN(key, ".", 2)
		m.catalog[downloadGCEarlyColumnsSQL] = append(m.catalog[downloadGCEarlyColumnsSQL], []driver.Value{parts[0], parts[1], strconv.Itoa(n + 2), gcDirectColumns(maintenance)[key], "YES", "null", "", "", "", "", ""})
	}
	m.catalog[downloadGCEarlyForeignKeysSQL] = [][]driver.Value{{database, "system_backup_v2_download_admission_receipts", "admission_operation", "1", "operation_id", database, "system_backup_v2_operations", "id", "RESTRICT", "RESTRICT"}}
	state := "absent"
	if maintenance {
		state = "installed"
	}
	c := DownloadGCEarlyReferenceConfig{Database: d.identity, Installation: d.record.Manifest.Identity.Installation, Account: m.account, GrantsSHA256: m.grantsPin(), Metadata: m.pins(), MaintenanceReceipts: state}
	var err error
	m.service, err = NewSQLDownloadGCEarlyReferences(c)
	if err != nil {
		t.Fatal("early reference guard", err)
	}
	return m
}

func TestDownloadRetentionGCEarlyReferencesAreL1AndRechecked(t *testing.T) {
	for _, maintenance := range []bool{true, false} {
		t.Run(strconv.FormatBool(maintenance), func(t *testing.T) {
			f := newRetentionGCFixture(t)
			f.d.early = newGCEarlyModel(t, f.d, maintenance)
			f.s.c.References.c.MaintenanceReceipts = f.d.early.service.c.MaintenanceReceipts
			if err := f.s.Collect(f.ctx, f.operation); err != nil {
				t.Fatal(err, f.d.queries)
			}
			if f.d.commits != f.commits+1 || f.d.early.accountReads != 4 {
				t.Fatal("early checks omitted", f.d.early.accountReads)
			}
			if !maintenance {
				if len(f.d.early.initialLocks) != 0 {
					t.Fatal("absent receipt table queried")
				}
				return
			}
			want := []string{downloadGCEarlyIntentReferenceSQL + "|1729", downloadGCEarlyIntentReferenceSQL + "|1730", downloadGCEarlyResultReferenceSQL + "|1729", downloadGCEarlyResultReferenceSQL + "|1730"}
			if !reflect.DeepEqual(f.d.early.initialLocks, want) {
				t.Fatal("early lock order", f.d.early.initialLocks)
			}
			at := func(q string) int {
				for n, v := range f.d.queries {
					if v == q {
						return n
					}
				}
				return -1
			}
			if at(downloadGCEarlyIntentReferenceSQL) < 0 || at(downloadGCEarlyResultReferenceSQL) >= at(downloadResultActorSQL) || at(downloadResultActorSQL) >= at(downloadGCWorkerSQL) {
				t.Fatal("L1/L2/L3 order", f.d.queries)
			}
		})
	}
}

func TestDownloadRetentionGCEarlyReferenceAndGrantDenials(t *testing.T) {
	modes := []string{"intent_to_intent", "intent_to_result", "result_to_intent", "result_to_result", "account", "role", "missing_global_metadata", "missing_delete", "extra_update_audit", "extra_insert_operation", "extra_delete_marker", "extra_user_select", "grant_option", "role_grant", "other_database", "duplicate_grant", "missing_metadata_table", "column_drift", "index_drift", "fk_drift", "pinned_cascade", "pinned_cross_schema", "oversized_cell", "metadata_query", "reference_query", "hint_operation", "hint_intent", "hint_result", "hint_null", "hint_same_audit", "nil_early"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			m := f.d.early
			before := f.d.reserved
			addGrant := func(priv, table string) {
				m.grants = append(m.grants, "GRANT "+priv+" ON `"+m.d.identity.Database+"`.`"+table+"` TO 'download_gc'@'localhost'")
				m.service.c.GrantsSHA256 = m.grantsPin()
			}
			switch mode {
			case "intent_to_intent":
				m.refs = [][]driver.Value{{int64(1), int64(1729), int64(9000)}}
			case "intent_to_result":
				m.refs = [][]driver.Value{{int64(1), int64(1730), int64(9000)}}
			case "result_to_intent":
				m.refs = [][]driver.Value{{int64(1), int64(9000), int64(1729)}}
			case "result_to_result":
				m.refs = [][]driver.Value{{int64(1), int64(9000), int64(1730)}}
			case "account":
				m.account = "other@localhost"
			case "role":
				m.role = "`other`@`localhost`"
			case "missing_global_metadata":
				m.grants = m.grants[1:]
			case "missing_delete":
				for n, g := range m.grants {
					m.grants[n] = strings.ReplaceAll(g, ", DELETE", "")
				}
			case "extra_update_audit":
				addGrant("UPDATE", "audit_logs")
			case "extra_insert_operation":
				addGrant("INSERT", "system_backup_v2_operations")
			case "extra_delete_marker":
				addGrant("DELETE", "system_backup_v2_compact_tombstones")
			case "extra_user_select":
				addGrant("SELECT", "users")
			case "grant_option":
				m.grants[0] += " WITH GRANT OPTION"
				m.service.c.GrantsSHA256 = m.grantsPin()
			case "role_grant":
				m.grants = append(m.grants, "GRANT 'gc_role'@'localhost' TO 'download_gc'@'localhost'")
				m.service.c.GrantsSHA256 = m.grantsPin()
			case "other_database":
				m.grants = append(m.grants, "GRANT SELECT ON `other`.`system_backup_v2_backups` TO 'download_gc'@'localhost'")
				m.service.c.GrantsSHA256 = m.grantsPin()
			case "duplicate_grant":
				m.grants = append(m.grants, m.grants[0])
				m.service.c.GrantsSHA256 = m.grantsPin()
			case "missing_metadata_table":
				m.catalog[downloadGCEarlyTablesSQL] = m.catalog[downloadGCEarlyTablesSQL][1:]
			case "column_drift":
				m.catalog[downloadGCEarlyColumnsSQL][0][3] = "varchar(128)"
			case "index_drift":
				m.catalog[downloadGCEarlyIndexesSQL][0][8] = "NO"
			case "fk_drift":
				m.catalog[downloadGCEarlyForeignKeysSQL][0][9] = "NO ACTION"
			case "pinned_cascade":
				m.catalog[downloadGCEarlyForeignKeysSQL][0][9] = "CASCADE"
				m.service.c.Metadata = m.pins()
			case "pinned_cross_schema":
				m.catalog[downloadGCEarlyForeignKeysSQL][0][0] = "foreign_db"
				m.service.c.Metadata = m.pins()
			case "oversized_cell":
				m.catalog[downloadGCEarlyColumnsSQL][0][6] = strings.Repeat("x", 16385)
			case "metadata_query":
				f.d.fail = "query:" + downloadGCEarlyColumnsSQL
			case "reference_query":
				f.d.fail = "query:" + downloadGCEarlyIntentReferenceSQL
			case "nil_early":
				m.nilEarly = true
			default:
				f.d.mutateRead = func(q string, v []driver.Value) []driver.Value {
					if q != downloadGCActorHintSQL {
						return v
					}
					switch mode {
					case "hint_operation":
						v[0] = int64(74)
					case "hint_intent":
						v[3] = int64(9001)
					case "hint_result":
						v[4] = int64(9002)
					case "hint_null":
						v[4] = nil
					case "hint_same_audit":
						v[4] = v[3]
					}
					return v
				}
			}
			if err := f.s.Collect(f.ctx, f.operation); err == nil {
				t.Fatal("unsafe early guard admitted")
			}
			if f.d.commits != f.commits || f.d.reserved != before || len(f.d.stone) != 0 || len(f.d.m.op) != 14 || len(f.d.m.receipt) != 16 || len(f.d.resultRetention) != 11 || len(f.d.body) == 0 || len(f.d.resultBody) == 0 {
				t.Fatal("early failure changed group or capacity")
			}
		})
	}
}

func TestDownloadRetentionGCEarlyLateChangesRollBack(t *testing.T) {
	for _, mode := range []string{"reference_after_marker", "reference_in_final_guard", "grant_revoked", "role_changed", "metadata_changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			m := f.d.early
			before := f.d.reserved
			f.d.afterWrite = func(q string) {
				if mode == "reference_after_marker" && q == downloadGCTombstoneInsertSQL {
					m.refs = append(m.refs, []driver.Value{int64(5), int64(1729), int64(9000)})
				}
			}
			f.policy.onCheck = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "reference_in_final_guard":
					m.refs = append(m.refs, []driver.Value{int64(6), int64(9000), int64(1730)})
				case "grant_revoked":
					m.grants = m.grants[1:]
				case "role_changed":
					m.role = "`new_role`@`localhost`"
				case "metadata_changed":
					m.catalog[downloadGCEarlyIndexesSQL][0][8] = "NO"
				}
			}
			if err := f.s.Collect(f.ctx, f.operation); err == nil {
				t.Fatal("late early-reference change committed")
			}
			if f.d.commits != f.commits || f.d.reserved != before || len(f.d.stone) != 0 || len(f.d.m.op) != 14 || len(f.d.m.receipt) != 16 || len(m.refs) != 0 {
				t.Fatal("late write escaped rollback")
			}
		})
	}
}

func TestDownloadRetentionGCEarlyGuardCannotReviveOrRebind(t *testing.T) {
	for _, mode := range []string{"scope", "transaction", "context"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			tx, _, err := f.s.c.Registry.begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			ns, err := sec.LockSensitiveDownloadNonceScope(f.ctx, tx, f.d.identity, f.d.record.Manifest.Identity.Installation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ns.LoadConfig(f.ctx, tx); err != nil {
				t.Fatal(err)
			}
			h := DownloadGCEarlyScope{Database: f.d.identity, Installation: f.d.record.Manifest.Identity.Installation, WorkerOperation: f.s.c.OperationID, PrincipalSHA256: f.s.principal, Operation: f.operation, OperationID: 73, ActorID: 42, IntentAuditID: 1729, ResultAuditID: 1730}
			g, err := f.d.early.service.Lock(f.ctx, tx, h)
			if err != nil {
				t.Fatal(err)
			}
			copy := *g
			s := DownloadRetentionGCScope{Database: h.Database, Installation: h.Installation, WorkerOperation: h.WorkerOperation, PrincipalSHA256: h.PrincipalSHA256, Operation: h.Operation, OperationID: h.OperationID, ActorID: h.ActorID, IntentAuditID: h.IntentAuditID, ResultAuditID: h.ResultAuditID}
			wrong := s
			badTx := tx
			ctx := f.ctx
			switch mode {
			case "scope":
				wrong.OperationID++
			case "transaction":
				badTx = nil
			case "context":
				ctx = nil
			}
			if g.Recheck(ctx, badTx, wrong, f.d.now) == nil || copy.Recheck(f.ctx, tx, s, f.d.now) == nil {
				t.Fatal("failed/copied early guard revived")
			}
		})
	}
}

func TestDownloadRetentionGCEarlyConfigurationIsExplicit(t *testing.T) {
	f := newRetentionGCFixture(t)
	for _, mode := range []string{"root", "empty_state", "unknown_state", "empty_pin", "wrong_database", "empty_account"} {
		t.Run(mode, func(t *testing.T) {
			c := f.d.early.service.c
			switch mode {
			case "root":
				c.Account = "root@localhost"
			case "empty_state":
				c.MaintenanceReceipts = ""
			case "unknown_state":
				c.MaintenanceReceipts = "auto"
			case "empty_pin":
				c.Metadata.ForeignKeys = ""
			case "wrong_database":
				c.Database.Database = "db.name"
			case "empty_account":
				c.Account = ""
			}
			if _, err := NewSQLDownloadGCEarlyReferences(c); err == nil {
				t.Fatal("implicit/invalid configuration accepted")
			}
		})
	}
}
