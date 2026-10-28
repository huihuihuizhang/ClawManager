package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// SQL is a scripted transport. These tests exercise the concrete task guard,
// including inside the real collector, not InnoDB concurrency or real grants.
type gcTaskEligibilityModel struct {
	database                            sec.DatabaseIdentity
	installation, kind, ownerID, backup string
	tasks                               map[string][]driver.Value
	catalog                             [][]driver.Value
	savedCatalog                        [][]driver.Value
	ranges                              map[string][][]driver.Value
	savedTasks                          map[string][]driver.Value
	savedRanges                         map[string][][]driver.Value
	queries, locks                      []string
	locked                              map[string]bool
	rechecking                          bool
	failQuery                           string
	hint                                []driver.Value
	afterHint                           func()
	service                             *SQLDownloadGCTaskEligibility
}

func gcTaskRangeKey(q string, args ...any) string { return q + "|" + string(canonical(args)) }
func (m *gcTaskEligibilityModel) begin() {
	m.savedTasks = map[string][]driver.Value{}
	m.savedCatalog = cloneGCEarlyRows(m.catalog)
	for k, row := range m.tasks {
		m.savedTasks[k] = append([]driver.Value(nil), row...)
	}
	m.savedRanges = map[string][][]driver.Value{}
	for k, rows := range m.ranges {
		m.savedRanges[k] = cloneGCEarlyRows(rows)
	}
	m.locked = map[string]bool{}
	m.locks = nil
	m.rechecking = false
}
func (m *gcTaskEligibilityModel) rollback() {
	m.tasks, m.ranges = m.savedTasks, m.savedRanges
	m.catalog = m.savedCatalog
}
func (m *gcTaskEligibilityModel) query(q string, a []driver.NamedValue) (driver.Rows, bool, error) {
	var width int
	var rows [][]driver.Value
	args := make([]any, len(a))
	for n, arg := range a {
		args[n] = arg.Value
	}
	switch q {
	case downloadGCTaskDatabaseSQL:
		width, rows = 2, [][]driver.Value{{m.database.ServerUUID, m.database.Database}}
	case downloadGCTaskTablesSQL:
		width, rows = 3, m.catalog
	case downloadGCTaskStagingSQL, downloadGCTaskRestoreSQL:
		width, rows = 8, m.ranges[gcTaskRangeKey(q, args...)]
	case downloadGCTaskLeaseStateSQL:
		width, rows = 5, m.ranges[gcTaskRangeKey(q, args...)]
	case downloadGCTaskSourceLeaseSQL, downloadGCTaskHolderLeaseSQL:
		width, rows = 15, m.ranges[gcTaskRangeKey(q, args...)]
	case downloadGCTaskBackupPromotionSQL, downloadGCTaskDrillPromotionSQL, downloadGCTaskPruneDependencySQL:
		width, rows = 1, m.ranges[gcTaskRangeKey(q, args...)]
	default:
		for _, kind := range []string{"backup", "drill", "preflight", "artifact_verify"} {
			if kind != "backup" && q == downloadGCTaskDependentSQL(kind) {
				width = 25
				if len(args) != 1 {
					return nil, true, errors.New("dependent arguments")
				}
				rows = cloneGCEarlyRows(m.ranges[gcTaskRangeKey(q, args...)])
				for _, row := range m.tasks {
					if row[3] == kind && row[14] == args[0] {
						rows = append(rows, append([]driver.Value(nil), row...))
					}
				}
				sort.Slice(rows, func(i, j int) bool { a, _ := rows[i][0].(int64); b, _ := rows[j][0].(int64); return a < b })
			}
			if q == downloadGCTaskRetrySQL(kind) {
				width, rows = 1, m.ranges[gcTaskRangeKey(q, args...)]
			}
			if q == downloadGCTaskSQL(kind, false) && len(args) == 1 {
				width = 25
				if row := m.tasks[fmt.Sprint(args[0])]; row != nil {
					rows = [][]driver.Value{row}
				}
			}
			if kind != "backup" && q == downloadGCTaskSQL(kind, true) && len(args) == 1 {
				width = 2
				if row := m.tasks[fmt.Sprint(args[0])]; row != nil {
					rows = [][]driver.Value{{row[13], row[14]}}
				}
				if m.hint != nil {
					rows = [][]driver.Value{m.hint}
				}
				if m.afterHint != nil {
					m.afterHint()
				}
			}
		}
	}
	if width == 0 {
		return nil, false, nil
	}
	if strings.Count(q, "?") != len(a) {
		return nil, true, errors.New("task guard placeholder mismatch")
	}
	m.queries = append(m.queries, q)
	if q == m.failQuery {
		return nil, true, errors.New("PRIVATE task guard transport failure")
	}
	if strings.HasSuffix(q, " FOR UPDATE") {
		key := gcTaskRangeKey(q, args...)
		if !m.locked[key] {
			if m.rechecking {
				return nil, true, errors.New("new task range after later phases")
			}
			m.locked[key] = true
			m.locks = append(m.locks, key)
		}
	}
	return &admissionTxRows{width: width, data: cloneGCEarlyRows(rows)}, true, nil
}

type gcTaskConnector struct{ m *gcTaskEligibilityModel }
type gcTaskConn struct{ m *gcTaskEligibilityModel }
type gcTaskDriver struct{}

func (gcTaskDriver) Open(string) (driver.Conn, error)                  { return nil, errors.New("connector required") }
func (c gcTaskConnector) Driver() driver.Driver                        { return gcTaskDriver{} }
func (c gcTaskConnector) Connect(context.Context) (driver.Conn, error) { return &gcTaskConn{c.m}, nil }
func (*gcTaskConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("no prepared statement")
}
func (*gcTaskConn) Close() error { return nil }
func (*gcTaskConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction required")
}
func (c *gcTaskConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || opts.ReadOnly {
		return nil, ErrDenied
	}
	c.m.begin()
	return c, nil
}
func (c *gcTaskConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	r, ok, err := c.m.query(q, a)
	if !ok {
		return nil, errors.New("unknown task query: " + q)
	}
	return r, err
}
func (*gcTaskConn) Commit() error     { return errors.New("guard must not commit") }
func (c *gcTaskConn) Rollback() error { c.m.rollback(); return nil }

func newGCTaskEligibilityModel(t *testing.T, database sec.DatabaseIdentity, installation, kind, owner string, now time.Time) *gcTaskEligibilityModel {
	t.Helper()
	backup := "sbk_22222222-2222-4222-8222-222222222222"
	if kind == "backup" {
		backup = owner
	}
	s, err := NewSQLDownloadGCTaskEligibility(DownloadGCTaskEligibilityConfig{database, installation})
	if err != nil {
		t.Fatal(err)
	}
	m := &gcTaskEligibilityModel{database: database, installation: installation, kind: kind, ownerID: owner, backup: backup, tasks: map[string][]driver.Value{}, ranges: map[string][][]driver.Value{}, service: s}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_artifact_lease_states", "system_backup_v2_artifact_leases", "system_backup_v2_staging_resources", "system_backup_v2_restore_drill_resources", "system_backup_v2_promotions", "system_backup_v2_prune_items"} {
		m.catalog = append(m.catalog, []driver.Value{table, "BASE TABLE", "InnoDB"})
	}
	row := func(kind, id string, created time.Time) []driver.Value {
		return []driver.Value{int64(11), installation, id, kind, "system-backup-task.v1", "failed", int64(7), now.Add(-500 * 24 * time.Hour), created, now.Add(-600 * 24 * time.Hour), nil, nil, nil, "backup", backup, "", nil, false, "", false, false, nil, int64(0), "", ""}
	}
	m.tasks[backup] = row("backup", backup, now.Add(-800*24*time.Hour))
	b := m.tasks[backup]
	b[15], b[18], b[22] = "deleted", "deleted", int64(3)
	if kind != "backup" {
		m.tasks[owner] = row(kind, owner, now.Add(-700*24*time.Hour))
	}
	if kind == "drill" {
		m.tasks[owner][23], m.tasks[owner][24] = "succeeded", "none"
	}
	return m
}

type gcTaskEligibilityFixture struct {
	m     *gcTaskEligibilityModel
	tx    *sql.Tx
	scope DownloadRetentionGCScope
	now   time.Time
}

func newGCTaskEligibilityFixture(t *testing.T, kind string) *gcTaskEligibilityFixture {
	t.Helper()
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	ids := map[string]string{"backup": "sbk_11111111-1111-4111-8111-111111111111", "drill": "sdr_11111111-1111-4111-8111-111111111111", "preflight": "spf_11111111-1111-4111-8111-111111111111", "artifact_verify": "sav_11111111-1111-4111-8111-111111111111"}
	dbID := sec.DatabaseIdentity{ServerUUID: "gc-test-server", Database: "gc_test"}
	m := newGCTaskEligibilityModel(t, dbID, "installation_test", kind, ids[kind], now)
	db := sql.OpenDB(gcTaskConnector{m})
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	scope := DownloadRetentionGCScope{Database: dbID, Installation: m.installation, WorkerOperation: "sop_99999999-9999-4999-8999-999999999999", PrincipalSHA256: hash([]byte("current GC worker")), Operation: "sop_33333333-3333-4333-8333-333333333333", RequestHash: hash([]byte("request")), Evidence: Identity{Installation: m.installation, ID: "sev_44444444-4444-4444-8444-444444444444", OwnerType: kind, OwnerID: ids[kind]}, OperationID: 73, EvidenceID: 61, ActorID: 1, EvidenceRowVersion: 7, IntentAuditID: 1729, ResultAuditID: 1730, AdmittedAt: now.Add(-400 * 24 * time.Hour), RetainUntil: now.Add(-time.Hour), MinimumRetainUntil: now.Add(-time.Minute)}
	return &gcTaskEligibilityFixture{m, tx, scope, now}
}

func TestDownloadRetentionGCTaskFourOwnersAndOriginalDeadlines(t *testing.T) {
	for _, kind := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		for _, artifact := range []string{"deleted", "never_committed"} {
			t.Run(kind+"/"+artifact, func(t *testing.T) {
				f := newGCTaskEligibilityFixture(t, kind)
				if artifact == "never_committed" {
					f.m.tasks[f.m.backup][15], f.m.tasks[f.m.backup][18] = "staging", "not_committed"
				}
				// Equality is expired, and each original task deadline is independent.
				f.m.tasks[f.m.ownerID][7] = f.now
				g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
				if err != nil {
					t.Fatal(err, f.m.queries)
				}
				locks := append([]string(nil), f.m.locks...)
				f.m.rechecking = true
				if err = g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(locks, f.m.locks) || !strings.HasPrefix(locks[0], downloadGCTaskSQL("backup", false)) || kind != "backup" && !strings.HasPrefix(locks[1], downloadGCTaskSQL(kind, false)) {
					t.Fatal("task/parent lock order or original ranges changed", f.m.locks)
				}
				for _, v := range []any{g, *g} {
					if _, err = json.Marshal(v); err == nil {
						t.Fatal("guard serialized")
					}
				}
			})
		}
	}
}

func TestDownloadRetentionGCTaskProtectedFactsDeny(t *testing.T) {
	cases := map[string]func(*gcTaskEligibilityFixture){
		"live_owner":                 func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][5] = "running" },
		"owner_future_deadline":      func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][7] = f.now.Add(time.Microsecond) },
		"owner_missing":              func(f *gcTaskEligibilityFixture) { delete(f.m.tasks, f.m.ownerID) },
		"owner_wrong_installation":   func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][1] = "installation_other" },
		"owner_wrong_kind":           func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][3] = "backup" },
		"owner_wrong_schema":         func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][4] = "future" },
		"owner_bad_version":          func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][6] = int64(0) },
		"owner_no_finished":          func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][9] = nil },
		"owner_future_finished":      func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][9] = f.now.Add(time.Second) },
		"owner_newer_than_admission": func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][8] = f.scope.AdmittedAt.Add(time.Second) },
		"owner_live_controller": func(f *gcTaskEligibilityFixture) {
			r := f.m.tasks[f.m.ownerID]
			r[10], r[11] = "controller", f.now.Add(time.Second)
		},
		"owner_half_claim":        func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][10] = "controller" },
		"owner_reconcile_pending": func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][12] = f.now.Add(-time.Hour) },
		"backup_missing":          func(f *gcTaskEligibilityFixture) { delete(f.m.tasks, f.m.backup) },
		"backup_nonterminal":      func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][5] = "publishing" },
		"backup_future_deadline":  func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][7] = f.now.Add(time.Second) },
		"manual_hold":             func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][19] = true },
		"promotion_hold":          func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][20] = true },
		"committed_artifact":      func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][15] = "committed" },
		"unresolved_artifact":     func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][15] = "delete_failed" },
		"usable_artifact":         func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.backup][17] = true },
		"unresolved_commit": func(f *gcTaskEligibilityFixture) {
			r := f.m.tasks[f.m.backup]
			r[15], r[18], r[21] = "staging", "not_committed", f.now.Add(-time.Hour)
		},
		"committed_staging": func(f *gcTaskEligibilityFixture) {
			r := f.m.tasks[f.m.backup]
			r[15], r[18], r[16] = "staging", "not_committed", f.now.Add(-time.Hour)
		},
		"catalog_source": func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][13] = "catalog_import" },
		"hint_substitution": func(f *gcTaskEligibilityFixture) {
			f.m.hint = []driver.Value{"backup", f.m.backup}
			f.m.afterHint = func() { f.m.tasks[f.m.ownerID][14] = "sbk_55555555-5555-4555-8555-555555555555" }
		},
		"cleanup_retained": func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][23] = "retained" },
		"cleanup_running":  func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][23] = "running" },
		"cleanup_failed":   func(f *gcTaskEligibilityFixture) { f.m.tasks[f.m.ownerID][24] = "residual_data" },
		"backup_retry": func(f *gcTaskEligibilityFixture) {
			f.m.ranges[gcTaskRangeKey(downloadGCTaskRetrySQL("backup"), f.m.backup)] = [][]driver.Value{{int64(90)}}
		},
		"owner_retry": func(f *gcTaskEligibilityFixture) {
			f.m.ranges[gcTaskRangeKey(downloadGCTaskRetrySQL("drill"), f.m.ownerID)] = [][]driver.Value{{int64(90)}}
		},
		"backup_promotion_without_flag": func(f *gcTaskEligibilityFixture) {
			f.m.ranges[gcTaskRangeKey(downloadGCTaskBackupPromotionSQL, f.m.backup)] = [][]driver.Value{{int64(90)}}
		},
		"drill_promotion_without_flag": func(f *gcTaskEligibilityFixture) {
			f.m.ranges[gcTaskRangeKey(downloadGCTaskDrillPromotionSQL, f.m.ownerID)] = [][]driver.Value{{int64(90)}}
		},
		"wrong_database":     func(f *gcTaskEligibilityFixture) { f.m.database.Database = "other" },
		"missing_table":      func(f *gcTaskEligibilityFixture) { f.m.catalog = f.m.catalog[1:] },
		"view_owner":         func(f *gcTaskEligibilityFixture) { f.m.catalog[0][1] = "VIEW" },
		"nontransactional":   func(f *gcTaskEligibilityFixture) { f.m.catalog[0][2] = "MyISAM" },
		"duplicate_table":    func(f *gcTaskEligibilityFixture) { f.m.catalog = append(f.m.catalog, f.m.catalog[0]) },
		"scope_substitution": func(f *gcTaskEligibilityFixture) { f.scope.Installation = "installation_other" },
		"retention_future":   func(f *gcTaskEligibilityFixture) { f.scope.RetainUntil = f.now.Add(time.Microsecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "drill")
			mutate(f)
			if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err == nil {
				t.Fatal("protected facts admitted")
			}
		})
	}
	for _, kind := range []string{"system", "catalog_import", "restore_resource", "backup_staging", "promotion", "prune_run", "external_action"} {
		t.Run("unsupported/"+kind, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "backup")
			f.scope.Evidence.OwnerType = kind
			if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err == nil || len(f.m.queries) != 0 {
				t.Fatal("unknown source received a task deadline")
			}
		})
	}
}

func gcTaskSettledResource(f *gcTaskEligibilityFixture) []driver.Value {
	return []driver.Value{int64(31), f.m.installation, "deleted", nil, nil, int64(3), "succeeded", "none"}
}
func gcTaskExpiredLease(f *gcTaskEligibilityFixture, kind string) []driver.Value {
	id, purpose, mode := "sdr_66666666-6666-4666-8666-666666666666", "read", "shared"
	if kind == "prune" {
		id, purpose, mode = "spr_66666666-6666-4666-8666-666666666666", "delete", "delete"
	}
	if kind == "health_reconcile" {
		id, purpose = "sop_66666666-6666-4666-8666-666666666666", "verify"
	}
	return []driver.Value{int64(41), f.m.installation, "backup", f.m.backup, int64(3), mode, kind, id, purpose, f.now.Add(-15 * time.Second), f.now, int64(15), int64(4), "lease-worker", int64(1)}
}

func TestDownloadRetentionGCTaskInventoryAndExpiredLeaseRanges(t *testing.T) {
	for _, mode := range []string{"settled", "absent", "expired_claim", "expired_shared", "expired_delete", "expired_health", "live_resource", "unsettled_resource", "cross_installation_resource", "resource_half_claim", "not_started_with_resource", "resource_overflow", "resource_duplicate", "live_lease", "lease_without_state", "lease_wrong_generation", "lease_cross_installation", "lease_wrong_source", "lease_wrong_purpose", "lease_holder_other_source", "lease_state_duplicate", "lease_state_wrong_installation", "lease_bad_ttl", "lease_bad_owner"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "drill")
			allowed := oneOf(mode, "settled", "absent", "expired_claim", "expired_shared", "expired_delete", "expired_health")
			r := gcTaskSettledResource(f)
			q := downloadGCTaskStagingSQL
			id := f.m.backup
			if mode == "not_started_with_resource" {
				q, id = downloadGCTaskRestoreSQL, f.m.ownerID
				r[6] = ""
				f.m.tasks[f.m.ownerID][23] = "not_started"
			}
			switch mode {
			case "absent":
				r[2] = "absent"
			case "expired_claim":
				r[3], r[4] = "old-worker", f.now
			case "live_resource":
				r[3], r[4] = "live-worker", f.now.Add(time.Microsecond)
			case "unsettled_resource":
				r[2] = "delete_failed"
			case "cross_installation_resource":
				r[1] = "installation_other"
			case "resource_half_claim":
				r[3] = "broken-worker"
			}
			f.m.ranges[gcTaskRangeKey(q, id)] = [][]driver.Value{r}
			if mode == "resource_overflow" {
				rs := make([][]driver.Value, 10001)
				for i := range rs {
					rs[i] = append([]driver.Value(nil), r...)
					rs[i][0] = int64(i + 1)
				}
				f.m.ranges[gcTaskRangeKey(q, id)] = rs
			}
			if mode == "resource_duplicate" {
				f.m.ranges[gcTaskRangeKey(q, id)] = [][]driver.Value{r, r}
			}
			if strings.Contains(mode, "lease") || strings.HasPrefix(mode, "expired_") && mode != "expired_claim" {
				kind := "drill"
				if mode == "expired_delete" {
					kind = "prune"
				}
				if mode == "expired_health" {
					kind = "health_reconcile"
				}
				lease := gcTaskExpiredLease(f, kind)
				state := []driver.Value{int64(51), f.m.installation, lease[5], int64(3), int64(4)}
				switch mode {
				case "live_lease":
					lease[10] = f.now.Add(time.Microsecond)
				case "lease_wrong_generation":
					lease[4] = int64(4)
				case "lease_cross_installation":
					lease[1] = "installation_other"
				case "lease_wrong_source", "lease_holder_other_source":
					lease[3] = "sbk_77777777-7777-4777-8777-777777777777"
				case "lease_wrong_purpose":
					lease[8] = "delete"
				case "lease_state_wrong_installation":
					state[1] = "installation_other"
				case "lease_bad_ttl":
					lease[11] = int64(14)
				case "lease_bad_owner":
					lease[13] = ""
				}
				f.m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, f.m.backup)] = [][]driver.Value{state}
				if mode == "lease_without_state" {
					f.m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, f.m.backup)] = nil
				}
				if mode == "lease_state_duplicate" {
					f.m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, f.m.backup)] = [][]driver.Value{state, state}
				}
				lq, largs := downloadGCTaskSourceLeaseSQL, []any{f.m.backup}
				if mode == "lease_holder_other_source" {
					lq, largs = downloadGCTaskHolderLeaseSQL, []any{"drill", f.m.ownerID}
					lease[7] = f.m.ownerID
				}
				f.m.ranges[gcTaskRangeKey(lq, largs...)] = [][]driver.Value{lease}
			}
			g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if (err == nil) != allowed {
				t.Fatal("wrong inventory eligibility", mode, err, f.m.queries)
			}
			if allowed {
				f.m.rechecking = true
				if err = g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDownloadRetentionGCTaskLateChangesPoisonAllCopies(t *testing.T) {
	for _, mode := range []string{"hold", "eligible_version", "eligible_deadline", "owner_disappeared", "source_changed", "resource_inserted", "promotion_inserted", "retry_inserted", "lease_state_inserted", "query_failure", "backward_clock", "scope_changed", "wrong_tx", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "drill")
			g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if err != nil {
				t.Fatal(err)
			}
			copyGuard := *g
			f.m.rechecking = true
			original := f.m.tasks[f.m.backup]
			saved := append([]driver.Value(nil), original...)
			scope, at, tx, ctx := f.scope, f.now, f.tx, context.Background()
			switch mode {
			case "hold":
				original[19] = true
			case "eligible_version":
				original[6] = int64(8)
			case "eligible_deadline":
				original[7] = f.now.Add(-time.Hour)
			case "owner_disappeared":
				delete(f.m.tasks, f.m.ownerID)
			case "source_changed":
				f.m.tasks[f.m.ownerID][14] = "sbk_55555555-5555-4555-8555-555555555555"
			case "resource_inserted":
				f.m.ranges[gcTaskRangeKey(downloadGCTaskStagingSQL, f.m.backup)] = [][]driver.Value{gcTaskSettledResource(f)}
			case "promotion_inserted":
				f.m.ranges[gcTaskRangeKey(downloadGCTaskBackupPromotionSQL, f.m.backup)] = [][]driver.Value{{int64(91)}}
			case "retry_inserted":
				f.m.ranges[gcTaskRangeKey(downloadGCTaskRetrySQL("drill"), f.m.ownerID)] = [][]driver.Value{{int64(91)}}
			case "lease_state_inserted":
				f.m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, f.m.backup)] = [][]driver.Value{{int64(51), f.m.installation, "shared", int64(1), int64(1)}}
			case "query_failure":
				f.m.failQuery = downloadGCTaskSourceLeaseSQL
			case "backward_clock":
				at = at.Add(-time.Microsecond)
			case "scope_changed":
				scope.IntentAuditID++
			case "wrong_tx":
				tx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if g.Recheck(ctx, tx, scope, at) == nil {
				t.Fatal("late drift accepted")
			}
			f.m.tasks[f.m.backup] = saved
			f.m.failQuery = ""
			f.m.ranges = map[string][][]driver.Value{}
			if copyGuard.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)) == nil {
				t.Fatal("failed guard revived through copy")
			}
		})
	}
}

func TestDownloadRetentionGCTaskSQLFailuresAndConfiguration(t *testing.T) {
	f := newGCTaskEligibilityFixture(t, "drill")
	good, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
	if err != nil {
		t.Fatal(err)
	}
	_ = good
	queries := append([]string(nil), f.m.queries...)
	for n, q := range queries {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			x := newGCTaskEligibilityFixture(t, "drill")
			x.m.failQuery = q
			if _, err := x.m.service.Lock(context.Background(), x.tx, x.scope, x.now); err == nil {
				t.Fatal("query failure treated as no references")
			}
		})
	}
	for _, c := range []DownloadGCTaskEligibilityConfig{{}, {Database: f.scope.Database}, {Database: sec.DatabaseIdentity{ServerUUID: "server", Database: "x;DROP"}, Installation: f.scope.Installation}} {
		if _, err := NewSQLDownloadGCTaskEligibility(c); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	var source *SQLDownloadGCTaskEligibility
	if _, err := source.Lock(context.Background(), f.tx, f.scope, f.now); err == nil {
		t.Fatal("nil source accepted")
	}
	var guard *DownloadGCTaskEligibilityGuard
	if guard.Recheck(context.Background(), f.tx, f.scope, f.now) == nil {
		t.Fatal("nil guard accepted")
	}
}

func TestDownloadRetentionGCTaskCollectorRollbackAndFinalRecheck(t *testing.T) {
	for _, mode := range []string{"complete", "late_hold", "late_settled_resource", "late_promotion", "late_lease_state"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			i := f.d.record.Manifest.Identity
			f.d.taskEligibility = newGCTaskEligibilityModel(t, f.d.identity, i.Installation, i.OwnerType, i.OwnerID, f.d.now)
			before := f.d.reserved
			if mode != "complete" {
				f.d.afterWrite = func(q string) {
					if q != downloadGCDeleteResultSQL {
						return
					}
					m := f.d.taskEligibility
					switch mode {
					case "late_hold":
						m.tasks[m.backup][19] = true
					case "late_settled_resource":
						m.ranges[gcTaskRangeKey(downloadGCTaskStagingSQL, m.backup)] = [][]driver.Value{{int64(31), m.installation, "deleted", nil, nil, int64(1), "succeeded", "none"}}
					case "late_promotion":
						m.ranges[gcTaskRangeKey(downloadGCTaskBackupPromotionSQL, m.backup)] = [][]driver.Value{{int64(91)}}
					case "late_lease_state":
						m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, m.backup)] = [][]driver.Value{{int64(51), m.installation, "shared", int64(1), int64(1)}}
					}
				}
			}
			err := f.s.Collect(f.ctx, f.operation)
			if mode == "complete" {
				if err != nil || f.d.commits != f.commits+1 || f.policy.taskGuard == nil {
					t.Fatal("concrete task guard not composed", err, f.d.queries)
				}
				return
			}
			if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || f.d.reserved != before || len(f.d.m.op) == 0 || len(f.d.resultRetention) == 0 || f.d.taskEligibility.tasks[f.d.taskEligibility.backup][19] != false {
				t.Fatal("late task facts did not roll back whole group", err)
			}
		})
	}
}
