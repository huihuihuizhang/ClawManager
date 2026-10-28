package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Synthetic SQL/catalog transport; the mandatory production reference guard,
// original group reconstruction, task guard and collector code all execute.
type gcDirectModel struct {
	d           *retentionGCModel
	refs, saved map[string][][]driver.Value
	locked      map[string]int
	initial     []gcDirectRange
	lastColumns [][]driver.Value
	afterRead   func(string)
}

func newGCDirectModel(d *retentionGCModel) *gcDirectModel {
	return &gcDirectModel{d: d, refs: map[string][][]driver.Value{}}
}
func (m *gcDirectModel) begin() {
	m.saved = map[string][][]driver.Value{}
	for k, v := range m.refs {
		m.saved[k] = cloneGCEarlyRows(v)
	}
	m.locked = map[string]int{}
	m.initial = nil
}
func (m *gcDirectModel) rollback() { m.refs = m.saved }

func (m *gcDirectModel) columnDiagnostic() string {
	expected := gcDirectColumns(m.d.early.service.c.MaintenanceReceipts == "installed")
	seen := map[string]bool{}
	var bad []string
	for _, r := range m.lastColumns {
		key, kind := fmt.Sprint(r[0])+"."+fmt.Sprint(r[1]), fmt.Sprint(r[2])
		if seen[key] || expected[key] != kind {
			bad = append(bad, key+"="+kind+" expected="+expected[key])
		}
		seen[key] = true
		delete(expected, key)
	}
	return string(canonical(map[string]any{"bad": bad, "missing": expected}))
}

var gcDirectColumnPattern = regexp.MustCompile(`(^|_)(operation(_public)?_id|audit(_log)?_id|nonce_id)$|^operation_identity$`)

func gcDirectModelColumn(table, column string) bool {
	return strings.HasPrefix(table, "system_") && gcDirectColumnPattern.MatchString(column) || table == "audit_logs" && oneOf(column, "details", "resource_id") || table == "system_backup_v2_check_results" && column == "cleanup_target_public_id" || table == "system_backup_v2_compact_tombstones" && column == "gc_batch_id" || table == "system_backup_v2_artifact_leases" && column == "holder_public_id"
}
func (m *gcDirectModel) query(q string, a []driver.NamedValue) (driver.Rows, bool, error) {
	if q == downloadGCDirectColumnsSQL {
		var rows [][]driver.Value
		for _, r := range m.d.early.catalog[downloadGCEarlyColumnsSQL] {
			table, column := r[0].(string), r[1].(string)
			if gcDirectModelColumn(table, column) {
				kind := strings.Split(strings.Fields(r[3].(string))[0], "(")[0]
				rows = append(rows, []driver.Value{table, column, kind})
			}
		}
		m.lastColumns = cloneGCEarlyRows(rows)
		return &admissionTxRows{width: 3, data: rows}, true, nil
	}
	if q == downloadGCDirectForeignKeysSQL {
		var rows [][]driver.Value
		for _, r := range m.d.early.catalog[downloadGCEarlyForeignKeysSQL] {
			if oneOf(r[6].(string), "system_backup_v2_operations", "audit_logs", "system_backup_v2_strong_auth_nonces", "system_backup_v2_download_admission_receipts", "system_backup_v2_download_result_receipts") {
				v := append([]driver.Value(nil), r[:8]...)
				v = append(v, r[9])
				rows = append(rows, v)
			}
		}
		return &admissionTxRows{width: 9, data: rows}, true, nil
	}
	for _, r := range gcDirectReferences(true) {
		if q != gcDirectQuery(r) {
			continue
		}
		args := make([]any, len(a))
		for i, v := range a {
			args[i] = v.Value
		}
		if len(args) == 0 || strings.Count(q, "?") != len(args) {
			return nil, true, errors.New("direct reference argument shape")
		}
		if r.own {
			own := int64(73)
			if r.table == "system_backup_v2_strong_auth_nonces" {
				own = 95
			}
			if r.table == "audit_logs" {
				own = m.d.id
			}
			if len(args) < 2 || args[1] != own || r.table == "audit_logs" && (len(args) != 3 || args[2] != int64(1730)) {
				return nil, true, errors.New("wrong own original group exemption")
			}
		}
		key := gcTaskRangeKey(q, args...)
		if _, ok := m.locked[key]; !ok {
			valid := r.stage == 1 && !m.d.opKeyLocked && !m.d.ownerLocked || r.stage == 3 && m.d.opKeyLocked && !m.d.ownerLocked || r.stage == 5 && m.d.ownerLocked && m.d.groupReads[downloadRetentionNonceSQL] > 0 && !m.d.evidenceLocked || r.stage == 7 && m.d.reserved > 0 && m.d.groupReads[downloadRetentionAuditSQL] >= 2 && !m.d.evidenceLocked
			if !valid {
				return nil, true, errors.New("new direct reference range outside its initial phase")
			}
			m.locked[key] = r.stage
			m.initial = append(m.initial, gcDirectRange{q, args, r.stage})
		}
		if m.afterRead != nil {
			m.afterRead(q)
		}
		return &admissionTxRows{width: 1, data: cloneGCEarlyRows(m.refs[key])}, true, nil
	}
	return nil, false, nil
}

func gcDirectTestArgs(f *retentionGCFixture, r gcDirectReference, audit int64) []any {
	var value any = f.operation
	switch r.value {
	case "numeric":
		value = int64(73)
	case "audits":
		value = audit
	case "nonce":
		value = "95"
	}
	if strings.HasPrefix(r.column, "json:") && r.value == "audits" {
		value = strconv.FormatInt(audit, 10)
	}
	args := []any{value}
	if r.own {
		own := int64(73)
		if r.table == "system_backup_v2_strong_auth_nonces" {
			own = 95
		}
		if r.table == "audit_logs" {
			own = f.d.id
		}
		args = append(args, own)
		if r.table == "audit_logs" {
			args = append(args, int64(1730))
		}
	}
	return args
}
func gcDirectOwnedRanges() []gcDirectReference {
	var out []gcDirectReference
	for _, r := range gcDirectReferences(true) {
		if r.table != "system_backup_v2_config_maintenance_receipts" {
			out = append(out, r)
		}
	}
	return out
}

func TestDownloadRetentionGCDirectPublishedColumnTypesAndFKs(t *testing.T) {
	// Independent declarations, not gcDirectColumns-generated fake metadata.
	// This is a source contract check, not execution of MySQL DDL or a parser
	// for arbitrary historical upgrades. The real metadata guard remains needed.
	entries, err := os.ReadDir(filepath.Join("..", "db", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			raw, e := os.ReadFile(filepath.Join("..", "db", "migrations", entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			sources = append(sources, string(raw))
		}
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "download_producer_probe_inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var capsule struct {
		Admission string `json:"admission_inputs"`
	}
	if json.Unmarshal(raw, &capsule) != nil {
		t.Fatal("producer input capsule")
	}
	var inputs struct {
		Ownership string `json:"ownership_ddl"`
	}
	if json.Unmarshal([]byte(capsule.Admission), &inputs) != nil {
		t.Fatal("admission DDL capsule")
	}
	sources = append(sources, inputs.Ownership)
	statement := regexp.MustCompile(`(?i)(?:CREATE TABLE(?: IF NOT EXISTS)?|ALTER TABLE)\s+([a-z_][a-z0-9_]*)`)
	column := regexp.MustCompile(`(?m)^[ \t]{2,}(?:ADD COLUMN )?([a-z_][a-z0-9_]*)[ \t]+([A-Za-z]+)`)
	fk := regexp.MustCompile(`(?is)FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)`)
	actual := map[string]string{}
	// The integration publishes maintenance receipts as an appended migration;
	// they are no longer an optional proposal outside the runtime schema.
	allowed := gcDirectFKEdges(true)
	fkCount := 0
	for _, source := range sources {
		matches := statement.FindAllStringSubmatchIndex(source, -1)
		for n, m := range matches {
			table := strings.ToLower(source[m[2]:m[3]])
			end := len(source)
			if n+1 < len(matches) {
				end = matches[n+1][0]
			}
			body := source[m[1]:end]
			for _, c := range column.FindAllStringSubmatch(body, -1) {
				if gcDirectModelColumn(table, c[1]) {
					key := table + "." + c[1]
					if _, exists := actual[key]; !exists {
						actual[key] = strings.ToLower(c[2])
					}
				}
			}
			for _, edge := range fk.FindAllStringSubmatch(body, -1) {
				target := strings.ToLower(edge[2])
				if !oneOf(target, "system_backup_v2_operations", "audit_logs", "system_backup_v2_strong_auth_nonces", "system_backup_v2_download_admission_receipts", "system_backup_v2_download_result_receipts") {
					continue
				}
				left, right := strings.Split(edge[1], ","), strings.Split(edge[3], ",")
				if len(left) != len(right) {
					t.Fatal("bad published composite FK")
				}
				for i := range left {
					key := table + "." + strings.TrimSpace(left[i]) + ">" + target + "." + strings.TrimSpace(right[i])
					if !allowed[key] {
						t.Fatal("published FK lacks a direct reference classifier", key)
					}
					fkCount++
				}
			}
		}
	}
	if !reflect.DeepEqual(actual, gcDirectColumns(true)) {
		t.Fatal("published source types differ from GC catalog", actual, gcDirectColumns(true))
	}
	if fkCount < 20 {
		t.Fatal("published FK declarations were not read", fkCount)
	}
}

func TestDownloadRetentionGCDirectPhasesAndOriginalOwnLinks(t *testing.T) {
	f := newRetentionGCFixture(t)
	i := f.d.record.Manifest.Identity
	f.d.taskEligibility = newGCTaskEligibilityModel(t, f.d.identity, i.Installation, i.OwnerType, i.OwnerID, f.d.now)
	if err := f.s.Collect(f.ctx, f.operation); err != nil {
		t.Fatal(err, f.d.direct.columnDiagnostic(), f.d.queries)
	}
	if f.d.commits != f.commits+1 || len(f.d.m.op) != 0 || len(f.d.nonce) != 0 || len(f.d.resultRetention) != 0 || len(f.d.stone) != 23 {
		t.Fatal("direct checks prevented legitimate own group deletion")
	}
	stages := map[int]int{}
	for _, r := range f.d.direct.initial {
		stages[r.stage]++
	}
	if !reflect.DeepEqual(stages, map[int]int{1: 2, 3: 10, 5: 12, 7: 8}) {
		t.Fatal("missing direct phases/ranges", stages)
	}
	first := func(q string) int {
		for n, v := range f.d.queries {
			if q == v {
				return n
			}
		}
		return -1
	}
	for _, r := range f.d.direct.initial {
		at := first(r.query)
		switch r.stage {
		case 1:
			if at >= first(downloadResultActorSQL) {
				t.Fatal("early ref follows actor")
			}
		case 3:
			if at >= first(downloadGCTaskSQL("backup", false)) {
				t.Fatal("L3 follows task owner")
			}
		case 5:
			if at <= first(downloadRetentionNonceSQL) || at >= first(downloadRetentionAuditSQL) {
				t.Fatal("L5 reference order")
			}
		case 7:
			if at <= first(downloadRetentionAuditSQL) || at >= first(downloadGCDeletedEvidenceSQL) {
				t.Fatal("L7 reference order")
			}
		}
	}
}

func TestDownloadRetentionGCDirectEveryIncomingRangeBlocks(t *testing.T) {
	for _, r := range gcDirectOwnedRanges() {
		ids := []int64{1729}
		if r.value == "audits" {
			ids = append(ids, 1730)
		}
		for _, audit := range ids {
			t.Run(r.table+"/"+r.column+"/"+strconv.FormatInt(audit, 10), func(t *testing.T) {
				f := newRetentionGCFixture(t)
				args := gcDirectTestArgs(f, r, audit)
				key := gcTaskRangeKey(gcDirectQuery(r), args...)
				f.d.direct.refs[key] = [][]driver.Value{{"foreign-cross-installation-or-retained-reference"}}
				before := f.d.reserved
				err := f.s.Collect(f.ctx, f.operation)
				if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.writes) != 0 || f.d.reserved != before {
					t.Fatal("incoming reference allowed collection", r, err)
				}
				if _, reached := f.d.direct.locked[key]; !reached {
					last := f.d.queries
					if len(last) > 8 {
						last = last[len(last)-8:]
					}
					t.Fatal("negative case never reached its reference range", r, err, "sql_clock_age", time.Since(f.d.now), "last_queries", last)
				}
			})
		}
	}
}

func TestDownloadRetentionGCDirectLateRangesRollBackWholeGroup(t *testing.T) {
	for _, stage := range []int{1, 3, 5, 7} {
		t.Run(strconv.Itoa(stage), func(t *testing.T) {
			f := newRetentionGCFixture(t)
			var target gcDirectReference
			for _, r := range gcDirectOwnedRanges() {
				if r.stage == stage {
					target = r
					break
				}
			}
			args := gcDirectTestArgs(f, target, 1729)
			before := f.d.reserved
			injected := false
			f.d.afterWrite = func(q string) {
				if q == downloadGCDeleteResultSQL {
					injected = true
					f.d.direct.refs[gcTaskRangeKey(gcDirectQuery(target), args...)] = [][]driver.Value{{int64(9001)}}
				}
			}
			if err := f.s.Collect(f.ctx, f.operation); err == nil || !injected || len(f.d.writes) < 2 || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || f.d.reserved != before || len(f.d.resultRetention) == 0 || len(f.d.direct.refs) != 0 {
				t.Fatal("late reference escaped atomic rollback", err)
			}
		})
	}
}

func TestDownloadRetentionGCDirectClosedSchemaAndFailures(t *testing.T) {
	for _, mode := range []string{"unknown_column", "missing_column", "wrong_type", "duplicate_column", "missing_table", "view", "unknown_fk", "cross_schema_fk", "nonce_fk", "result_fk", "cascade_fk", "columns_query", "fk_query", "reference_query", "missing_component", "wrong_component_database", "wrong_component_installation"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			m := f.d.early
			switch mode {
			case "unknown_column":
				m.catalog[downloadGCEarlyColumnsSQL] = append(m.catalog[downloadGCEarlyColumnsSQL], []driver.Value{"system_backup_v2_operations", "new_operation_id", "900", "bigint", "YES", "null", "", "", "", "", ""})
			case "missing_column", "wrong_type", "duplicate_column":
				for n, r := range m.catalog[downloadGCEarlyColumnsSQL] {
					if r[0] == "system_backup_v2_operations" && r[1] == "retry_of_operation_public_id" {
						switch mode {
						case "missing_column":
							m.catalog[downloadGCEarlyColumnsSQL] = append(m.catalog[downloadGCEarlyColumnsSQL][:n], m.catalog[downloadGCEarlyColumnsSQL][n+1:]...)
						case "wrong_type":
							r[3] = "bigint"
						case "duplicate_column":
							m.catalog[downloadGCEarlyColumnsSQL] = append(m.catalog[downloadGCEarlyColumnsSQL], append([]driver.Value(nil), r...))
						}
						break
					}
				}
			case "missing_table", "view":
				for n, r := range m.catalog[downloadGCEarlyTablesSQL] {
					if r[0] == "system_backup_v2_events" {
						if mode == "view" {
							r[1] = "VIEW"
						} else {
							m.catalog[downloadGCEarlyTablesSQL] = append(m.catalog[downloadGCEarlyTablesSQL][:n], m.catalog[downloadGCEarlyTablesSQL][n+1:]...)
						}
						break
					}
				}
			case "unknown_fk", "cross_schema_fk", "nonce_fk", "result_fk", "cascade_fk":
				r := append([]driver.Value(nil), m.catalog[downloadGCEarlyForeignKeysSQL][0]...)
				switch mode {
				case "unknown_fk":
					r[1] = "unknown_reference"
				case "cross_schema_fk":
					r[0] = "other_database"
				case "nonce_fk":
					r[6] = "system_backup_v2_strong_auth_nonces"
				case "result_fk":
					r[6] = "system_backup_v2_download_result_receipts"
				case "cascade_fk":
					r[9] = "CASCADE"
				}
				m.catalog[downloadGCEarlyForeignKeysSQL] = [][]driver.Value{r}
			case "columns_query":
				f.d.fail = "query:" + downloadGCDirectColumnsSQL
			case "fk_query":
				f.d.fail = "query:" + downloadGCDirectForeignKeysSQL
			case "reference_query":
				f.d.fail = "query:" + gcDirectQuery(gcDirectReferences(true)[0])
			case "missing_component", "wrong_component_database", "wrong_component_installation":
				c := f.s.c
				if mode == "missing_component" {
					c.References = nil
				} else {
					copyService := *c.References
					c.References = &copyService
					if mode == "wrong_component_database" {
						c.References.c.Database.Database = "different"
					} else {
						c.References.c.Installation = "installation_other"
					}
				}
				if _, err := NewSQLDownloadRetentionGC(c); err == nil {
					t.Fatal("mandatory component omitted or rebound")
				}
				return
			}
			// Re-pin the scripted catalog: this test exercises the independent closed
			// reference semantics, not merely the outer exact fingerprint mismatch.
			m.service.c.Metadata = m.pins()
			if err := f.s.Collect(f.ctx, f.operation); err == nil || len(f.d.writes) != 0 {
				t.Fatal("schema/query failure inferred empty refs", mode, err)
			}
		})
	}
}

func openGCDirectGuard(t *testing.T, f *retentionGCFixture) (*downloadGCDirectGuard, *sql.Tx, DownloadRetentionGCScope) {
	t.Helper()
	ctx := context.Background()
	tx, _, err := f.s.c.Registry.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	configScope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, f.d.identity, f.d.record.Manifest.Identity.Installation)
	if err != nil {
		t.Fatal(err)
	}
	config, err := configScope.LoadConfig(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	h := DownloadGCEarlyScope{Database: f.d.identity, Installation: f.d.record.Manifest.Identity.Installation, WorkerOperation: f.s.c.OperationID, PrincipalSHA256: f.s.principal, Operation: f.operation, OperationID: 73, ActorID: 42, IntentAuditID: f.d.id, ResultAuditID: 1730}
	g, err := f.s.c.References.early(ctx, tx, h, f.d.now)
	if err != nil {
		t.Fatal(err)
	}
	group, err := LockDownloadRetentionGroup(ctx, tx, f.d.identity, config, f.operation)
	if err != nil {
		t.Fatal(err)
	}
	s := DownloadRetentionGCScope{Database: h.Database, Installation: h.Installation, WorkerOperation: h.WorkerOperation, PrincipalSHA256: h.PrincipalSHA256, Operation: h.Operation, OperationID: 73, ActorID: 42, IntentAuditID: h.IntentAuditID, ResultAuditID: h.ResultAuditID, Evidence: f.d.record.Manifest.Identity, EvidenceID: 61, EvidenceRowVersion: group.receipt.EvidenceRowVersion, RequestHash: group.operation.RequestHash, AdmittedAt: group.operation.AdmittedAt, RetainUntil: group.retain, MinimumRetainUntil: group.retain}
	if g.bindL3(ctx, tx, s, group) != nil {
		t.Fatal("bind direct L3")
	}
	if _, err = f.policy.Lock(ctx, tx, s, f.d.now); err != nil {
		t.Fatal(err)
	}
	if group.LockNonce(ctx, tx) != nil || g.lockL5(ctx, tx, group) != nil {
		t.Fatal("lock original nonce/direct L5")
	}
	if _, err = f.s.c.Capacity.Reserve(ctx, tx, config.Values(), config.Values(), f.s.c.MeasuredReservationBytes, f.d.now); err != nil {
		t.Fatal(err)
	}
	if group.VerifyAudits(ctx, tx) != nil || g.lockL7(ctx, tx) != nil || g.Recheck(ctx, tx, s, f.d.now) != nil {
		t.Fatal("lock original audits/direct L7")
	}
	return g, tx, s
}

func TestDownloadRetentionGCDirectGuardStagesAndPoison(t *testing.T) {
	for _, mode := range []string{"wrong_tx", "wrong_stage", "scope_change", "late_valid_fk", "late_query", "backward_clock", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			g, tx, s := openGCDirectGuard(t, f)
			copyGuard := *g
			ctx, at := context.Background(), f.d.now
			switch mode {
			case "wrong_tx":
				tx = nil
			case "scope_change":
				s.ActorID++
			case "late_valid_fk":
				r := append([]driver.Value(nil), f.d.early.catalog[downloadGCEarlyForeignKeysSQL][0]...)
				r[2] = "late_permitted_constraint"
				f.d.early.catalog[downloadGCEarlyForeignKeysSQL] = append(f.d.early.catalog[downloadGCEarlyForeignKeysSQL], r)
				f.d.early.service.c.Metadata = f.d.early.pins()
			case "late_query":
				f.d.fail = "query:" + downloadGCDirectColumnsSQL
			case "backward_clock":
				at = at.Add(-time.Microsecond)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var err error
			if mode == "wrong_stage" {
				err = g.lockL7(ctx, tx)
			} else {
				err = g.Recheck(ctx, tx, s, at)
			}
			if err == nil {
				t.Fatal("guard misuse or late change accepted", mode)
			}
			f.d.fail = ""
			if copyGuard.Recheck(context.Background(), g.tx, g.scope, f.d.now.Add(time.Second)) == nil {
				t.Fatal("failed reference guard revived through copy")
			}
			for _, v := range []any{g, *g} {
				if _, err := json.Marshal(v); err == nil {
					t.Fatal("private group guard serialized")
				}
			}
		})
	}
	var source *SQLDownloadGCDirectReferences
	if _, err := source.early(context.Background(), nil, DownloadGCEarlyScope{}, newRetentionGCFixture(t).d.now); err == nil {
		t.Fatal("nil direct source accepted")
	}
	for _, c := range []DownloadGCDirectReferencesConfig{{}, {Installation: "installation_test", MaintenanceReceipts: "installed"}} {
		if _, err := NewSQLDownloadGCDirectReferences(c); err == nil {
			t.Fatal("incomplete direct configuration accepted")
		}
	}
}
