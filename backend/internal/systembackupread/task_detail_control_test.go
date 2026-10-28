package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type detailControlFixture struct {
	*executionFixture
	values                           map[string]driver.Value
	queryError, missing, streamError bool
}

func newDetailControlFixture(kind TaskKind) *detailControlFixture {
	e := newExecutionFixture(kind)
	v := map[string]driver.Value{
		"schema_version": "system-backup-task.v1", "public_id": e.rows[0][1], "origin_installation_id": "installation_test",
		"task_type": string(kind), "row_version": int64(1), "config_version": int64(1), "status": "pending",
		"task_purpose": "acceptance", "source_artifact_type": "backup", "source_public_id": "sbk_00000000-0000-4000-8000-000000000003",
		"target_profile": "cluster", "restore_target_config_hash": strings.Repeat("f", 64),
		"verifier_aggregate_status": "skipped", "verifier_passed": int64(0), "verifier_warning": int64(0), "verifier_failed": int64(0), "verifier_skipped": int64(0),
		"acceptance_eligible": false, "eligibility_reason_codes": "task_not_succeeded",
	}
	switch kind {
	case BackupTask:
		for column, value := range map[string]driver.Value{
			"source_orchestrator": "kubernetes", "source_profile": "cluster", "matrix_key": "k8s-cluster", "datasource_topology": "in_cluster", "runner": "k8s",
			"requested_parts": "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle", "target_class": "dr-ready-external", "target_risks": "", "target_failure_domain_id": "external-zone",
			"artifact_state": "staging", "artifact_usable": false, "artifact_unusable_reason": "not_committed", "manual_hold": false, "promotion_hold": false, "prune_guard_version": int64(1),
		} {
			v[column] = value
		}
	case DrillTask:
		v["cleanup_policy"], v["cleanup_status"], v["cleanup_failure_code"] = "delete-on-success", "not_started", "none"
	case PreflightTask:
		v["preflight_mode"], v["artifact_compatibility"], v["report_validity_reason"] = "production_readonly", "supported", "pending"
	case VerificationTask:
		v["verification_scope"], v["usable_before"], v["usable_after"] = "health", false, false
		v["artifact_state_before"], v["artifact_state_after"] = "staging", "staging"
		v["unusable_reason_before"], v["unusable_reason_after"], v["decision_reason"] = "not_committed", "not_committed", "pending"
	}
	return &detailControlFixture{executionFixture: e, values: v}
}

type detailControlConnector struct{ f *detailControlFixture }

func (c detailControlConnector) Connect(context.Context) (driver.Conn, error) {
	return &detailControlConn{executionConn{c.f.executionFixture}, c.f}, nil
}
func (detailControlConnector) Driver() driver.Driver { return pageDriver{} }

type detailControlConn struct {
	executionConn
	f *detailControlFixture
}

func (c *detailControlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	kind := TaskKind(f.rows[0][3].(string))
	if query != taskDetailControlSQL(kind) {
		return c.executionConn.QueryContext(ctx, query, args)
	}
	f.queries = append(f.queries, query)
	if f.queryError {
		return nil, errors.New("detail read failure")
	}
	if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][1] {
		return nil, errors.New("unscoped detail read")
	}
	columns := strings.Split(strings.TrimSuffix(strings.TrimPrefix(query, "SELECT "), " FROM "+taskTables[kind].name+" WHERE origin_installation_id=? AND public_id=?"), ",")
	row := make([]driver.Value, len(columns))
	for i, column := range columns {
		row[i] = f.values[column]
	}
	rows := &pageRows{columns: columns}
	if !f.missing {
		rows.values = [][]driver.Value{row}
	}
	if f.streamError {
		return detailControlErrorRows{rows}, nil
	}
	return rows, nil
}

type detailControlErrorRows struct{ *pageRows }

func (detailControlErrorRows) Next([]driver.Value) error {
	return errors.New("detail row read failure")
}

func detailControlReader(t *testing.T, f *detailControlFixture) *Reader {
	t.Helper()
	db := sql.OpenDB(detailControlConnector{f})
	t.Cleanup(func() { db.Close() })
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTaskDetailControlFourKindsShareExecutionSnapshotAndStayPrivate(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newDetailControlFixture(kind)
			s, err := detailControlReader(t, f).ReadTaskDetailControl(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || s.Execution().Task().Kind != kind || len(s.Execution().Attempts()) != 1 || len(s.Execution().JobObservations()) != 1 ||
				len(f.queries) != 4 || f.queries[3] != taskDetailControlSQL(kind) || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || f.rechecks != 1 || f.commits != 1 || f.rollbacks != 0 {
				t.Fatal("detail was not one complete authorized snapshot", err, f.queries, f.options, f.rechecks, f.commits, f.rollbacks)
			}
			b, isBackup := s.Backup()
			d, isDrill := s.Drill()
			p, isPreflight := s.Preflight()
			v, isVerification := s.Verification()
			if isBackup != (kind == BackupTask) || isDrill != (kind == DrillTask) || isPreflight != (kind == PreflightTask) || isVerification != (kind == VerificationTask) {
				t.Fatal("wrong kind getter available")
			}
			if isBackup {
				if b.Consistency.Valid || b.Bytes.Valid || b.Eligibility.DecisionSHA.Valid || b.ArtifactUsable || b.Eligibility.Eligible {
					t.Fatal("unknown or pending facts replaced by defaults", b)
				}
				b.RequestedParts[0], b.Eligibility.Reasons[0] = "changed", "changed"
				again, _ := s.Backup()
				if again.RequestedParts[0] != "mysql" || again.Eligibility.Reasons[0] != "task_not_succeeded" {
					t.Fatal("backup getter aliases saved slices")
				}
			}
			if isDrill {
				d.Eligibility.Reasons[0] = "changed"
				again, _ := s.Drill()
				if again.Eligibility.Reasons[0] != "task_not_succeeded" {
					t.Fatal("drill getter aliases reasons")
				}
			}
			for _, value := range []any{s, b, d, p, v, b.Eligibility, b.Checksums, d.Source, p.Report, v.Verifier} {
				if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
					t.Fatal("internal contribution became public JSON", err)
				}
			}
			for _, query := range f.queries {
				for _, forbidden := range []string{"SELECT *", "config_snapshot", "failure_message", "manual_hold_reason", "manual_hold_actor", "artifact_uri", "immutable_version", "restore_target_config_ref", "relay_identity_ref", "expected_json", "actual_json"} {
					if strings.Contains(query, forbidden) {
						t.Fatal("sensitive column selected", forbidden, query)
					}
				}
			}
		})
	}
}

func TestTaskDetailControlRejectsCorruptBindingsAndKindFields(t *testing.T) {
	type mutation struct {
		kind   TaskKind
		column string
		value  driver.Value
	}
	cases := map[string]mutation{
		"verification backup missing state":      {VerificationTask, "artifact_state_before", nil},
		"verification false usability with none": {VerificationTask, "unusable_reason_after", "none"},
		"backup empty parts":                     {BackupTask, "requested_parts", ""}, "backup unknown part": {BackupTask, "requested_parts", "mysql,other"}, "backup duplicate part": {BackupTask, "requested_parts", "mysql,mysql"},
		"backup unknown risk": {BackupTask, "target_risks", "other"}, "backup duplicate risk": {BackupTask, "target_risks", "broad_egress,broad_egress"},
		"backup matrix mismatch": {BackupTask, "matrix_key", "k3s-cluster"}, "backup runner mismatch": {BackupTask, "runner", "k3s"}, "backup profile": {BackupTask, "source_profile", "other"},
		"backup topology": {BackupTask, "datasource_topology", "external"}, "backup purpose": {BackupTask, "task_purpose", "other"}, "backup target class": {BackupTask, "target_class", "other"},
		"backup empty domain": {BackupTask, "target_failure_domain_id", ""}, "backup consistency": {BackupTask, "consistency", "unknown"},
		"backup staging usable": {BackupTask, "artifact_usable", true}, "backup staging committed time": {BackupTask, "artifact_committed_at", time.Now()}, "backup unknown state": {BackupTask, "artifact_state", "other"},
		"backup bad checksum": {BackupTask, "manifest_checksum", "bad"}, "backup registration missing hash": {BackupTask, "artifact_registration_id", "record"},
		"backup hold missing time": {BackupTask, "manual_hold", true}, "backup zero guard": {BackupTask, "prune_guard_version", int64(0)}, "backup negative bytes": {BackupTask, "artifact_bytes", int64(-1)},
		"backup unknown reason": {BackupTask, "eligibility_reason_codes", "other"}, "backup duplicate reason": {BackupTask, "eligibility_reason_codes", "task_not_succeeded,task_not_succeeded"},
		"backup false eligible reason": {BackupTask, "eligibility_reason_codes", "eligible"}, "backup missing decision time": {BackupTask, "eligibility_decision_hash", strings.Repeat("f", 64)},
		"drill source kind": {DrillTask, "source_artifact_type", "other"}, "drill wrong source prefix": {DrillTask, "source_public_id", "sdr_00000000-0000-4000-8000-000000000003"},
		"drill source hash": {DrillTask, "source_manifest_checksum", "bad"}, "drill bad target hash": {DrillTask, "restore_target_config_hash", "bad"}, "drill target profile": {DrillTask, "target_profile", "other"},
		"drill cleanup missing failure": {DrillTask, "cleanup_status", "failed"}, "drill cleanup inconsistent failure": {DrillTask, "cleanup_failure_code", "internal"}, "drill cleanup policy": {DrillTask, "cleanup_policy", "other"},
		"drill evidence missing hash": {DrillTask, "preflight_evidence_public_id", "sev_00000000-0000-4000-8000-000000000003"}, "drill verifier count overflow": {DrillTask, "verifier_passed", int64(1 << 32)},
		"drill verifier aggregate": {DrillTask, "verifier_aggregate_status", "unknown"}, "drill verifier report missing ID": {DrillTask, "verifier_report_evidence_sha256", strings.Repeat("f", 64)},
		"preflight mode": {PreflightTask, "preflight_mode", "other"}, "preflight compatibility": {PreflightTask, "artifact_compatibility", "other"}, "preflight validity": {PreflightTask, "report_validity_reason", "other"},
		"preflight evidence missing hash": {PreflightTask, "report_evidence_public_id", "sev_00000000-0000-4000-8000-000000000003"},
		"verification scope":              {VerificationTask, "verification_scope", "other"}, "verification unknown observed state": {VerificationTask, "artifact_state_before", "other"},
		"verification bad checksum": {VerificationTask, "observed_catalog_checksum", "bad"}, "verification unknown decision": {VerificationTask, "decision_reason", "other"},
		"verification unknown reason": {VerificationTask, "unusable_reason_after", "other"}, "verification missing state but usable": {VerificationTask, "usable_after", true},
		"verification health report half pair": {VerificationTask, "health_report_evidence_sha256", strings.Repeat("f", 64)},
	}
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		for column, bad := range map[string]driver.Value{"schema_version": "system-backup-task.v2", "public_id": "sbk_00000000-0000-4000-8000-000000000099", "origin_installation_id": "installation_other", "task_type": "other", "row_version": int64(2), "config_version": int64(2), "status": "succeeded"} {
			cases[string(kind)+" binding "+column] = mutation{kind, column, bad}
		}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newDetailControlFixture(tc.kind)
			f.values[tc.column] = tc.value
			s, err := detailControlReader(t, f).ReadTaskDetailControl(context.Background(), tc.kind, f.rows[0][1].(string))
			if !errors.Is(err, ErrUnavailable) || !reflect.ValueOf(s).IsZero() || f.commits != 0 || f.rollbacks != 1 {
				t.Fatal("corrupt detail escaped or committed", s, err, f.commits, f.rollbacks)
			}
		})
	}
}

func TestTaskDetailControlPreservesHistoricalEligibilityAndUnknowns(t *testing.T) {
	f := newDetailControlFixture(BackupTask)
	f.rows[0][11], f.values["status"] = "succeeded", "succeeded"
	for column, value := range map[string]driver.Value{"acceptance_eligible": true, "eligibility_reason_codes": "eligible", "eligibility_decision_hash": strings.Repeat("d", 64), "eligibility_decided_at": f.rows[0][20],
		"artifact_registration_id": "registered-exact-version", "artifact_registration_hash": strings.Repeat("e", 64), "artifact_state": "deleted", "artifact_unusable_reason": "deleted", "artifact_bytes": "18446744073709551615"} {
		f.values[column] = value
	}
	s, err := detailControlReader(t, f).ReadTaskDetailControl(context.Background(), BackupTask, f.rows[0][1].(string))
	b, ok := s.Backup()
	if err != nil || !ok || !b.Eligibility.Eligible || b.ArtifactUsable || !b.Bytes.Valid || b.Bytes.V != ^uint64(0) || b.Consistency.Valid {
		t.Fatal("historical eligibility, uint64 or unknown consistency changed", b, err)
	}
}

func TestTaskDetailControlImportedVerificationPreservesNullStates(t *testing.T) {
	f := newDetailControlFixture(VerificationTask)
	f.values["source_artifact_type"], f.values["source_public_id"] = "catalog_import", "sci_00000000-0000-4000-8000-000000000003"
	f.values["artifact_state_before"], f.values["artifact_state_after"] = nil, nil
	f.values["usable_before"], f.values["usable_after"] = true, true
	f.values["unusable_reason_before"], f.values["unusable_reason_after"] = "none", "none"
	s, err := detailControlReader(t, f).ReadTaskDetailControl(context.Background(), VerificationTask, f.rows[0][1].(string))
	v, ok := s.Verification()
	if err != nil || !ok || v.StateBefore.Valid || v.StateAfter.Valid || !v.UsableBefore || !v.UsableAfter {
		t.Fatal("imported artifact state or saved readability changed", v, err)
	}
}

func TestTaskDetailControlTransactionFailuresNeverPublishPartialResults(t *testing.T) {
	for _, scenario := range []string{"initial deny", "final deny", "commit", "query", "missing detail", "row stream", "execution query", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDetailControlFixture(BackupTask)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expected := ErrUnavailable
			switch scenario {
			case "initial deny":
				f.deny = true
				expected = ErrDenied
			case "final deny":
				f.finalErr = errors.New("revoked")
				expected = ErrDenied
			case "commit":
				f.commitErr = errors.New("commit reply lost")
			case "query":
				f.queryError = true
			case "missing detail":
				f.missing = true
			case "row stream":
				f.streamError = true
			case "execution query":
				f.executionFixture.queryError = taskJobsSQL
			case "canceled":
				cancel()
				expected = ErrDenied
			}
			s, err := detailControlReader(t, f).ReadTaskDetailControl(ctx, BackupTask, f.rows[0][1].(string))
			if !errors.Is(err, expected) || !reflect.ValueOf(s).IsZero() {
				t.Fatal("failure returned detail", s, err)
			}
			if scenario == "initial deny" && len(f.queries) != 0 {
				t.Fatal("denied reader selected data")
			}
		})
	}
}

func TestTaskDetailControlBuilderCannotCommitOrOutliveFinalAuthority(t *testing.T) {
	for _, scenario := range []string{"success", "revoked", "builder failure", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDetailControlFixture(BackupTask)
			r := detailControlReader(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			result, err := readTaskDetailControlInTransaction(ctx, r, BackupTask, f.rows[0][1].(string), func(ctx context.Context, q detailReadSQL, s TaskDetailControlSnapshot) (string, error) {
				called = true
				if f.rechecks != 0 || f.commits != 0 || len(f.queries) != 4 {
					t.Fatal("builder ran outside detail snapshot")
				}
				if _, ok := any(q).(*sql.Tx); ok {
					t.Fatal("builder obtained transaction")
				}
				if _, ok := any(q).(interface{ Commit() error }); ok {
					t.Fatal("builder can commit")
				}
				b, ok := s.Backup()
				if !ok || b.ArtifactState != "staging" {
					t.Fatal("builder missing D detail")
				}
				var rowVersion uint64
				// A later Owner query uses this exact same transaction wrapper.
				if err := q.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM system_backup_v2_backups WHERE origin_installation_id=?", s.Execution().Task().InstallationID).Scan(&rowVersion); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "revoked":
					f.finalErr = ErrDenied
				case "builder failure":
					return "partial", errors.New("Owner unavailable")
				case "cancel":
					cancel()
				}
				return "complete", nil
			})
			if !called {
				t.Fatal("builder not called")
			}
			if scenario == "success" {
				if err != nil || result != "complete" || f.commits != 1 || f.rechecks != 1 {
					t.Fatal("successful result missing", result, err)
				}
			} else if err == nil || result != "" {
				t.Fatal("unconfirmed result escaped", result, err)
			}
		})
	}
	if s, err := readTaskDetailControlInTransaction[string](context.Background(), nil, BackupTask, "invalid", nil); s != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil builder accepted", s, err)
	}
}

func TestTaskDetailControlColumnsExistInPublishedMigration(t *testing.T) {
	data, err := os.ReadFile("../db/migrations/098_backup_v2_add_system_backup_task_execution_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		query := taskDetailControlSQL(kind)
		table := taskTables[kind].name
		ddl := strings.SplitN(string(data), "CREATE TABLE IF NOT EXISTS "+table+" (", 2)[1]
		ddl = strings.SplitN(ddl, ") ENGINE=InnoDB", 2)[0]
		columns := strings.Split(strings.TrimSuffix(strings.TrimPrefix(query, "SELECT "), " FROM "+table+" WHERE origin_installation_id=? AND public_id=?"), ",")
		for _, column := range columns {
			if !strings.Contains(ddl, "\n  "+column+" ") {
				t.Fatal("detail selects nonexistent column", kind, column)
			}
		}
	}
}
