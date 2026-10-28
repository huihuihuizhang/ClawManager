package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

type verificationDetailFixture struct {
	*checkEvidenceFixture
	times                  []driver.Value
	reports                map[string][]driver.Value
	timeError, reportError bool
	beforeDetail           func()
	detailQueries          []string
}

func newVerificationDetailFixture() *verificationDetailFixture {
	f := &verificationDetailFixture{checkEvidenceFixture: newCheckEvidenceFixture(VerificationTask), reports: map[string][]driver.Value{}}
	now := f.rows[0][20].(time.Time)
	f.rows[0][11], f.values["status"] = "running", "running"
	f.values["verifier_aggregate_status"], f.values["verifier_warning"], f.values["verifier_skipped"] = "warning", int64(1), int64(1)
	f.times = []driver.Value{int64(1), now.Add(5 * time.Second), now.Add(time.Minute), now, nil}
	for index, prefix := range []string{"health_report_evidence", "verifier_report_evidence"} {
		id := []string{"sev_00000000-0000-4000-8000-000000000020", "sev_00000000-0000-4000-8000-000000000030"}[index]
		f.values[prefix+"_public_id"], f.values[prefix+"_sha256"] = id, strings.Repeat("d", 64)
		f.reports[id] = []driver.Value{"system-backup-evidence.v1", "artifact_verify", f.rows[0][1], strings.Repeat("d", 64), now.Add(6 * time.Second)}
	}
	return f
}

type verificationDetailConnector struct{ f *verificationDetailFixture }

func (c verificationDetailConnector) Driver() driver.Driver { return pageDriver{} }
func (c verificationDetailConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (checkEvidenceConnector{c.f.checkEvidenceFixture}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &verificationDetailConn{Conn: base, f: c.f}, nil
}

type verificationDetailConn struct {
	driver.Conn
	f *verificationDetailFixture
}

func (c *verificationDetailConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *verificationDetailConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	if query != verificationTaskTimesSQL && query != drillTaskTimesSQL && query != backupTaskTimesSQL && query != preflightTaskTimesSQL && query != verificationReportReferenceSQL {
		return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	if f.rechecks != 0 || f.commits != 0 {
		return nil, errors.New("detail query escaped its original authority transaction")
	}
	f.detailQueries = append(f.detailQueries, query)
	if f.beforeDetail != nil {
		f.beforeDetail()
	}
	if query == verificationTaskTimesSQL || query == drillTaskTimesSQL || query == backupTaskTimesSQL || query == preflightTaskTimesSQL {
		if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][1] || f.timeError {
			return nil, errors.New("private times query failure")
		}
		rows := [][]driver.Value{}
		if f.times != nil {
			rows = append(rows, f.times)
		}
		return &pageRows{columns: []string{"version", "heartbeat", "reconcile", "start", "finish"}, values: rows}, nil
	}
	if len(args) != 1 || f.reportError {
		return nil, errors.New("private evidence query failure")
	}
	rows := [][]driver.Value{}
	if row := f.reports[args[0].Value.(string)]; row != nil {
		rows = append(rows, row)
	}
	return &pageRows{columns: []string{"schema", "owner_kind", "owner_id", "hash", "created"}, values: rows}, nil
}

func verificationDetailReader(t *testing.T, f *verificationDetailFixture, probe *readCommitProbe) *Reader {
	t.Helper()
	var connector driver.Connector = verificationDetailConnector{f}
	if probe != nil {
		probe.base = connector
		connector = probe
	}
	database := sql.OpenDB(connector)
	t.Cleanup(func() { database.Close() })
	r, err := NewReader(database, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestVerificationDetailProjectsOneAuthorizedHistoricalObservation(t *testing.T) {
	for _, source := range []string{"backup", "catalog_import"} {
		t.Run(source, func(t *testing.T) {
			f := newVerificationDetailFixture()
			if source == "catalog_import" {
				f.values["source_artifact_type"], f.values["source_public_id"] = source, "sci_00000000-0000-4000-8000-000000000003"
				f.values["artifact_state_before"], f.values["artifact_state_after"] = nil, nil
				f.values["unusable_reason_before"], f.values["unusable_reason_after"] = "verification_pending", "verification_pending"
			}
			got, err := verificationDetailReader(t, f, nil).ReadVerificationDetail(context.Background(), f.rows[0][1].(string))
			if err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != "system-backup-artifact-verification-detail.v1" || got.Task.PublicID != f.rows[0][1] ||
				got.Task.OriginInstallationID != "installation_test" || got.Source.SourceArtifactType != source ||
				got.Execution.CurrentAttemptNumber == nil || *got.Execution.CurrentAttemptNumber != 2 || got.Execution.JobGeneration != nil ||
				got.Execution.LastBusinessProgressAt == nil || *got.Execution.LastBusinessProgressAt != f.rows[0][20].(time.Time).Add(4*time.Second).UTC().Format(time.RFC3339Nano) || got.VerifierSummary.AggregateStatus != "warning" ||
				got.VerifierSummary.Warning != 1 || got.VerifierSummary.Skipped != 1 || got.VerifierSummary.Failed != 0 || got.VerifierSummary.Passed != 0 {
				t.Fatalf("historical attempts or unrelated Job progress changed current projection: %#v", got)
			}
			if got.HealthReportEvidence == nil || got.VerifierSummary.ReportEvidence == nil || got.Task.StartedAt == nil || got.Task.HeartbeatAt == nil || got.Task.NextReconcileAt == nil ||
				got.Task.FailureMessage != nil || got.Task.FinishedAt != nil || (source == "catalog_import") != (got.ArtifactStateAfter == nil) {
				t.Fatal("lost evidence/timestamp bindings or fabricated redacted/nullable fields")
			}
			if f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || f.rechecks != 1 || f.commits != 1 || len(f.detailQueries) != 3 {
				t.Fatal("detail did not use one original authorized snapshot")
			}
			raw, err := json.Marshal(got)
			if err != nil || strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "expected_json") {
				t.Fatal("wire serialization leaked an internal snapshot")
			}
		})
	}
}

func TestVerificationDetailRejectsIncompleteOrInconsistentSources(t *testing.T) {
	for _, fault := range []string{"times_query", "times_missing", "row_version", "start_before_task", "finish_before_start", "bad_timestamp", "aggregate_status", "aggregate_count", "missing_report", "report_query", "report_schema", "report_owner_kind", "report_owner_id", "report_hash", "old_report", "health_restores_usable", "revocation", "commit_failure", "check_owner", "check_hash"} {
		t.Run(fault, func(t *testing.T) {
			f := newVerificationDetailFixture()
			report := f.reports[f.values["health_report_evidence_public_id"].(string)]
			switch fault {
			case "times_query":
				f.timeError = true
			case "times_missing":
				f.times = nil
			case "row_version":
				f.times[0] = int64(2)
			case "start_before_task":
				f.times[3] = f.rows[0][20].(time.Time).Add(-time.Second)
			case "finish_before_start":
				f.times[4] = f.rows[0][20].(time.Time).Add(-time.Second)
			case "bad_timestamp":
				f.times[1] = time.Time{}
			case "aggregate_status":
				f.values["verifier_aggregate_status"] = "passed"
			case "aggregate_count":
				f.values["verifier_warning"] = int64(2)
			case "missing_report":
				delete(f.reports, f.values["health_report_evidence_public_id"].(string))
			case "report_query":
				f.reportError = true
			case "report_schema":
				report[0] = "unknown"
			case "report_owner_kind":
				report[1] = "backup"
			case "report_owner_id":
				report[2] = "sav_00000000-0000-4000-8000-000000000099"
			case "report_hash":
				report[3] = strings.Repeat("e", 64)
			case "old_report":
				report[4] = f.rows[0][20].(time.Time).Add(-time.Second)
			case "health_restores_usable":
				f.values["artifact_state_after"], f.values["usable_after"], f.values["unusable_reason_after"] = "committed", true, "none"
			case "revocation":
				f.finalErr = ErrDenied
			case "commit_failure":
				f.commitErr = errors.New("private commit failure")
			case "check_owner":
				f.bindings[0][6] = "sav_00000000-0000-4000-8000-000000000099"
			case "check_hash":
				f.bindings[0][7] = strings.Repeat("f", 64)
			}
			got, err := verificationDetailReader(t, f, nil).ReadVerificationDetail(context.Background(), f.rows[0][1].(string))
			if err == nil || !reflect.DeepEqual(got, contract.ArtifactVerificationDetailResource{}) {
				t.Fatal("partial detail escaped failed source/authority checks", err)
			}
			if fault != "commit_failure" && f.commits != 0 {
				t.Fatal("failed detail committed")
			}
		})
	}
}

func TestVerificationDetailDiscardsLateCommitAfterRequestCancellation(t *testing.T) {
	f := newVerificationDetailFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := &readCommitProbe{afterCommit: cancel}
	got, err := verificationDetailReader(t, f, probe).ReadVerificationDetail(ctx, f.rows[0][1].(string))
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, contract.ArtifactVerificationDetailResource{}) || probe.commits != 1 {
		t.Fatal("canceled request received committed detail", err)
	}
}

func TestVerificationExecutionKeepsParallelUnitsUnambiguousAndIgnoresHeartbeats(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	s := TaskExecutionSnapshot{attempts: []TaskAttempt{{Number: 1, Phase: "verify", CreatedAt: at}, {Number: 2, Phase: "verify", CreatedAt: at.Add(time.Second)}}}
	s.jobs = []TaskJobObservation{
		{AttemptNumber: 1, Generation: 99, BusinessProgressAt: sql.NullTime{Time: at.Add(time.Hour), Valid: true}},
		{AttemptNumber: 2, Generation: 3, BusinessProgressAt: sql.NullTime{Time: at.Add(2 * time.Second), Valid: true}},
		{AttemptNumber: 2, Generation: 4, BusinessProgressAt: sql.NullTime{Time: at.Add(3 * time.Second), Valid: true}},
	}
	got, current, _, err := verificationExecution(s)
	if err != nil || current != 2 || got.JobGeneration != nil || got.LastBusinessProgressAt == nil || *got.LastBusinessProgressAt != at.Add(3*time.Second).Format(time.RFC3339Nano) {
		t.Fatal("mixed independent generations or historical progress")
	}
	s.jobs = s.jobs[1:2]
	got, _, _, err = verificationExecution(s)
	if err != nil || got.JobGeneration == nil || *got.JobGeneration != 3 {
		t.Fatal("lost singular Job generation")
	}
	s.jobs[0].BusinessProgressAt = sql.NullTime{}
	got, _, _, err = verificationExecution(s)
	if err != nil || got.LastBusinessProgressAt != nil {
		t.Fatal("heartbeat-only observation became business progress")
	}
}
