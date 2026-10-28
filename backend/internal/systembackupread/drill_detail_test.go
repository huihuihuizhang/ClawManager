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

func newDrillDetailFixture() *verificationDetailFixture {
	f := &verificationDetailFixture{checkEvidenceFixture: newCheckEvidenceFixture(DrillTask), reports: map[string][]driver.Value{}}
	now := f.rows[0][20].(time.Time)
	f.rows[0][11], f.values["status"] = "restoring", "restoring"
	f.values["verifier_aggregate_status"], f.values["verifier_warning"], f.values["verifier_skipped"] = "warning", int64(1), int64(1)
	f.times = []driver.Value{int64(1), now.Add(5 * time.Second), now.Add(time.Minute), now, nil}
	for i, prefix := range []string{"preflight_evidence", "diff_evidence", "verifier_report_evidence"} {
		id := []string{"sev_00000000-0000-4000-8000-000000000020", "sev_00000000-0000-4000-8000-000000000030", "sev_00000000-0000-4000-8000-000000000040"}[i]
		f.values[prefix+"_public_id"], f.values[prefix+"_sha256"] = id, strings.Repeat("d", 64)
		f.reports[id] = []driver.Value{"system-backup-evidence.v1", "drill", f.rows[0][1], strings.Repeat("d", 64), now.Add(6 * time.Second)}
	}
	f.values["source_manifest_checksum"] = strings.Repeat("b", 64)
	return f
}

func TestDrillDetailHistoricalProjectionAndOriginalAuthority(t *testing.T) {
	for _, source := range []string{"backup", "catalog_import"} {
		t.Run(source, func(t *testing.T) {
			f := newDrillDetailFixture()
			if source == "catalog_import" {
				f.values["source_artifact_type"], f.values["source_public_id"] = source, "sci_00000000-0000-4000-8000-000000000003"
			}
			got, err := verificationDetailReader(t, f, nil).ReadDrillDetail(context.Background(), f.rows[0][1].(string))
			if err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != "system-backup-drill-detail.v1" || got.Task.TaskType != "drill" || got.Task.OriginInstallationID != "installation_test" ||
				got.Source.SourceArtifactType != source || got.Execution.CurrentAttemptNumber == nil || *got.Execution.CurrentAttemptNumber != 2 ||
				got.Execution.CurrentPhase == nil || *got.Execution.CurrentPhase != "restore" || got.Execution.JobGeneration != nil ||
				got.Execution.LastBusinessProgressAt == nil || *got.Execution.LastBusinessProgressAt != f.rows[0][20].(time.Time).Add(4*time.Second).Format(time.RFC3339Nano) ||
				got.VerifierSummary.AggregateStatus != "warning" || got.VerifierSummary.Warning != 1 || got.VerifierSummary.Skipped != 1 || got.VerifierSummary.Failed != 0 || got.VerifierSummary.Passed != 0 {
				t.Fatal("historical retry/Job progress polluted current drill projection")
			}
			if got.PreflightEvidence == nil || got.DiffEvidence == nil || got.VerifierSummary.ReportEvidence == nil || got.SourceChecksums.Manifest == nil ||
				got.SourceChecksums.Index != nil || got.SourceChecksums.Marker != nil || got.Task.FailureMessage != nil || got.Consistency != nil || got.AcceptanceEligible ||
				got.TargetProfile != "cluster" || got.CleanupPolicy != "delete-on-success" || got.CleanupStatus != "not_started" || got.CleanupFailureCode != "none" || got.Task.StartedAt == nil {
				t.Fatal("fabricated current health, target content or missing historical field")
			}
			if f.rechecks != 1 || f.commits != 1 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || len(f.detailQueries) != 4 {
				t.Fatal("escaped original authorized snapshot")
			}
			raw, err := json.Marshal(got)
			if err != nil || strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "restore_target_config_ref") || strings.Contains(string(raw), "expected_json") {
				t.Fatal("internal/raw data leaked")
			}
		})
	}
}

func TestDrillDetailRejectsUnboundOrInconsistentHistory(t *testing.T) {
	for _, mode := range []string{"times_query", "times_missing", "version", "zero_time", "start_before_task", "finish_before_start", "aggregate_status", "aggregate_count",
		"report_query", "missing_report", "report_schema", "report_owner", "report_kind", "report_hash", "report_old", "shared_ref_hash", "shared_ref_old",
		"old_verifier_report", "cleanup_failure", "eligibility_cleanup", "revocation", "commit", "check_hash", "check_owner", "missing_task", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newDrillDetailFixture()
			id := f.rows[0][1].(string)
			now := f.rows[0][20].(time.Time)
			report := f.reports[f.values["verifier_report_evidence_public_id"].(string)]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "times_query":
				f.timeError = true
			case "times_missing":
				f.times = nil
			case "version":
				f.times[0] = int64(2)
			case "zero_time":
				f.times[1] = time.Time{}
			case "start_before_task":
				f.times[3] = now.Add(-time.Second)
			case "finish_before_start":
				f.times[4] = now.Add(-time.Second)
			case "aggregate_status":
				f.values["verifier_aggregate_status"] = "passed"
			case "aggregate_count":
				f.values["verifier_warning"] = int64(2)
			case "report_query":
				f.reportError = true
			case "missing_report":
				delete(f.reports, f.values["verifier_report_evidence_public_id"].(string))
			case "report_schema":
				report[0] = "unknown"
			case "report_owner":
				report[2] = "sdr_00000000-0000-4000-8000-000000000099"
			case "report_kind":
				report[1] = "backup"
			case "report_hash":
				report[3] = strings.Repeat("e", 64)
			case "report_old":
				report[4] = now.Add(-time.Second)
			case "shared_ref_hash":
				f.values["diff_evidence_public_id"] = f.values["preflight_evidence_public_id"]
				f.values["diff_evidence_sha256"] = strings.Repeat("e", 64)
			case "shared_ref_old":
				f.attempts[1][7] = now.Add(2 * time.Second)
				f.attempts[1][9] = now.Add(2 * time.Second)
				f.attempts[1][10] = now.Add(2 * time.Second)
				f.values["verifier_report_evidence_public_id"] = f.values["preflight_evidence_public_id"]
				f.reports[f.values["preflight_evidence_public_id"].(string)][4] = now.Add(time.Second)
			case "old_verifier_report":
				f.attempts[1][7] = now.Add(2 * time.Second)
				f.attempts[1][9] = now.Add(2 * time.Second)
				f.attempts[1][10] = now.Add(2 * time.Second)
				report[4] = now.Add(time.Second)
			case "cleanup_failure":
				f.values["cleanup_status"] = "failed"
				f.values["cleanup_failure_code"] = "none"
			case "eligibility_cleanup":
				f.values["acceptance_eligible"] = true
			case "revocation":
				f.finalErr = ErrDenied
			case "commit":
				f.commitErr = errors.New("PRIVATE commit error")
			case "check_hash":
				f.bindings[0][7] = strings.Repeat("e", 64)
			case "check_owner":
				f.bindings[0][6] = "sdr_00000000-0000-4000-8000-000000000099"
			case "missing_task":
				f.missingTask = true
				f.rows = nil
			case "cancel":
				f.beforeDetail = cancel
			}
			got, err := verificationDetailReader(t, f, nil).ReadDrillDetail(ctx, id)
			if err == nil || !reflect.DeepEqual(got, contract.DrillDetailResource{}) {
				t.Fatal("partial/untrusted history escaped", err)
			}
			if mode != "commit" && mode != "missing_task" && f.commits != 0 {
				t.Fatal("failed builder committed")
			}
			if mode == "missing_task" && (!errors.Is(err, ErrNotFound) || f.rechecks != 1 || f.checkQueries != 0) {
				t.Fatal("authorized miss boundary lost")
			}
		})
	}
}

func TestDrillDetailHistoricalReferencesCanPredateRetry(t *testing.T) {
	f := newDrillDetailFixture()
	now := f.rows[0][20].(time.Time)
	f.attempts[1][7] = now.Add(2 * time.Second)
	f.attempts[1][9] = now.Add(2 * time.Second)
	f.attempts[1][10] = now.Add(2 * time.Second)
	f.reports[f.values["preflight_evidence_public_id"].(string)][4] = now.Add(time.Second)
	f.reports[f.values["diff_evidence_public_id"].(string)][4] = now.Add(time.Second)
	if _, err := verificationDetailReader(t, f, nil).ReadDrillDetail(context.Background(), f.rows[0][1].(string)); err != nil {
		t.Fatal("immutable preflight/diff lost across retry", err)
	}
}

func TestDrillDetailPostCommitCancellationReturnsNothing(t *testing.T) {
	f := newDrillDetailFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := &readCommitProbe{afterCommit: cancel}
	got, err := verificationDetailReader(t, f, probe).ReadDrillDetail(ctx, f.rows[0][1].(string))
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, contract.DrillDetailResource{}) || probe.commits != 1 {
		t.Fatal("late canceled result escaped", err)
	}
}

func TestDrillExecutionKeepsPhaseAndJobAmbiguity(t *testing.T) {
	at := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	s := TaskExecutionSnapshot{attempts: []TaskAttempt{{Number: 1, Phase: "restore", CreatedAt: at}, {Number: 2, Phase: "restore", CreatedAt: at.Add(time.Second)}, {Number: 2, Phase: "normalize", CreatedAt: at.Add(2 * time.Second)}}}
	s.jobs = []TaskJobObservation{{AttemptNumber: 1, Generation: 99, BusinessProgressAt: sql.NullTime{Time: at.Add(time.Hour), Valid: true}}, {AttemptNumber: 2, Generation: 3, BusinessProgressAt: sql.NullTime{Time: at.Add(3 * time.Second), Valid: true}}}
	got, current, start, err := drillExecution(s)
	if err != nil || current != 2 || got.CurrentPhase != nil || got.JobGeneration != nil || !start.Equal(at.Add(2*time.Second)) || got.LastBusinessProgressAt == nil || *got.LastBusinessProgressAt != at.Add(3*time.Second).Format(time.RFC3339Nano) {
		t.Fatal("invented a phase/generation or included old progress")
	}
	s.attempts = s.attempts[:2]
	got, _, _, err = drillExecution(s)
	if err != nil || got.CurrentPhase == nil || *got.CurrentPhase != "restore" || got.JobGeneration == nil || *got.JobGeneration != 3 {
		t.Fatal("lost singular phase/Job")
	}
	s.jobs = append(s.jobs, TaskJobObservation{AttemptNumber: 2, Generation: 4})
	got, _, _, err = drillExecution(s)
	if err != nil || got.JobGeneration != nil {
		t.Fatal("merged independent Job generations")
	}
	s.jobs = nil
	got, _, _, err = drillExecution(s)
	if err != nil || got.LastBusinessProgressAt != nil {
		t.Fatal("heartbeat became progress")
	}
	got, current, _, err = drillExecution(TaskExecutionSnapshot{})
	if err != nil || current != 0 || got.CurrentAttemptNumber != nil || got.CurrentPhase != nil {
		t.Fatal("fabricated attempt")
	}
}
