package systembackupbusinessa

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func reportTargetFixture() ReportTarget {
	n := int64(1)
	return ReportTarget{Type: "drill", PublicID: "sdr_11111111-2222-4333-8444-555555555555", AttemptNo: &n}
}

func TestVerificationReportsBackupAndMismatch(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	target := reportTargetFixture()
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "equal", true: "record_deleted"}[mismatch], func(t *testing.T) {
			current := dump
			current.Snapshot = cloneSourceSnapshot(dump.Snapshot)
			if mismatch {
				current.Snapshot.Tables[len(current.Snapshot.Tables)-1].Rows--
			}
			reports, err := VerifyBackupReports(context.Background(), target, scope, source, current, &proofFixture{})
			if mismatch != errors.Is(err, ErrSnapshotMismatch) || !mismatch && err != nil {
				t.Fatal("wrong verification outcome", err)
			}
			if len(reports.Users.Checks) != 8 || len(reports.AIGateway.Checks) != 12 {
				t.Fatal("incomplete report")
			}
			check := reports.Users.Checks[len(reports.Users.Checks)-1]
			if mismatch && (check.Status != "failed" || check.Expected["rows"] != int64(2) || check.Actual["rows"] != int64(1)) {
				t.Fatal("report lost exact record-count difference", check)
			}
			assertReportEnvelope(t, reports, "backup_validate")
		})
	}
	got, err := VerifyBackupReports(context.Background(), target, scope, source, dump, &proofFixture{err: ErrSnapshotMismatch})
	if !errors.Is(err, ErrSnapshotMismatch) || !reflect.DeepEqual(got, VerificationReports{}) {
		t.Fatal("proof error masqueraded as a completed mismatch report")
	}
}

func assertReportEnvelope(t *testing.T, reports VerificationReports, mode string) {
	t.Helper()
	for _, report := range []VerificationReport{reports.Users, reports.AIGateway} {
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil || len(document) != 7 {
			t.Fatal("v12 envelope field set", err, string(raw))
		}
		for _, key := range []string{"schema_version", "target_type", "target_public_id", "attempt_no", "category", "mode", "checks"} {
			if _, ok := document[key]; !ok {
				t.Fatal("missing envelope field", key)
			}
		}
		if report.SchemaVersion != "system-backup-verifier-result.v1" || report.Mode != mode {
			t.Fatal("wrong envelope profile")
		}
	}
}

func TestVerificationReportsRestoreDifferencesAndFailures(t *testing.T) {
	scope, expected := restoreFixture(t)
	for _, name := range []string{"equal", "money", "tokens", "record_deleted", "sql_failure", "final_proof_failure"} {
		t.Run(name, func(t *testing.T) {
			state, proof := &countState{}, &restoreProofFixture{}
			group := fixtureCostGroup(2)
			switch name {
			case "money":
				group.EstimatedCost = "0.00000001"
			case "tokens":
				group.TotalTokens = "1"
			case "record_deleted":
				state.counts = map[string]int64{"users": 1}
			case "sql_failure":
				state.failure = "cost-query"
			case "final_proof_failure":
				proof.endErr = errors.New("target authority revoked")
			}
			if name == "money" || name == "tokens" {
				state.costRows = func() driver.Rows { return costSQLRows(group) }
			}
			v := SQLRestoreVerifier{DB: countDB(t, state), Proof: proof}
			target := reportTargetFixture()
			reports, err := v.VerifyRestoreReports(context.Background(), target, scope, expected, "sev_restored")
			if name == "sql_failure" || name == "final_proof_failure" {
				if err == nil || !reflect.DeepEqual(reports, VerificationReports{}) || state.commits != 0 {
					t.Fatal("incomplete verification returned report", err)
				}
				return
			}
			if name == "equal" && err != nil || name != "equal" && !errors.Is(err, ErrRestoreNormalizationMismatch) {
				t.Fatal("wrong outcome", err)
			}
			failed := 0
			for _, check := range allCategoryChecks(CategoryChecks{Users: reports.Users.Checks, AIGateway: reports.AIGateway.Checks}) {
				if check.Status == "failed" {
					failed++
					if name == "record_deleted" && (check.ID != "users.restore_count.users" || check.Expected["rows"] != int64(2) || check.Actual["rows"] != int64(1)) {
						t.Fatal("record difference missing", check)
					}
					if name != "record_deleted" && (check.ID != "ai_gateway.restore_cost_aggregates" || check.Expected["hash"] == check.Actual["hash"]) {
						t.Fatal("cost/token difference missing", check)
					}
				}
			}
			if name == "equal" && failed != 0 || name != "equal" && failed != 1 {
				t.Fatal("wrong failed check count", failed)
			}
			assertReportEnvelope(t, reports, "restore_validate")
			*target.AttemptNo = 99
			if *reports.Users.AttemptNo != 1 || *reports.AIGateway.AttemptNo != 1 {
				t.Fatal("caller mutated report attempt")
			}
		})
	}
}

func TestVerificationReportsRejectInvalidTargetBeforeSQL(t *testing.T) {
	scope, expected := restoreFixture(t)
	for _, target := range []ReportTarget{{}, {Type: "drill", PublicID: "../report"}, {Type: "backup", PublicID: reportTargetFixture().PublicID}, {Type: "drill", PublicID: reportTargetFixture().PublicID, AttemptNo: new(int64)}} {
		state := &countState{}
		reports, err := (SQLRestoreVerifier{DB: countDB(t, state), Proof: &restoreProofFixture{}}).VerifyRestoreReports(context.Background(), target, scope, expected, "sev_restored")
		if err == nil || len(state.queries) != 0 || !reflect.DeepEqual(reports, VerificationReports{}) {
			t.Fatal("invalid target reached SQL")
		}
	}
}

type reportMutatingProof struct{ mutate func() }

func (p reportMutatingProof) VerifyCapture(context.Context, CaptureEvidence, CaptureEvidence) error {
	p.mutate()
	return nil
}

func TestVerificationReportTargetCannotChangeDuringProof(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	target := reportTargetFixture()
	reports, err := VerifyBackupReports(context.Background(), target, scope, source, dump, reportMutatingProof{mutate: func() { *target.AttemptNo = 0 }})
	if err != nil || *reports.Users.AttemptNo != 1 || *reports.AIGateway.AttemptNo != 1 {
		t.Fatal("proof callback changed task attempt in report", err)
	}
}
