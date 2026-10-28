package systembackupbusinessa

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

func TestSQLBackupReporterReadsBothActualViews(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	// Deliberately false request counts must never become a passing SQL report.
	source.Snapshot.Tables[0].Rows = 999
	dump.Snapshot.Tables[0].Rows = 999
	for _, name := range []string{"equal", "money", "tokens", "record_deleted", "source_failure", "target_failure", "proof_failure"} {
		t.Run(name, func(t *testing.T) {
			sourceState, targetState := &countState{}, &countState{}
			proof := &proofFixture{}
			group := fixtureCostGroup(2)
			switch name {
			case "money":
				group.EstimatedCost = "0.00000001"
			case "tokens":
				group.TotalTokens = "1"
			case "record_deleted":
				targetState.counts = map[string]int64{"users": 1}
			case "source_failure":
				sourceState.failure = "count:users"
			case "target_failure":
				targetState.failure = "cost-query"
			case "proof_failure":
				proof.err = errors.New("capture source not authenticated")
			}
			if name == "money" || name == "tokens" {
				targetState.costRows = func() driver.Rows { return costSQLRows(group) }
			}
			v := SQLBackupReporter{SourceDB: countDB(t, sourceState), TargetDB: countDB(t, targetState), Proof: proof}
			reports, err := v.VerifyReports(context.Background(), reportTargetFixture(), scope, source, dump)
			if name == "source_failure" || name == "target_failure" || name == "proof_failure" {
				if err == nil || !reflect.DeepEqual(reports, VerificationReports{}) {
					t.Fatal("failed SQL/proof returned reports", err)
				}
				if name == "source_failure" && len(targetState.queries) != 0 {
					t.Fatal("target read after failed source read")
				}
				return
			}
			if sourceState.commits != 1 || targetState.commits != 1 || !sourceState.begin.ReadOnly || !targetState.begin.ReadOnly || proof.calls != 1 {
				t.Fatal("did not collect and authenticate both actual views")
			}
			failed := 0
			auditCountSeen := false
			for _, check := range allCategoryChecks(CategoryChecks{Users: reports.Users.Checks, AIGateway: reports.AIGateway.Checks}) {
				if check.ID == "ai_gateway.table_count.audit_events" {
					auditCountSeen = true
					if check.Expected["rows"] != int64(2) || check.Actual["rows"] != int64(2) {
						t.Fatal("request-supplied counts reached report", check)
					}
				}
				if check.Status == "failed" {
					failed++
					if name == "record_deleted" && (check.ID != "users.table_count.users" || check.Expected["rows"] != int64(2) || check.Actual["rows"] != int64(1)) {
						t.Fatal("wrong record-count report", check)
					}
					if name != "record_deleted" && check.ID != "ai_gateway.cost_aggregates" {
						t.Fatal("wrong cost report", check)
					}
				}
			}
			if name == "equal" && (err != nil || failed != 0) || name != "equal" && (!errors.Is(err, ErrSnapshotMismatch) || failed != 1) {
				t.Fatal("wrong comparison result", failed, err)
			}
			if !auditCountSeen {
				t.Fatal("actual table count missing from report")
			}
		})
	}
}

func TestSQLBackupReporterRequiresDistinctAuthorizedViews(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	state := &countState{}
	db := countDB(t, state)
	v := SQLBackupReporter{SourceDB: db, TargetDB: db, Proof: &proofFixture{}}
	got, err := v.VerifyReports(context.Background(), reportTargetFixture(), scope, source, dump)
	if err == nil || !reflect.DeepEqual(got, VerificationReports{}) || len(state.queries) != 0 {
		t.Fatal("same view used as its own independent comparison")
	}
	v.TargetDB, v.Proof = countDB(t, &countState{}), nil
	if _, err := v.VerifyReports(context.Background(), reportTargetFixture(), scope, source, dump); err == nil || len(state.queries) != 0 {
		t.Fatal("missing capture authority reached SQL")
	}
}
