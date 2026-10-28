//go:build systembackup_mysql

package systembackupbusinessa

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

// The existing isolated migrated fixture supplies the database and read proof.
// Only counts, aggregate hashes and inert-state violations enter this log.
type businessReportSQLVerifier struct {
	SQLRestoreVerifier
	t *testing.T
}

func (v businessReportSQLVerifier) VerifyRestoreTarget(ctx context.Context, scope *CaptureScope, expected SourceSnapshot, evidenceRef string) (CategoryChecks, error) {
	reports, err := v.SQLRestoreVerifier.VerifyRestoreReports(ctx, reportTargetFixture(), scope, expected, evidenceRef)
	checks := CategoryChecks{Users: reports.Users.Checks, AIGateway: reports.AIGateway.Checks}
	if len(checks.Users) != 0 || len(checks.AIGateway) != 0 {
		body, marshalErr := json.Marshal(reports)
		if marshalErr != nil {
			v.t.Fatal("encode actual SQL check reports", marshalErr)
		}
		v.t.Logf("A_BUSINESS_REPORT_JSON %s", body)
	}
	return checks, err
}

func businessReportRecordDeletion(t *testing.T, ctx context.Context, database *sql.DB, verifier businessReportSQLVerifier, scope *CaptureScope, expected SourceSnapshot, evidenceRef string, cases []businessSQLRow) {
	t.Helper()
	var quota *businessSQLRow
	for i := range cases {
		if cases[i].table == "user_quotas" {
			quota = &cases[i]
			break
		}
	}
	if quota == nil {
		t.Fatal("quota fixture missing")
	}
	result, err := database.ExecContext(ctx, "DELETE FROM user_quotas WHERE id=?", quota.values["id"])
	if err != nil {
		t.Fatal("delete exact owned quota fixture", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		t.Fatal("record injection did not delete one row", n, err)
	}
	checks, err := verifier.VerifyRestoreTarget(ctx, scope, expected, evidenceRef)
	if !errors.Is(err, ErrRestoreNormalizationMismatch) {
		t.Fatal("deleted record did not fail report", err)
	}
	failures := 0
	for _, check := range allCategoryChecks(checks) {
		if check.Status == "failed" {
			failures++
			if check.ID != "users.restore_count.user_quotas" || check.Expected["rows"] != int64(1) || check.Actual["rows"] != int64(0) {
				t.Fatal("deleted record difference was misreported", check)
			}
		}
	}
	if failures != 1 {
		t.Fatal("report must identify exactly one deleted-record difference", failures)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertBusinessSQLRow(ctx, tx, *quota); err != nil {
		t.Fatal("restore exact quota fixture", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal("commit restored quota fixture", err)
	}
	if _, err := verifier.VerifyRestoreTarget(ctx, scope, expected, evidenceRef); err != nil {
		t.Fatal("restored fixture did not pass report", err)
	}
}
