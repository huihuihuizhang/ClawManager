package systembackupread

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"

	contract "clawreef/internal/systembackupcontract"
)

func newUnstartedDetailFixture(kind TaskKind) *verificationDetailFixture {
	f := &verificationDetailFixture{checkEvidenceFixture: newCheckEvidenceFixture(kind), reports: map[string][]driver.Value{}}
	f.attempts, f.jobs, f.checks, f.bindings = nil, nil, nil, nil
	f.times = []driver.Value{int64(1), nil, nil, nil, nil}
	return f
}

func TestBackupDetailUnstartedDoesNotInventExecutionOrSuccess(t *testing.T) {
	f := newUnstartedDetailFixture(BackupTask)
	got, err := verificationDetailReader(t, f, nil).ReadBackupDetail(context.Background(), f.rows[0][1].(string))
	if err != nil {
		t.Fatal(err)
	}
	if got.Task.Status != "pending" || got.ArtifactUsable || got.AcceptanceReady || got.AcceptanceEligible || got.Consistency != nil || got.Execution.CurrentAttemptNumber != nil || got.Checksums.Manifest != nil || got.VerifierSummary.Passed != 0 {
		t.Fatal("unstarted task acquired fabricated execution evidence")
	}
	if got.SchemaVersion != "system-backup-backup-detail.v1" || len(got.RequestedParts) != 6 || f.rechecks != 1 || f.commits != 1 {
		t.Fatal("incomplete projection or authority")
	}
}

func TestPreflightDetailUnstartedAndRevocation(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		f := newUnstartedDetailFixture(PreflightTask)
		if revoked {
			f.finalErr = ErrDenied
		}
		got, err := verificationDetailReader(t, f, nil).ReadPreflightDetail(context.Background(), f.rows[0][1].(string))
		if revoked {
			if !errors.Is(err, ErrDenied) || !reflect.DeepEqual(got, contract.PreflightDetailResource{}) {
				t.Fatal("revoked detail escaped")
			}
		} else if err != nil || got.Task.Status != "pending" || got.ReportValidityReason != "pending" || got.ReportEvidence != nil || got.Execution.CurrentAttemptNumber != nil {
			t.Fatal(got, err)
		}
	}
}
