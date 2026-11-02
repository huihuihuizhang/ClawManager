//go:build systembackup_mysql

package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Uses the existing original task/real TLS SQL/actual public composition and
// encrypted C/CE flow. Its Kubernetes/provider fixture is not a field acceptance
// proof; there is no injected successful source-recovery/proof callback.
func TestSourceRecoveryActualPublicCaptureProducerCompositionMySQL(t *testing.T) {
	runDOriginalSixPartCaptureValidated(t, false, true, func(ctx context.Context, f *dOriginalSixPartTask, work c.ExecutionWork, results []d.ModuleResult) {
		inner, err := d.UnwrapTaskPlan(work.Input, work.Plan, b.PlanVersion)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(inner.CanonicalJSON)
		desc, err := b.DescribePlan(work.Input, inner)
		if err != nil {
			t.Fatal(err)
		}
		var expectedResultSHA string
		if f.control.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='capture_result'`, f.publicID, work.Input.Authority.AttemptNo).Scan(&expectedResultSHA) != nil {
			t.Fatal("actual original result digest")
		}
		rows, err := f.control.QueryContext(ctx, `SELECT content_checksum,inline_payload FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND public_id LIKE 'sev=_source=_recovery=_%' ESCAPE '=' ORDER BY public_id`, f.publicID)
		if err != nil {
			t.Fatal("original recovery evidence query")
		}
		defer rows.Close()
		rootCount, writerCount := 0, 0
		seen := map[string]bool{}
		for rows.Next() {
			var digest string
			var raw []byte
			var record struct {
				Version, WriterID, CaptureResultSHA256, FrozenControlSHA256, SourceSHA256 string
				WriterCount                                                               int
			}
			if rows.Scan(&digest, &raw) != nil || digest != hash(raw) || json.Unmarshal(raw, &record) != nil || record.CaptureResultSHA256 != expectedResultSHA || record.SourceSHA256 != desc.SourceSHA256 || !formalCandidateDigest(record.FrozenControlSHA256) {
				t.Fatal("durable original result/source/control binding")
			}
			switch record.Version {
			case "original-source-recovery.v1":
				rootCount++
				if record.WriterCount != len(desc.Writers) {
					t.Fatal("incomplete original writer set")
				}
			case "original-source-recovery-writer.v1":
				writerCount++
				if seen[record.WriterID] {
					t.Fatal("duplicate original writer leaf")
				}
				seen[record.WriterID] = true
			default:
				t.Fatal("unexpected original recovery record")
			}
		}
		if rows.Err() != nil || rootCount != 1 || writerCount != len(desc.Writers) {
			t.Fatal("complete physical producer evidence did not join validating")
		}
		for _, writer := range desc.Writers {
			if !seen[writer.ID] {
				t.Fatal("original writer missing")
			}
		}
	})
}

func TestSourceRecoveryOriginalProviderFailureRetainsPhysicalRecoveryMySQL(t *testing.T) {
	// Existing helper verifies original source-resume and failed-outcome facts.
	// Mandatory successful-capture proof must not replace that original path.
	runDOriginalSixPartCapture(t, true, true)
}
