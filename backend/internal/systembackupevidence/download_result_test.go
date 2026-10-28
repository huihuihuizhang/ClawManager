package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func resultFixture(t *testing.T, f *admissionTxFixture) *SQLDownloadResults {
	r, _ := resultFixtureWithReportSampler(t, f)
	return r
}

// The result audit is a separate operation with its own current capacity
// observation. Sampling does not renew admission, proof or provider limits.
func resultFixtureWithReportSampler(t *testing.T, f *admissionTxFixture) (*SQLDownloadResults, func(time.Time) error) {
	t.Helper()
	reportPath := filepath.Join(t.TempDir(), "synthetic-result-capacity.json")
	sample := func(at time.Time) error {
		raw, err := json.Marshal(sec.CapacityReport{ServerUUID: f.db.identity.ServerUUID, Database: f.db.identity.Database, ObservedAt: at, AllocatedBytes: 1048576, AvailableBytes: 1099511627776})
		if err != nil {
			return err
		}
		return os.WriteFile(reportPath, raw, 0600)
	}
	if err := sample(f.db.now); err != nil {
		t.Fatal(err)
	}
	capacity, err := sec.NewConfigMutationCapacity(f.db.identity, reportPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSQLDownloadResults(SQLDownloadResultsConfig{Registry: f.service.registry, Owners: &admissionPinnedOwners{f: f}, Capacity: capacity, MeasuredReservationBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	return r, sample
}

func TestDownloadResultActualIDOriginalGroupAndRevokedSession(t *testing.T) {
	for _, mode := range []string{"local_write_complete", "interrupted", "rejected", "revoked", "expired_download", "new_current_config", "other_claim", "version_ceiling"} {
		t.Run(mode, func(t *testing.T) {
			f, _, c := committedFixture(t)
			if mode == "version_ceiling" {
				f, _, c = committedConfiguredFixture(t, func(f *admissionTxFixture) { f.initial.RowVersion = 9007199254740990 })
			}
			r := resultFixture(t, f)
			op, receipt, nonce := append([]driver.Value(nil), f.db.m.op...), append([]driver.Value(nil), f.db.m.receipt...), append([]driver.Value(nil), f.db.nonce...)
			intent := append([]byte(nil), f.db.body...)
			start, end, _ := c.Range()
			o := DownloadResultObservation{Outcome: "local_write_complete", BytesWritten: end - start + 1}
			switch mode {
			case "interrupted":
				o = DownloadResultObservation{Outcome: mode, BytesWritten: 3}
			case "rejected":
				o = DownloadResultObservation{Outcome: mode}
			case "revoked":
				f.db.sessionRevoked = true
				f.db.userActive = false
				f.db.revokedBefore = f.db.now
				c.fail()
			case "expired_download":
				c.localDeadline = time.Now().Add(-time.Second)
				c.fail()
			case "new_current_config":
				f.db.activeConfig = 2
			case "other_claim":
				f.db.record.Claim = "aev_" + strings.Repeat("f", 32)
				f.db.record.RowVersion++
			}
			if err := r.Finish(context.Background(), c, o); err != nil {
				t.Fatal("result", err, f.db.queries)
			}
			if f.db.resultInserts != 1 || f.db.inserts != 1 || f.db.commits != 2 || f.db.reserved != 65536+8192 || f.db.resultCreated.Nanosecond() != 0 {
				t.Fatal("incorrect independent effects")
			}
			if !reflect.DeepEqual(op, f.db.m.op) || !reflect.DeepEqual(receipt, f.db.m.receipt) || !reflect.DeepEqual(nonce, f.db.nonce) || !bytes.Equal(intent, f.db.body) {
				t.Fatal("result modified admission/intent/nonce")
			}
			if mode == "other_claim" {
				if f.db.record.Claim == c.record.Claim || f.db.record.Claim == "" {
					t.Fatal("released another claim")
				}
			} else if mode == "version_ceiling" {
				if f.db.record.Claim != c.record.Claim || f.db.record.RowVersion != c.record.RowVersion {
					t.Fatal("unsafe row version overflow")
				}
			} else if f.db.record.Claim != "" || f.db.record.RowVersion != c.record.RowVersion+1 {
				t.Fatal("original claim not released")
			}
			var body map[string]any
			if json.Unmarshal(f.db.resultBody, &body) != nil || len(body) != 15 || body["operation_public_id"] != c.operationID || body["intent_audit_id"] != float64(c.intentAuditID) || body["claim_sha256"] != hash([]byte(c.record.Claim)) || body["outcome"] != o.Outcome || body["bytes_written"] != float64(o.BytesWritten) {
				t.Fatal("result correlation/closed body")
			}
			for _, private := range []string{c.record.Claim, f.request.Header.Get("Authorization"), f.request.Header.Get(sec.StrongAuthProofHeader), f.proof.Payload.Nonce, c.record.Ref.RelativeKey} {
				if private != "" && bytes.Contains(f.db.resultBody, []byte(private)) {
					t.Fatal("private input persisted")
				}
			}
			before := len(f.db.queries)
			copyCap := *c
			if r.Finish(context.Background(), &copyCap, o) == nil || len(f.db.queries) != before {
				t.Fatal("result repeated through copy")
			}
		})
	}
}

func TestDownloadResultFailuresRollbackAndNeverRetry(t *testing.T) {
	for _, fault := range []string{"result_actor", "result_insert", "result_zero", "result_id", "result_read", "result_body", "result_time", "release_sql", "release_multiple", "release_not_applied", "operation_read", "nonce_read", "capacity_report"} {
		t.Run(fault, func(t *testing.T) {
			f, _, c := committedFixture(t)
			r := resultFixture(t, f)
			before := c.Record()
			reserved := f.db.reserved
			if fault == "operation_read" {
				f.db.m.fault = fault
			} else if fault == "capacity_report" {
				r.c.Capacity, _ = sec.NewConfigMutationCapacity(f.db.identity, filepath.Join(t.TempDir(), "missing.json"), 1)
			} else {
				f.db.fault = fault
			}
			if r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "rejected"}) == nil {
				t.Fatal("failure accepted")
			}
			if f.db.commits != 1 || len(f.db.resultBody) != 0 || len(f.db.resultRetention) != 0 || f.db.record.Claim != before.Claim || f.db.record.RowVersion != before.RowVersion || f.db.reserved != reserved || len(f.db.nonce) != 16 || len(f.db.m.op) != 14 {
				t.Fatal("partial result/release survived rollback")
			}
			queries := len(f.db.queries)
			if r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "rejected"}) == nil || len(f.db.queries) != queries {
				t.Fatal("result failure retried")
			}
		})
	}
}

func TestDownloadResultUnknownCommitIsTerminal(t *testing.T) {
	f, _, c := committedFixture(t)
	r := resultFixture(t, f)
	f.db.commitUnknown = true
	if err := r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted"}); err != ErrDownloadResultCommitUnknown {
		t.Fatal(err)
	}
	if f.db.resultInserts != 1 || len(f.db.resultBody) == 0 || len(f.db.resultRetention) != 11 || f.db.record.Claim != "" || len(f.db.nonce) != 16 {
		t.Fatal("unknown commit was replayed or original admission erased")
	}
	before := len(f.db.queries)
	if r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted"}) == nil || len(f.db.queries) != before {
		t.Fatal("unknown commit retried")
	}
}

func TestDownloadResultRejectsInvalidObservationBeforeSQL(t *testing.T) {
	for _, mode := range []string{"sent", "negative", "excess", "short_complete", "rejected_bytes", "nil_context", "wrong_database"} {
		t.Run(mode, func(t *testing.T) {
			f, _, c := committedFixture(t)
			r := resultFixture(t, f)
			o := DownloadResultObservation{Outcome: "rejected"}
			ctx := context.Background()
			switch mode {
			case "sent":
				o.Outcome = "sent"
			case "negative":
				o.BytesWritten = -1
			case "excess":
				o.Outcome = "interrupted"
				o.BytesWritten = MaxResponse + 1
			case "short_complete":
				o.Outcome = "local_write_complete"
				o.BytesWritten = 1
			case "rejected_bytes":
				o.BytesWritten = 1
			case "nil_context":
				ctx = nil
			case "wrong_database":
				r.c.Registry.Database += "_other"
			}
			before := len(f.db.queries)
			if r.Finish(ctx, c, o) == nil || len(f.db.queries) != before {
				t.Fatal("invalid result reached SQL")
			}
		})
	}
}
