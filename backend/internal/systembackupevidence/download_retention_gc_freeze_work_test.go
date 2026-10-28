package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"testing"
	"time"
)

func TestDownloadGCFinalizerProtectedCandidate(t *testing.T) {
	for _, mode := range []string{"commit", "clock_advance", "worker_claim", "worker_fence", "worker_deadline", "authority", "early_reference", "direct_reference", "grant_revoked", "capacity", "capacity_overflow", "capacity_sample", "clock_backwards", "clock_intermediate_rollback", "until_equality", "config", "envelope", "tombstone", "absent_key", "callback_changes_worker"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			c := &gcFrozenWorkConn{retentionGCModel: f.d}
			beforeRows := cloneGCEarlyRows([][]driver.Value{f.d.m.op, f.d.m.receipt, f.d.nonce, f.d.resultRetention})
			beforeBody, beforeResult := append([]byte(nil), f.d.body...), append([]byte(nil), f.d.resultBody...)
			beforeReserved, beforeEvidence := f.d.reserved, f.d.record
			beforeSample, beforeReport := f.d.sample, f.p.report
			queriesAtTicket := 0
			lastWorkClockAdvanced := false
			if mode == "clock_intermediate_rollback" || mode == "clock_advance" {
				c.beforeQuery = func(q string) {
					// Advance only the LAST work clock, after the independent
					// absence checks. An earlier captured floor would miss a
					// post-ticket value strictly between the two work samples.
					if q == downloadIntentClockSQL && !c.ticketObserved && len(f.d.queries) > 0 && f.d.queries[len(f.d.queries)-1] == "SELECT id FROM audit_logs WHERE id=?" {
						f.d.now = f.d.now.Add(2 * time.Microsecond)
						lastWorkClockAdvanced = true
					}
				}
			}
			c.afterTicket = func() {
				queriesAtTicket = len(f.d.queries)
				switch mode {
				case "worker_claim":
					f.d.worker[6] = "other-worker"
				case "worker_fence":
					f.d.worker[8] = int64(8)
				case "worker_deadline":
					f.d.worker[9] = f.d.now.Add(time.Hour)
				case "authority":
					f.policy.denyGuard = true
				case "early_reference":
					f.d.early.refs = append(f.d.early.refs, []driver.Value{int64(6), int64(9000), int64(1730)})
				case "direct_reference":
					r := f.d.direct.initial[0]
					f.d.direct.refs[gcTaskRangeKey(r.query, r.args...)] = [][]driver.Value{{int64(9001)}}
				case "grant_revoked":
					f.d.early.grants = f.d.early.grants[1:]
				case "capacity":
					// Recheck pins the ORIGINAL physical sample; it reads the
					// retained SQL reservation, not a replacement report file.
					f.d.reserved = 0
				case "capacity_overflow":
					f.d.reserved = 1 << 60
				case "capacity_sample":
					f.d.sample = f.d.sample.Add(time.Microsecond)
				case "clock_backwards":
					f.d.now = f.d.now.Add(-time.Microsecond)
				case "clock_intermediate_rollback":
					f.d.now = f.d.now.Add(-time.Microsecond)
				case "clock_advance":
					f.d.now = f.d.now.Add(time.Microsecond)
				case "until_equality":
					// ConfigMutationCapacity's original bound is observed+5s.
					f.d.now = f.p.report.ObservedAt.Add(5 * time.Second)
				case "config":
					f.d.activeConfig = 2
				case "envelope":
					f.d.record.RowVersion++
				case "tombstone":
					f.d.stone[1] = "other-installation"
				case "absent_key":
					f.d.resurrectKey = true
				case "callback_changes_worker":
					f.policy.onCheck = func(int) { f.d.worker[6] = "late-callback-worker" }
				}
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			out, err := f.s.collectFrozenCandidate(ctx, downloadGCFreezeConfig{Connector: gcFrozenWorkConnector{c}, Server: c.identity.ServerUUID, Database: c.identity.Database, Account: "gc-fixture@%", WaitSeconds: 1, Admit: func(context.Context, *sql.Conn) error { return nil }}, f.operation)
			if !c.ticketObserved || len(f.d.writes) == 0 || c.connections != 1 || c.begins != 1 || c.releases != 1 || !out.DiscardRequested || out.Unlock != "confirmed" || f.d.active {
				t.Fatalf("candidate did not reach final ticket on sole owned tx: %v %+v", err, out)
			}
			if (mode == "clock_intermediate_rollback" || mode == "clock_advance") && !lastWorkClockAdvanced {
				t.Fatal("fixture did not advance the final work SQL sample")
			}
			if !reflect.DeepEqual(f.p.report, beforeReport) {
				t.Fatal("original physical sample was replaced or renewed")
			}
			if mode == "commit" || mode == "clock_advance" {
				if err != nil || out.Transaction != "committed" || f.d.commits != f.commits+1 || f.d.rollbacks != f.rollbacks || len(f.d.m.op) != 0 || len(f.d.stone) != 23 || !reflect.DeepEqual(f.d.record, beforeEvidence) {
					t.Fatalf("captured finalizer did not commit complete deletion: %v %+v", err, out)
				}
				// The independent worker check and final clock must occur AFTER
				// ticket observation, with no second acquisition/transaction.
				workerAfter := false
				for _, query := range f.d.queries[queriesAtTicket:] {
					workerAfter = workerAfter || query == downloadGCWorkerSQL
				}
				if !workerAfter || f.d.queries[len(f.d.queries)-1] != downloadIntentClockSQL {
					t.Fatal("final business guards did not follow ticket")
				}
			} else {
				afterRows := [][]driver.Value{f.d.m.op, f.d.m.receipt, f.d.nonce, f.d.resultRetention}
				if err == nil || out.Transaction != "rolled_back" || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || f.d.reserved != beforeReserved || !f.d.sample.Equal(beforeSample) || !reflect.DeepEqual(f.d.record, beforeEvidence) || !reflect.DeepEqual(beforeRows, afterRows) || !reflect.DeepEqual(beforeBody, f.d.body) || !reflect.DeepEqual(beforeResult, f.d.resultBody) {
					t.Fatalf("post-ticket failure escaped exact shared rollback: %v %+v", err, out)
				}
			}
		})
	}
}

func TestDownloadGCFinalizerCapturedFactsCannotBeRebound(t *testing.T) {
	for _, mode := range []string{"wrong_tx", "wrong_collector", "wrong_scope", "unrelated_context"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			owned, now, err := beginDownloadGCConnection(f.ctx, f.s.c.Registry)
			if err != nil {
				t.Fatal(err)
			}
			defer owned.close()
			peer, err := pinnedPeerExpiry(f.ctx, f.s, f.s.roots, f.s.c.CertificateSHA256, f.s.c.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			var captured *downloadGCWorkFinalizer
			if err := f.s.collectProtectedWork(f.ctx, owned.tx, f.operation, peer, now, &captured); err != nil || captured == nil {
				t.Fatal("real work failed to issue completion", err)
			}
			ctx, tx, collector, operation := f.ctx, owned.tx, f.s, f.operation
			switch mode {
			case "wrong_tx":
				tx = new(sql.Tx)
			case "wrong_collector":
				copy := *f.s
				collector = &copy
			case "wrong_scope":
				operation = f.s.c.OperationID
			case "unrelated_context":
				ctx = context.Background()
			}
			beforeQueries := len(f.d.queries)
			copy := *captured
			if captured.finish(ctx, tx, collector, operation) == nil || copy.finish(f.ctx, owned.tx, f.s, f.operation) == nil || len(f.d.queries) != beforeQueries || f.d.commits != f.commits {
				t.Fatal("caller rebound original facts or replayed failed capability")
			}
		})
	}
}
