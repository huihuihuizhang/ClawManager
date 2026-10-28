package systembackupevidence

import (
	"fmt"
	"testing"
	"time"
)

func TestGCObservationResultAndPersistedBackoff(t *testing.T) {
	for _, mode := range []string{"ok", "no_proof", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			x := newGCRuntimeFixture(t, mode)
			now := x.db.plan[8].values[0].(time.Time)
			old := recoveryTestObservation{health: "degraded", checked: now.Add(-time.Minute), next: now.Add(-time.Second)}
			x.db.observation = old
			x.policy.afterAudit = func(int) {
				if x.db.observation != old || x.db.pendingObservation != old {
					t.Fatal("claim, authorization or audit manufactured an observation")
				}
			}
			r, err := NewGCRuntime(x.c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(x.f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			id := x.db.record.Manifest.Identity.ID
			result := r.GC(ctx, []string{id})[0]
			got := x.db.observation
			wantHealth := "unknown"
			if mode == "mismatch" {
				wantHealth = "degraded"
			}
			if got.health != wantHealth || !got.checked.Equal(now) || len(x.db.audits) != 2 {
				t.Fatal("GC result and observation diverged", got, result)
			}
			if mode == "ok" {
				if result != nil || !got.next.IsZero() || x.db.record.State != "deleted" {
					t.Fatal("successful absence retained retry/healthy state", got, result)
				}
			} else if result == nil || !got.next.Equal(now.Add(time.Minute)) || x.db.record.State != "delete_failed" {
				t.Fatal("failure lost bounded retry", got, result)
			}
			before := x.exchanges.Load()
			writes := x.db.writes
			x.policy.afterAudit = nil
			again := r.GC(ctx, []string{id})[0]
			if mode == "ok" && again != nil || mode != "ok" && again != ErrConflict {
				t.Fatal("direct retry bypassed scheduling or tombstone failed", again)
			}
			if x.exchanges.Load() != before || x.db.writes != writes || len(x.db.audits) != 2 || x.db.observation != got {
				t.Fatal("backoff/tombstone replay changed provider or observation")
			}
		})
	}
}

func TestGCObservationRollsBackWithFailedResult(t *testing.T) {
	for _, mode := range []string{"claim_audit", "claim_expiry", "result_audit", "result_expiry", "chunks", "revoke_in_proof", "revoke_before_result", "result_cas", "commit"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := mode
			if mode == "result_cas" || mode == "commit" {
				fixtureMode = "no_proof"
			}
			x := newGCRuntimeFixture(t, fixtureMode)
			now := x.db.plan[8].values[0].(time.Time)
			old := recoveryTestObservation{health: "degraded", checked: now.Add(-2 * time.Minute), next: now.Add(-time.Minute)}
			x.db.observation = old
			if mode == "result_cas" {
				x.db.failWrite = 2
			}
			if mode == "commit" {
				x.policy.afterAudit = func(call int) {
					if call == 2 {
						x.db.commitErr = true
					}
				}
			}
			r, err := NewGCRuntime(x.c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(x.f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			if r.GC(ctx, []string{x.db.record.Manifest.Identity.ID})[0] == nil || x.db.observation != old || len(x.db.audits) > 1 || x.db.record.Ref == (Ref{}) {
				t.Fatal("failed transaction committed observation or lost reference", x.db.observation)
			}
		})
	}
}

func TestGCSchedulingDueTimeEnforcedUnderClaimLock(t *testing.T) {
	for _, delta := range []time.Duration{-time.Microsecond, 0, time.Microsecond, time.Minute} {
		t.Run(delta.String(), func(t *testing.T) {
			x := newGCRuntimeFixture(t, "ok")
			now := x.db.plan[8].values[0].(time.Time)
			x.db.observation = recoveryTestObservation{health: "unknown", checked: now.Add(-time.Minute), next: now.Add(delta)}
			old := x.db.observation
			r, err := NewGCRuntime(x.c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(x.f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			result := r.GC(ctx, []string{x.db.record.Manifest.Identity.ID})[0]
			if delta > 0 {
				if result != ErrConflict || x.db.writes != 0 || x.exchanges.Load() != 0 || x.db.observation != old || len(x.db.audits) != 0 {
					t.Fatal("future candidate bypassed backoff", result)
				}
			} else if result != nil || x.db.record.State != "deleted" {
				t.Fatal("due candidate rejected", result)
			}
		})
	}
}

func TestGCRetryPolicyValidatedBeforeClaimAndProvider(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 4, 5, 600, 601, 1 << 62} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			x := newGCRuntimeFixture(t, "no_proof")
			x.db.plan[3].values[5] = seconds
			r, err := NewGCRuntime(x.c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(x.f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			result := r.GC(ctx, []string{x.db.record.Manifest.Identity.ID})[0]
			if seconds < 5 || seconds > 600 {
				if result != ErrDenied || x.db.writes != 0 || x.exchanges.Load() != 0 || len(x.db.audits) != 0 {
					t.Fatal("invalid retry policy reached side effects", result)
				}
			} else {
				now := x.db.plan[8].values[0].(time.Time)
				if result == nil || !x.db.observation.next.Equal(now.Add(time.Duration(seconds)*time.Second)) || x.db.record.State != "delete_failed" {
					t.Fatal("wrong persisted retry interval", result, x.db.observation)
				}
			}
		})
	}
}
