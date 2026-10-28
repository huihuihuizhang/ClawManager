package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
)

func guardFixture(t *testing.T) (Task, FrozenPrune, []recovery.PruneArtifact) {
	task := testTask()
	task.Owner = "owner"
	task.Generation = 2
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	n := time.Now().UnixMilli()
	group := recovery.RecoveryGroup{Origin: "isolated-origin", Matrix: "k8s-cluster", FailureDomain: "fixture"}
	rows := []recovery.PruneArtifact{}
	for i, id := range []string{"old", "new"} {
		record := scannedFixture(t, id)
		r := record.Record.Registration
		rows = append(rows, recovery.PruneArtifact{ID: id, Group: group, Terminal: true, FinishedAt: n - 10000 + int64(i)*1000, CommittedAt: n - 10000 + int64(i)*1000, State: "committed", HistoricalEligible: true, Locator: r.Locator, Core: r.Core, GuardVersion: 1, RegistrationID: record.Record.ID, RegistrationSHA256: record.Object.SHA256})
	}
	plan, e := recovery.PlanRetention(n, 1000, 1, []recovery.RecoveryGroup{group}, rows, recovery.Reference{ID: "retention", Version: "v1", SHA256: strings.Repeat("a", 64)})
	if e != nil || len(plan.Candidates) != 1 {
		t.Fatal(plan, e)
	}
	return task, FrozenPrune{ID: "prune-test", CreatedAt: n, ExpiresAt: task.Deadline, Retention: 1000, Minimum: 1, Groups: []recovery.RecoveryGroup{group}, Plan: plan}, rows
}
func guardSteps(task Task) []sqlStep {
	return append(workerCommit(task), sqlStep{contains: "recovery_mutex", rows: [][]driver.Value{{int64(1)}}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}})
}
func guardRow(a recovery.PruneArtifact) sqlStep {
	b, _ := recovery.Marshal(a)
	return sqlStep{contains: "SELECT artifact_json", rows: [][]driver.Value{{b}}}
}
func pruneRow(p FrozenPrune, state string) sqlStep {
	b, _ := recovery.Marshal(p)
	return sqlStep{contains: "SELECT plan_json,run_state", rows: [][]driver.Value{{b, state}}}
}
func TestPruneClaimRechecksHoldsAndUnreleasedExpiredLeases(t *testing.T) {
	for _, mode := range []string{"hold", "expired-lease", "newer-guard"} {
		t.Run(mode, func(t *testing.T) {
			task, p, rows := guardFixture(t)
			leases := int64(0)
			if mode == "hold" {
				rows[0].ManualHold = true
			}
			if mode == "expired-lease" {
				leases = 1
			}
			if mode == "newer-guard" {
				rows[0].GuardVersion++
			}
			values := [][]driver.Value{}
			for i, a := range rows {
				b, _ := recovery.Marshal(a)
				l := int64(0)
				if i == 0 {
					l = leases
				}
				values = append(values, []driver.Value{b, l})
			}
			steps := append(guardSteps(task), pruneRow(p, "prepared"), sqlStep{contains: "FROM system_backup_recovery_guards g", rows: values})
			store, script := scriptStore(t, steps...)
			if e := (RecoveryGuards{store, task}).ClaimPrune(context.Background(), p); e == nil || script.writes != 0 {
				t.Fatal("stale candidate claimed", mode, e)
			}
		})
	}
}

func TestPruneClaimFreezesAllCandidatesBeforeAnyProviderCall(t *testing.T) {
	task, p, rows := guardFixture(t)
	values := [][]driver.Value{}
	for _, a := range rows {
		b, _ := recovery.Marshal(a)
		values = append(values, []driver.Value{b, int64(0)})
	}
	steps := append(guardSteps(task), pruneRow(p, "prepared"), sqlStep{contains: "FROM system_backup_recovery_guards g", rows: values}, sqlStep{contains: "UPDATE system_backup_recovery_guards", affected: 1, checkArgs: func(args []driver.NamedValue) {
		var a recovery.PruneArtifact
		if json.Unmarshal(args[0].Value.([]byte), &a) != nil || a.State != "deleting" || a.GuardVersion != 2 {
			t.Fatal("candidate not claimed")
		}
	}}, sqlStep{contains: "INSERT INTO system_backup_v2_prune_items", affected: 1}, sqlStep{contains: "SET run_state='claimed'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	s, script := scriptStore(t, steps...)
	if e := (RecoveryGuards{s, task}).ClaimPrune(context.Background(), p); e != nil || script.commits != 1 {
		t.Fatal(e)
	}
}

func TestPruneFreezeIsIdempotentAndRejectsPolicyReplacement(t *testing.T) {
	task, p, _ := guardFixture(t)
	raw, _ := recovery.Marshal(p)
	s, script := scriptStore(t, append(guardSteps(task), sqlStep{contains: "SELECT plan_json", rows: [][]driver.Value{{raw}}})...)
	if _, e := (RecoveryGuards{s, task}).FreezePrune(context.Background(), p.ID, p.Retention, p.Minimum+1, p.Groups, p.Plan.Config); e == nil || script.writes != 0 {
		t.Fatal("changed retention policy accepted", e)
	}
}
func TestRestoreLeaseCannotEnterClaimedDeletion(t *testing.T) {
	task, _, rows := guardFixture(t)
	task.Request.Kind = "drill"
	task.Request.Artifact = "sb-source"
	rows[0].State = "deleting"
	store, script := scriptStore(t, append(guardSteps(task), guardRow(rows[0]))...)
	if _, e := (RecoveryGuards{store, task}).Acquire(context.Background(), rows[0].ID, time.Minute); e == nil || script.writes != 0 {
		t.Fatal("restore raced delete", e)
	}
}

type pruneProviderFixture struct{ deletes, observations int }

func (p *pruneProviderFixture) Delete(context.Context, PruneDispatch) (PruneObservation, error) {
	p.deletes++
	return PruneObservation{}, ErrNotReady
}
func (p *pruneProviderFixture) Observe(context.Context, PruneDispatch) (PruneObservation, error) {
	p.observations++
	return PruneObservation{}, ErrNotReady
}
func TestPruneUnknownWriteIsObservedNeverResent(t *testing.T) {
	task, p, _ := guardFixture(t)
	a := p.Plan.Candidates[0]
	a.State = "deleting"
	a.GuardVersion++
	d := PruneDispatch{Run: p.ID, CandidateSHA256: p.Plan.SHA256, FirstActor: "1", Artifact: a, Deadline: p.ExpiresAt}
	raw, _ := recovery.Marshal(d)
	steps := append(guardSteps(task), pruneRow(p, "claimed"))
	steps = append(steps, guardSteps(task)...)
	steps = append(steps, sqlStep{contains: "SELECT dispatch_json,item_state", rows: [][]driver.Value{{raw, "request_sent"}}})
	store, script := scriptStore(t, steps...)
	provider := &pruneProviderFixture{}
	result, e := (RecoveryGuards{store, task}).ExecutePrune(context.Background(), p, provider)
	if e == nil || !result.Pending || provider.deletes != 0 || provider.observations != 1 || script.writes != 0 {
		t.Fatal(result, e, provider)
	}
}
func TestPruneLostDispatchCommitDoesNotSend(t *testing.T) {
	task, p, _ := guardFixture(t)
	a := p.Plan.Candidates[0]
	a.State = "deleting"
	a.GuardVersion++
	d := PruneDispatch{Run: p.ID, CandidateSHA256: p.Plan.SHA256, FirstActor: "1", Artifact: a, Deadline: p.ExpiresAt}
	raw, _ := recovery.Marshal(d)
	steps := append(guardSteps(task), pruneRow(p, "claimed"))
	steps = append(steps, guardSteps(task)...)
	steps = append(steps, sqlStep{contains: "SELECT dispatch_json,item_state", rows: [][]driver.Value{{raw, "prepared"}}}, sqlStep{contains: "SET item_state='request_sent'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	store, script := scriptStore(t, steps...)
	script.loseCommit = true
	provider := &pruneProviderFixture{}
	if _, e := (RecoveryGuards{store, task}).ExecutePrune(context.Background(), p, provider); e == nil || provider.deletes != 0 {
		t.Fatal("sent after uncertain SQL commit", e)
	}
}
func TestPruneAbortCannotClearUnresolvedDispatch(t *testing.T) {
	task, p, _ := guardFixture(t)
	steps := append(guardSteps(task), pruneRow(p, "claimed"), sqlStep{contains: "item_state<>'prepared'", rows: [][]driver.Value{{int64(1)}}})
	s, script := scriptStore(t, steps...)
	if e := (RecoveryGuards{s, task}).AbortPrune(context.Background(), p); e == nil || script.writes != 0 {
		t.Fatal("canceled unknown remote delete", e)
	}
}

type stopLeaseFixture struct{ stopped bool }

func (f stopLeaseFixture) VerifyStopped(_ context.Context, l RecoveryLease) (LeaseStopProof, error) {
	return LeaseStopProof{Lease: l, Stopped: f.stopped, Evidence: recovery.Reference{ID: "stop", Version: "v1", SHA256: strings.Repeat("a", 64)}}, nil
}
func TestLeaseReleaseRequiresPositiveStopProof(t *testing.T) {
	task, _, _ := guardFixture(t)
	g := RecoveryGuards{Task: task}
	l := RecoveryLease{Artifact: "old", Task: task.ID, Consumer: "task", Generation: task.Generation}
	if e := g.Release(context.Background(), l, stopLeaseFixture{}); e == nil {
		t.Fatal("expiry treated as stop")
	}
}
func TestPruneCompletionBindsExactIdentityAndAllVersions(t *testing.T) {
	task, p, _ := guardFixture(t)
	a := p.Plan.Candidates[0]
	a.State = "deleting"
	a.GuardVersion++
	d := PruneDispatch{Run: p.ID, CandidateSHA256: p.Plan.SHA256, FirstActor: "1", Artifact: a, Deadline: p.ExpiresAt}
	out := PruneObservation{Dispatch: d, AllVersionsAbsent: true, WriterStopped: true, Evidence: recovery.Reference{ID: "absent", Version: "v1", SHA256: strings.Repeat("a", 64)}, DeletedAt: time.Now().UnixMilli()}
	raw, _ := recovery.Marshal(d)
	steps := append(guardSteps(task), sqlStep{contains: "SELECT dispatch_json,item_state", rows: [][]driver.Value{{raw, "request_sent"}}}, guardRow(a), sqlStep{contains: "UPDATE system_backup_recovery_guards", affected: 1}, sqlStep{contains: "SET item_state='completed'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	s, script := scriptStore(t, steps...)
	if e := (RecoveryGuards{s, task}).confirm(context.Background(), d, out); e != nil || script.commits != 1 {
		t.Fatal(e)
	}
	out.WriterStopped = false
	if e := (RecoveryGuards{}).confirm(context.Background(), d, out); e == nil {
		t.Fatal("late writer ignored")
	}
}
