package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/worker"
)

func restartFixture() (SourceRestarter, flow.State) {
	task, _, _ := grantFixture()
	task.Request.Kind = "backup"
	task.Request.Artifact = ""
	task.Status = "capturing"
	j := PauseJournal{Task: task, Identity: flow.Identity{Task: task.ID, Attempt: "capture", Generation: 1, Phase: "capture"}, Writers: []string{"gateway/1"}}
	return SourceRestarter{Journal: j, Writer: "gateway/1", Binding: SourceBinding{Database: "source", ServerUUID: "source-uuid", InstanceID: 1, UserID: 2, Generation: 3, Mode: "lite", PodName: "runtime", Namespace: "source", PodUID: "pod-uid", GatewayID: "gw-1-3", Port: 10001, RuntimePodID: 7, UsedSlots: 4, Workspace: "/workspace/1"}}, flow.State{UID: "pod-uid", Generation: 3, Running: true, Checkpoint: "frozen"}
}
func drainedSteps(task Task) []sqlStep {
	steps := workerCommit(task)
	return append(steps, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT task_id,closed,hold_until_ms", rows: [][]driver.Value{{task.ID, true, task.Deadline}}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}}, sqlStep{contains: "SELECT COUNT(*) FROM system_backup_mutations", rows: [][]driver.Value{{int64(0)}}})
}
func restartSteps(r SourceRestarter, s flow.State, sent bool, result []byte) []sqlStep {
	registry, _ := r.Journal.registry()
	raw, _ := json.Marshal(s)
	steps := workerCommit(r.Journal.Task)
	steps = append(steps, sqlStep{contains: "SELECT registry_json", rows: [][]driver.Value{{registry}}})
	steps = append(steps, drainedSteps(r.Journal.Task)...)
	steps = append(steps, sqlStep{contains: "SELECT " + pendingWorkersSQL, rows: [][]driver.Value{{int64(0)}}}, sqlStep{contains: "SELECT original_json,restart_dispatched,restart_result", rows: [][]driver.Value{{raw, sent, result}}}, sqlStep{contains: "SELECT @@server_uuid", rows: [][]driver.Value{{r.Binding.ServerUUID}}})
	gen := int64(3)
	if sent {
		gen++
	}
	bindingGen := int64(3)
	gateway := "gw-1-3"
	if len(result) > 0 {
		bindingGen++
		gateway = "gw-1-4"
	}
	return append(steps, sqlStep{contains: "FROM `source`.instances", rows: [][]driver.Value{{int64(2), gen, "lite", "running", "runtime", "source"}}}, sqlStep{contains: "FROM `source`.instance_runtime_bindings", rows: [][]driver.Value{{int64(7), gateway, int64(10001), "/workspace/1", "running", bindingGen}}}, sqlStep{contains: "FROM `source`.runtime_pods", rows: [][]driver.Value{{"pod-uid", int64(4)}}})
}
func TestSourceRestartGenerationAndDispatchCommitTogether(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "dispatch-CAS-failure"}[fail], func(t *testing.T) {
			r, s := restartFixture()
			if !r.valid() {
				t.Fatalf("invalid fixture: %+v", r.Binding)
			}
			steps := restartSteps(r, s, false, nil)
			affected := int64(1)
			if fail {
				affected = 0
			}
			steps = append(steps, sqlStep{contains: "UPDATE `source`.instances SET runtime_generation", affected: 1}, sqlStep{contains: "SET restart_dispatched=TRUE", affected: affected})
			if !fail {
				steps = append(steps, drainedSteps(r.Journal.Task)...)
			}
			store, script := scriptStore(t, steps...)
			r.Journal.Store = store
			claimed, e := r.Claim(context.Background(), s)
			if fail {
				if e == nil || claimed || script.commits != 0 {
					t.Fatal("partial claim committed", e)
				}
			} else if e != nil || !claimed || script.commits != 1 {
				t.Fatal("claim failed", e)
			}
			if len(script.steps) != 0 {
				t.Fatal("unconsumed SQL")
			}
		})
	}
}
func TestSourceRestartRetryDoesNotReserveAnotherGenerationOrSlot(t *testing.T) {
	r, s := restartFixture()
	if !r.valid() {
		t.Fatalf("invalid fixture: %+v", r.Binding)
	}
	steps := append(restartSteps(r, s, true, nil), drainedSteps(r.Journal.Task)...)
	store, script := scriptStore(t, steps...)
	r.Journal.Store = store
	claimed, e := r.Claim(context.Background(), s)
	if e != nil || claimed || script.writes != 0 || len(script.steps) != 0 {
		t.Fatal("restart replay mutated generation or slots", e)
	}
}
func TestSourceBindingCompletionAndDurableReceiptShareTransaction(t *testing.T) {
	r, s := restartFixture()
	if !r.valid() {
		t.Fatalf("invalid fixture: %+v", r.Binding)
	}
	steps := restartSteps(r, s, true, nil)
	steps = append(steps, sqlStep{contains: "UPDATE `source`.instance_runtime_bindings SET gateway_id=?,generation=?", affected: 1}, sqlStep{contains: "UPDATE system_backup_pauses SET restart_result=?", affected: 1})
	steps = append(steps, drainedSteps(r.Journal.Task)...)
	store, script := scriptStore(t, steps...)
	r.Journal.Store = store
	if e := r.Complete(context.Background(), s, RestartResult{PodUID: "pod-uid", GatewayID: "gw-1-4", Port: 10001}); e != nil || script.commits != 1 || script.writes != 2 || len(script.steps) != 0 {
		t.Fatal("binding completion", e)
	}
}
func TestSourceRestartRejectsWrongSlotIdentityBeforeWrite(t *testing.T) {
	r, s := restartFixture()
	if !r.valid() {
		t.Fatalf("invalid fixture: %+v", r.Binding)
	}
	steps := restartSteps(r, s, false, nil)
	steps[len(steps)-1].rows = [][]driver.Value{{"replacement-pod", int64(4)}}
	store, script := scriptStore(t, steps...)
	r.Journal.Store = store
	if claimed, e := r.Claim(context.Background(), s); e == nil || claimed || script.writes != 0 {
		t.Fatal("replacement inherited source identity")
	}
}
func TestExpiredWorkerRecordRemainsReadableButCannotAcquire(t *testing.T) {
	_, g, r := grantFixture()
	g.Invocation.Request.Deadline = time.Now().Add(-time.Minute)
	if !validWorker(g) {
		t.Fatal("expired immutable grant cannot be cleaned")
	}
	r.Invocation = g.Invocation
	r.InvocationSHA256, _ = g.Invocation.Hash()
	if worker.ValidateControl(r) {
		t.Fatal("expired worker can acquire")
	}
}

func TestRecoveryPreservesOriginallyStoppedGatewayWithoutGenerationClaim(t *testing.T) {
	r, s := restartFixture()
	s.Running = false
	steps := append(restartSteps(r, s, false, nil), drainedSteps(r.Journal.Task)...)
	store, script := scriptStore(t, steps...)
	r.Journal.Store = store
	if e := r.Guard(context.Background(), true, s); e != nil || script.writes != 0 {
		t.Fatal("cannot preserve original stopped gateway", e)
	}
	if _, e := r.Claim(context.Background(), s); e == nil {
		t.Fatal("allocated generation for stopped gateway")
	}
}
