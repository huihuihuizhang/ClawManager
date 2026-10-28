package control

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
)

func redisFixture() (Task, RedisIntent, recovery.RedisPolicy, redisPlan) {
	task := testTask()
	task.Request.Kind = "drill"
	task.Request.Artifact = "sb-source"
	task.Status = "restoring"
	task.Generation = 2
	task.Owner = "controller"
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	ref := recovery.Reference{ID: "fixture", Version: "v1", SHA256: strings.Repeat("a", 64)}
	i := RedisIntent{Target: recovery.RestoreTarget{ID: "isolated", Namespace: "cm-drill-test", Database: "redis-db-1", Isolation: ref}, Archive: ref, Index: 0, SHA256: strings.Repeat("b", 64)}
	policy := recovery.RedisPolicy{Source: ref, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "functional_test", Prefixes: []string{"fixture:"}, MaxItems: 100, MaxBytes: 10000}
	b, _ := recovery.Marshal(policy)
	return task, i, policy, redisPlan{i.Target, i.Archive, recovery.Hash(b), []string{i.SHA256}}
}
func redisSteps(task Task, p redisPlan) []sqlStep {
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "FROM system_backup_tasks", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}})
	b, _ := recovery.Marshal(p)
	return append(steps, sqlStep{contains: "SELECT plan_json", rows: [][]driver.Value{{b}}})
}
func TestRedisPlanPinsCompleteSequenceAndTargetBeforeAnyWrite(t *testing.T) {
	task, i, policy, p := redisFixture()
	s, script := scriptStore(t, redisSteps(task, p)...)
	j := RedisJournal{s, task}
	if e := j.Begin(context.Background(), i.Target, i.Archive, policy, []string{strings.Repeat("c", 64)}); e == nil || script.writes != 0 {
		t.Fatal("changed plan accepted", e)
	}
}
func TestRedisSentCommitUncertaintyDoesNotPermitResend(t *testing.T) {
	task, i, _, p := redisFixture()
	steps := redisSteps(task, p)
	steps = append(steps, sqlStep{contains: "item_state='request_sent'", rows: [][]driver.Value{{int64(0)}}}, sqlStep{contains: "SET item_state='request_sent'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	steps = append(steps, redisSteps(task, p)...)
	steps = append(steps, sqlStep{contains: "SELECT item_sha256,item_state", rows: [][]driver.Value{{i.SHA256, "request_sent"}}})
	s, script := scriptStore(t, steps...)
	script.loseCommit = true
	j := RedisJournal{s, task}
	if e := j.Sent(context.Background(), i.Target, i.Archive, i.Index, i.SHA256); e == nil {
		t.Fatal("uncertain commit granted write")
	}
	state, e := j.Freeze(context.Background(), i.Target, i.Archive, i.Index, i.SHA256)
	if e != nil || state != "request_sent" || script.writes != 1 {
		t.Fatal(state, e, script.writes)
	}
}

type redisProofFixture struct {
	stop    bool
	changed bool
}

func (f redisProofFixture) Observe(_ context.Context, i RedisIntent) (RedisOutcome, error) {
	if f.changed {
		i.Index++
	}
	return RedisOutcome{Intent: i, Proof: i.Archive, WriterStopped: f.stop, Matched: true}, nil
}
func TestRedisReconcileRequiresStoppedWriterAndExactBinding(t *testing.T) {
	for _, f := range []redisProofFixture{{false, false}, {true, true}} {
		task, i, _, p := redisFixture()
		task.Status = "canceling"
		task.Deadline = 1
		steps := append(redisSteps(task, p), sqlStep{contains: "SELECT item_sha256,item_state", rows: [][]driver.Value{{i.SHA256, "request_sent"}}})
		s, script := scriptStore(t, steps...)
		if e := (RedisJournal{s, task}).Reconcile(context.Background(), i, f); e == nil || script.writes != 0 {
			t.Fatal("weak reconciliation completed", e)
		}
	}
}
func TestRedisReconcileCompletesAfterDeadlineWithPositiveProof(t *testing.T) {
	task, i, _, p := redisFixture()
	task.Status = "canceling"
	task.Deadline = 1
	steps := append(redisSteps(task, p), sqlStep{contains: "SELECT item_sha256,item_state", rows: [][]driver.Value{{i.SHA256, "request_sent"}}})
	steps = append(steps, redisSteps(task, p)...)
	steps = append(steps, sqlStep{contains: "SELECT item_sha256,item_state,skipped", rows: [][]driver.Value{{i.SHA256, "request_sent", false}}}, sqlStep{contains: "SET item_state='completed'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	s, script := scriptStore(t, steps...)
	if e := (RedisJournal{s, task}).Reconcile(context.Background(), i, redisProofFixture{stop: true}); e != nil || script.commits != 1 {
		t.Fatal(e)
	}
}
