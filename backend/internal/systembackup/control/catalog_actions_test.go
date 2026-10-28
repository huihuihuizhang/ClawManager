package control

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
)

func catalogTask() (Task, recovery.Request) {
	t := testTask()
	t.Request.Kind = "backup"
	t.Status = "publishing"
	t.Owner = "controller"
	t.Generation = 1
	t.LeaseUntil = time.Now().Add(time.Hour).UnixMilli()
	t.Deadline = t.LeaseUntil
	b := []byte(`{"fixture":true}`)
	r := recovery.Request{ActionID: "fixture-marker", Key: "_COMMITTED", SHA256: recovery.Hash(b), Size: int64(len(b)), Deadline: t.Deadline, Generation: 1, Condition: "create-if-absent", Payload: b, Target: recovery.Reference{ID: "provider", Version: "v1", SHA256: strings.Repeat("a", 64)}}
	return t, r
}

func TestCatalogActionRequiresAdmissionAndExactPersistedBytes(t *testing.T) {
	task, r := catalogTask()
	j := CatalogActions{Task: task}
	if _, e := j.Prepare(context.Background(), r); e == nil {
		t.Fatal("missing admission admitted")
	}
	raw, _ := recovery.Marshal(r)
	steps := append(workerCommit(task), sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT request_json,action_state", rows: [][]driver.Value{{raw, "request_sent"}}})
	store, script := scriptStore(t, steps...)
	j.Store = store
	j.Admission = func(context.Context, *sql.Tx, Task, recovery.Request) error { return nil }
	r.Payload = []byte(`{"fixture":false}`)
	r.Size = int64(len(r.Payload))
	r.SHA256 = recovery.Hash(r.Payload)
	if _, e := j.Prepare(context.Background(), r); e == nil || script.writes != 0 {
		t.Fatal("frozen request replaced", e)
	}
}

func TestCatalogActionLostSentCommitNeverAuthorizesSend(t *testing.T) {
	task, r := catalogTask()
	raw, _ := recovery.Marshal(r)
	steps := append(workerCommit(task), sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT request_json,action_state", rows: [][]driver.Value{{raw, "prepared"}}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}}, sqlStep{contains: "SET can_cancel=FALSE", affected: 1}, sqlStep{contains: "SET action_state='request_sent'", affected: 1})
	steps = append(steps, workerCommit(task)...)
	store, script := scriptStore(t, steps...)
	script.loseCommit = true
	j := CatalogActions{Store: store, Task: task, Admission: func(context.Context, *sql.Tx, Task, recovery.Request) error { return nil }}
	if e := j.Sent(context.Background(), recovery.Action{Request: r, State: "prepared"}); e == nil || script.commits != 1 {
		t.Fatal("lost commit authorized sending", e)
	}
	// A takeover sees request_sent, even though the earlier sender saw an error.
	script.steps = append(workerCommit(task), sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT request_json,action_state", rows: [][]driver.Value{{raw, "request_sent"}}})
	a, e := j.Prepare(context.Background(), r)
	if e != nil || a.State != "request_sent" || script.writes != 2 {
		t.Fatal("takeover did not preserve read-only reconciliation", e)
	}
}

func TestCatalogActionCancelAndOrdinary404CannotFinalize(t *testing.T) {
	t.Run("canceled-before-send", func(t *testing.T) {
		task, r := catalogTask()
		canceled := task
		canceled.Status = "canceled"
		store, script := scriptStore(t, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(canceled)}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}})
		j := CatalogActions{Store: store, Task: task, Admission: func(context.Context, *sql.Tx, Task, recovery.Request) error {
			t.Fatal("admission after cancellation")
			return nil
		}}
		if e := j.Sent(context.Background(), recovery.Action{Request: r, State: "prepared"}); e == nil || script.writes != 0 {
			t.Fatal("canceled task sent", e)
		}
	})
	t.Run("weak-absence", func(t *testing.T) {
		task, r := catalogTask()
		raw, _ := recovery.Marshal(r)
		steps := append(workerCommit(task), sqlStep{contains: "SELECT request_json,action_state", rows: [][]driver.Value{{raw, "request_sent"}}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}})
		store, script := scriptStore(t, steps...)
		j := CatalogActions{Store: store, Task: task}
		if e := j.Observe(context.Background(), recovery.Action{Request: r, State: "request_sent"}, "absent", recovery.Observation{State: "absent", Key: r.Key}); e == nil || script.writes != 0 {
			t.Fatal("ordinary 404 finalized", e)
		}
	})
}
