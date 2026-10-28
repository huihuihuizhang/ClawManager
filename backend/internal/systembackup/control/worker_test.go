package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

type countingKeys struct{ calls int }

type unwrapFunc func(context.Context, staging.Binding, artifact.WrappedKey) ([]byte, error)

func (f unwrapFunc) Unwrap(ctx context.Context, b staging.Binding, k artifact.WrappedKey) ([]byte, error) {
	return f(ctx, b, k)
}

func (k *countingKeys) Unwrap(context.Context, staging.Binding, artifact.WrappedKey) ([]byte, error) {
	k.calls++
	return make([]byte, 32), nil
}

func grantFixture() (Task, WorkerGrant, worker.ControlRequest) {
	deadline := time.Now().Add(time.Minute)
	task := Task{ID: "sb-test", Request: Request{Kind: "drill", Profile: "fixture", Artifact: "sb-source", Purpose: "functional_test"}, ProfileRevision: strings.Repeat("a", 64), CanCancel: true, Status: "restoring", Owner: "controller", Generation: 1, RowVersion: 1, Deadline: deadline.UnixMilli(), LeaseUntil: deadline.UnixMilli()}
	invocation := worker.Invocation{WorkspacePath: "/workspace", StagingPath: "/staging", Request: worker.Request{Version: worker.Version, Operation: "restore-workspace", Deadline: deadline, Binding: staging.Binding{BackupID: "sb-source"}, MaxFiles: 10, MaxFileBytes: 1024, MaxArchiveBytes: 2048, MaxCompressedBytes: 2048, Receipt: staging.Receipt{Name: "workspace.enc", Size: 100, SHA256: strings.Repeat("b", 64)}}}
	g := WorkerGrant{TaskID: task.ID, ProfileRevision: task.ProfileRevision, SPIFFE: "spiffe://fixture/worker/one", JobNamespace: "cm-drill", JobName: "restore", JobUID: "uid-one", Invocation: invocation, Key: artifact.WrappedKey{Version: "v1", Nonce: make([]byte, 12), Ciphertext: make([]byte, 48)}}
	hash, _ := invocation.Hash()
	return task, g, worker.ControlRequest{Invocation: invocation, InvocationSHA256: hash, Action: "acquire"}
}
func workerSteps(task Task, g WorkerGrant, result []byte, expires int64) []sqlStep {
	raw, _ := json.Marshal(g)
	timestamp := time.Now().UnixMilli()
	return []sqlStep{
		{contains: "WHERE spiffe_uri=?", rows: [][]driver.Value{{raw}}},
		{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}},
		{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}},
		{contains: "SELECT " + dbNow, rows: [][]driver.Value{{timestamp}}},
		{contains: "SELECT uid,lifecycle,dispatched", rows: [][]driver.Value{{g.JobUID, "created", true}}},
		{contains: "SELECT grant_json,ready,revoked", rows: [][]driver.Value{{raw, true, false, expires, result}}},
		{contains: "SELECT " + dbNow, rows: [][]driver.Value{{timestamp}}},
	}
}
func workerCommit(task Task) []sqlStep {
	return []sqlStep{{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, {contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}}}
}

func TestWorkerAcquireCannotReleaseKeyWhenGrantCASFails(t *testing.T) {
	task, g, r := grantFixture()
	steps := append(workerSteps(task, g, nil, 0), sqlStep{contains: "SET acquired_until_ms=?", affected: 0})
	store, script := scriptStore(t, steps...)
	keys := &countingKeys{}
	a := WorkerAuthorizer{Store: store, Keys: keys, Lifetime: time.Minute, ValidateLive: func(context.Context, WorkerGrant, string) error { return nil }}
	lease, e := a.Authorize(context.Background(), g.SPIFFE, r)
	if e != worker.ErrNotReady || len(lease.DEK) != 0 || keys.calls != 0 || script.commits != 0 {
		t.Fatal("grant write failure released a key", e)
	}
}
func TestWorkerCompletionIsImmutableAndRetryable(t *testing.T) {
	for _, scenario := range []string{"first", "repeat", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			task, g, r := grantFixture()
			r.Action = "complete"
			r.Result = &worker.Result{Quarantined: true, Receipt: g.Invocation.Request.Receipt, Files: 2}
			var old []byte
			if scenario != "first" {
				copy := *r.Result
				if scenario == "conflict" {
					copy.Files++
				}
				old, _ = json.Marshal(copy)
			}
			steps := workerSteps(task, g, old, time.Now().Add(30*time.Second).UnixMilli())
			if scenario == "first" {
				steps = append(steps, sqlStep{contains: "SET result_json=?", affected: 1})
			}
			if scenario != "conflict" {
				steps = append(steps, workerCommit(task)...)
			}
			store, script := scriptStore(t, steps...)
			keys := &countingKeys{}
			a := WorkerAuthorizer{Store: store, Keys: keys, Lifetime: time.Minute, ValidateLive: func(context.Context, WorkerGrant, string) error { return nil }}
			lease, e := a.Authorize(context.Background(), g.SPIFFE, r)
			if scenario == "conflict" {
				if e != worker.ErrExecution || script.commits != 0 {
					t.Fatal("conflicting completion accepted", e)
				}
			} else if e != nil || script.commits != 1 {
				t.Fatal("completion failed", e)
			}
			if keys.calls != 0 || len(lease.DEK) != 0 || lease.Database != nil {
				t.Fatal("completion released credentials")
			}
		})
	}
}
func TestWorkerLiveProofFailureBeforeSQLMutation(t *testing.T) {
	task, g, r := grantFixture()
	raw, _ := json.Marshal(g)
	store, script := scriptStore(t, sqlStep{contains: "WHERE spiffe_uri=?", rows: [][]driver.Value{{raw}}})
	_ = task
	keys := &countingKeys{}
	a := WorkerAuthorizer{Store: store, Keys: keys, Lifetime: time.Minute, ValidateLive: func(context.Context, WorkerGrant, string) error { return ErrFence }}
	if _, e := a.Authorize(context.Background(), g.SPIFFE, r); e != worker.ErrNotReady || script.writes != 0 || keys.calls != 0 {
		t.Fatal("invalid Job or isolation proof authorized", e)
	}
}

func TestWorkerAcquireRechecksAfterProviderAndClearsOnRevocation(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "authorized", true: "revoked-during-provider"}[revoked], func(t *testing.T) {
			task, g, request := grantFixture()
			expires := time.Now().Add(30 * time.Second).UnixMilli()
			steps := append(workerSteps(task, g, nil, expires), workerCommit(task)...)
			if !revoked {
				steps = append(steps, workerSteps(task, g, nil, expires)...)
				steps = append(steps, workerCommit(task)...)
			} else {
				raw, _ := json.Marshal(g)
				steps = append(steps, sqlStep{contains: "WHERE spiffe_uri=?", rows: [][]driver.Value{{raw}}})
			}
			store, script := scriptStore(t, steps...)
			private := []byte(strings.Repeat("k", 32))
			fetched := false
			keys := unwrapFunc(func(ctx context.Context, _ staging.Binding, _ artifact.WrappedKey) ([]byte, error) {
				// The one-connection pool would block if Authorize held the task
				// transaction while invoking a vault-backed provider.
				bounded, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				conn, err := store.DB.Conn(bounded)
				if err != nil {
					return nil, err
				}
				conn.Close()
				if script.commits != 1 {
					t.Fatal("provider ran before durable grant")
				}
				fetched = true
				return private, nil
			})
			a := WorkerAuthorizer{Store: store, Keys: keys, Lifetime: time.Minute, ValidateLive: func(context.Context, WorkerGrant, string) error {
				if fetched && revoked {
					return ErrFence
				}
				return nil
			}}
			lease, err := a.Authorize(context.Background(), g.SPIFFE, request)
			if !fetched {
				t.Fatal("provider not exercised")
			}
			if revoked {
				if err == nil || len(lease.DEK) != 0 || string(private) != strings.Repeat("\x00", 32) {
					t.Fatal("revoked acquisition leaked key", err)
				}
			} else {
				if err != nil || len(lease.DEK) != 32 || lease.ExpiresAt.UnixMilli() != expires {
					t.Fatal("authorized acquisition failed", err)
				}
				lease.Clear()
			}
		})
	}
}
