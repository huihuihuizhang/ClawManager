package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryTasks struct {
	mu           sync.Mutex
	task         Task
	renewFailure bool
	history      []string
}

func (m *memoryTasks) Create(context.Context, int, string, Request, time.Duration) (Task, error) {
	return Task{}, ErrNotReady
}
func (m *memoryTasks) List(context.Context, int) ([]Task, error) {
	t, e := m.Get(context.Background(), "")
	return []Task{t}, e
}
func (m *memoryTasks) Get(_ context.Context, _ string) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.task, nil
}
func (m *memoryTasks) Cancel(_ context.Context, _ string, v int64) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v != m.task.RowVersion || !Allowed(m.task, "canceling") {
		return Task{}, ErrConflict
	}
	m.task.Status = "canceling"
	m.task.CanCancel = false
	m.task.RowVersion++
	return m.task, nil
}
func (m *memoryTasks) Claim(_ context.Context, owner string, ttl time.Duration) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.task.LeaseUntil > time.Now().UnixMilli() {
		return Task{}, ErrNotFound
	}
	m.task.Owner = owner
	m.task.Generation++
	m.task.RowVersion++
	m.task.LeaseUntil = time.Now().Add(ttl).UnixMilli()
	return m.task, nil
}
func (m *memoryTasks) Renew(_ context.Context, t Task, ttl time.Duration) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.renewFailure || t.Owner != m.task.Owner || t.Generation != m.task.Generation {
		return Task{}, ErrFence
	}
	m.task.LeaseUntil = time.Now().Add(ttl).UnixMilli()
	return m.task, nil
}
func (m *memoryTasks) Advance(_ context.Context, t Task, next, code string) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.Owner != m.task.Owner || t.Generation != m.task.Generation {
		return Task{}, ErrFence
	}
	if t.RowVersion != m.task.RowVersion || !Allowed(m.task, next) {
		return Task{}, ErrConflict
	}
	m.task.Status = next
	m.task.FailureCode = code
	m.task.RowVersion++
	if m.task.Terminal() || next == "finalization_unknown" {
		m.task.CanCancel = false
	}
	m.history = append(m.history, next)
	return m.task, nil
}
func (m *memoryTasks) BeginCommit(_ context.Context, t Task) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.task.Status != "publishing" || m.task.RowVersion != t.RowVersion {
		return Task{}, ErrConflict
	}
	m.task.CanCancel = false
	m.task.RowVersion++
	return m.task, nil
}

type testExecutor struct {
	step    func(context.Context, Task) error
	recover func(context.Context, Task) error
}

func (testExecutor) Profiles(context.Context) ([]Profile, error) { return nil, nil }
func (x testExecutor) Step(ctx context.Context, t Task) error    { return x.step(ctx, t) }
func (x testExecutor) Recover(ctx context.Context, t Task) error { return x.recover(ctx, t) }
func testTask() Task {
	return Task{ID: "sb-test", Request: Request{Kind: "backup", Profile: "fixture", Purpose: "functional_test"}, Actor: 1, Status: "pending", CanCancel: true, RowVersion: 1, Deadline: time.Now().Add(time.Minute).UnixMilli()}
}
func controllerFor(m *memoryTasks, x testExecutor) Controller {
	return Controller{Store: m, Executor: x, Owner: "owner-a", Lease: 3 * time.Second, RecoveryTimeout: time.Second}
}
func TestControllerTransitionsCancellationAndUnknownCommit(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "failure", "unknown", "recovery-failed", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			m := &memoryTasks{task: testTask()}
			if mode == "deadline" {
				m.task.Deadline = time.Now().Add(-time.Second).UnixMilli()
			}
			recovered := 0
			x := testExecutor{step: func(ctx context.Context, task Task) error {
				if mode == "cancel" && task.Status == "preparing" {
					_, e := m.Cancel(ctx, task.ID, task.RowVersion)
					return e
				}
				if mode == "failure" && task.Status == "capturing" {
					return errors.New("private detail")
				}
				if task.Status == "publishing" {
					if _, e := m.BeginCommit(ctx, task); e != nil {
						return e
					}
					if mode == "unknown" {
						return errors.New("lost reply")
					}
				}
				return nil
			}, recover: func(ctx context.Context, task Task) error {
				if ctx.Err() != nil {
					t.Fatal("recovery canceled by capture")
				}
				recovered++
				if mode == "recovery-failed" {
					return ErrNotReady
				}
				return nil
			}}
			e := controllerFor(m, x).RunOnce(context.Background())
			result, _ := m.Get(context.Background(), "")
			want := map[string]string{"success": "succeeded", "cancel": "canceled", "failure": "failed", "unknown": "finalization_unknown", "recovery-failed": "publishing", "deadline": "failed"}[mode]
			if result.Status != want || recovered != 1 {
				t.Fatalf("%s recovery=%d error=%v", result.Status, recovered, e)
			}
			if mode == "recovery-failed" {
				if e == nil {
					t.Fatal("unconfirmed recovery succeeded")
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if result.Terminal() && result.CanCancel {
				t.Fatal("terminal task remains cancelable")
			}
		})
	}
}
func TestControllerCancelInterruptsActiveStepButNotRecovery(t *testing.T) {
	m := &memoryTasks{task: testTask()}
	started := make(chan Task, 1)
	recovered := false
	x := testExecutor{step: func(ctx context.Context, t Task) error { started <- t; <-ctx.Done(); return ctx.Err() }, recover: func(ctx context.Context, t Task) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		recovered = true
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- controllerFor(m, x).RunOnce(context.Background()) }()
	task := <-started
	if _, e := m.Cancel(context.Background(), task.ID, task.RowVersion); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != nil || !recovered {
			t.Fatal(e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancel did not interrupt phase")
	}
	result, _ := m.Get(context.Background(), "")
	if result.Status != "canceled" {
		t.Fatal(result.Status)
	}
}
func TestControllerLostClaimDoesNotAdvanceOrRecover(t *testing.T) {
	m := &memoryTasks{task: testTask()}
	m.renewFailure = true
	x := testExecutor{step: func(ctx context.Context, _ Task) error { <-ctx.Done(); return ctx.Err() }, recover: func(context.Context, Task) error { t.Fatal("lost owner invoked recovery"); return nil }}
	if e := controllerFor(m, x).RunOnce(context.Background()); !errors.Is(e, ErrFence) {
		t.Fatal(e)
	}
	result, _ := m.Get(context.Background(), "")
	if result.Status != "pending" {
		t.Fatal("lost owner wrote terminal state")
	}
}
func TestContractRejectsProductionAndTerminalResurrection(t *testing.T) {
	for _, r := range []Request{{Kind: "restore", Profile: "p", Purpose: "functional_test"}, {Kind: "backup", Profile: "p", Purpose: "acceptance"}, {Kind: "drill", Profile: "p", Purpose: "functional_test"}, {Kind: "backup", Profile: "../p", Purpose: "functional_test"}} {
		if r.Validate() == nil {
			t.Fatal("unsupported request accepted")
		}
	}
	for _, state := range []string{"succeeded", "failed", "canceled"} {
		task := testTask()
		task.Status = state
		for _, next := range []string{"pending", "failed", "canceling", "succeeded"} {
			if Allowed(task, next) {
				t.Fatal("resurrection")
			}
		}
	}
	task := testTask()
	task.Status = "publishing"
	task.CanCancel = false
	if Allowed(task, "canceling") || Allowed(task, "failed") || !Allowed(task, "finalization_unknown") {
		t.Fatal("commit boundary lost")
	}
}
