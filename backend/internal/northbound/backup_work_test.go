package northbound

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/backupgate"
	"clawreef/internal/models"
)

func TestLifecycleCancellationRetainsActualChildWork(t *testing.T) {
	var active atomic.Int32
	restore := backupgate.ConfigureWorkBoundary(func(context.Context) (func(), error) {
		active.Add(1)
		return func() { active.Add(-1) }, nil
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent, err := backupgate.HoldWorkUnit(ctx, "northbound.operation")
	if err != nil {
		t.Fatal(err)
	}
	started, finish, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		close(finish)
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Error("action did not exit")
		}
		until := time.Now().Add(time.Second)
		for active.Load() != 0 && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if active.Load() != 0 {
			t.Error("finished action retained its work permit")
		}
	})
	worker := &OperationWorker{service: &CoreService{}}
	result := make(chan error, 1)
	go func() {
		result <- worker.runLifecycleActionWithLease(ctx, &models.NorthboundOperation{}, func() error {
			close(started)
			<-finish // A provider call may outlive cancellation of its caller.
			close(exited)
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("action not started")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller did not return")
	}
	parent()
	if got := active.Load(); got != 1 {
		t.Fatalf("actual action still running, active backup work = %d; want 1", got)
	}
}

func TestLifecycleCannotLaunchAcrossClosedBackupBoundary(t *testing.T) {
	blocked := errors.New("backup is draining")
	restore := backupgate.ConfigureWorkBoundary(func(context.Context) (func(), error) { return nil, blocked })
	defer restore()
	worker := &OperationWorker{service: &CoreService{}}
	called := false
	err := worker.runLifecycleActionWithLease(context.Background(), &models.NorthboundOperation{}, func() error { called = true; return nil })
	if !errors.Is(err, blocked) || called {
		t.Fatalf("err=%v action called=%v", err, called)
	}
}
