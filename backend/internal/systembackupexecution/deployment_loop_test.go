package systembackupexecution

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeploymentPassesRetainOwnerAfterTaskFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls, failures, recovered := 0, 0, false
	err := runDeploymentPasses(ctx, func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("private error must not be logged")
		}
		return nil
	}, time.Millisecond, func(e error) {
		if e != nil {
			failures++
			return
		}
		recovered = true
		cancel()
	})
	if !errors.Is(err, context.Canceled) || calls != 2 || failures != 1 || !recovered {
		t.Fatalf("owner did not resume durable scheduling: calls=%d failures=%d recovered=%v", calls, failures, recovered)
	}
}

func TestDeploymentPassesStopBeforeNewPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runDeploymentPasses(ctx, func(context.Context) error { t.Fatal("pass after stop"); return nil }, time.Second, func(error) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
