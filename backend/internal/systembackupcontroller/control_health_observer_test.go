package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestControlHealthTokensCannotMoveBetweenDatabasePools(t *testing.T) {
	e := &healthExecutor{rows: 1}
	store := e.store(t)
	writer, err := store.BeginWriter(context.Background(), "installation_test", 1, "pod", 0)
	if err != nil {
		t.Fatal(err)
	}
	other := (&healthExecutor{rows: 1}).store(t)
	probe := ReadinessProbeFunc(func(context.Context) error { t.Fatal("foreign token reached probe"); return nil })
	if _, err := other.Observe(context.Background(), writer, ControlLoopResult{}, probe); !errors.Is(err, ErrControlHealthFence) {
		t.Fatal("token moved to another pool", err)
	}
	if _, err := NewControlHealthObserver(other, writer, probe); !errors.Is(err, ErrControlHealthFence) {
		t.Fatal("observer accepted another pool's token", err)
	}
}

func TestControlHealthObserverSerializesSequencesAndStopsAfterUnknownWrite(t *testing.T) {
	e := &healthExecutor{rows: 1}
	store := e.store(t)
	writer, err := store.BeginWriter(context.Background(), "installation_test", 1, "pod", 0)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := NewControlHealthObserver(store, writer, ReadinessProbeFunc(func(context.Context) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsFound := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errorsFound <- observer.Observe(context.Background(), ControlLoopResult{}) }()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if e.args[i+1][6] != int64(i) {
			t.Fatal("observer reused or skipped sequence", e.args[i+1])
		}
	}
	e.err = errors.New("commit reply lost")
	if err := observer.Observe(context.Background(), ControlLoopResult{}); err == nil {
		t.Fatal("unknown write accepted")
	}
	e.err = nil
	queries := len(e.queries)
	if err := observer.Observe(context.Background(), ControlLoopResult{}); err == nil || len(e.queries) != queries || observer.writer != (ControlHealthWriter{}) {
		t.Fatal("poisoned observer resumed SQL")
	}
}

type loopObserverFunc func(context.Context, ControlLoopResult) error

func (f loopObserverFunc) Observe(ctx context.Context, result ControlLoopResult) error {
	return f(ctx, result)
}

func TestControlLoopPersistsCompletedResultBeforeCallbackAndStopsOnFence(t *testing.T) {
	var order []string
	passErr := errors.New("kill-switch pass failed")
	loop := ControlLoop{
		GateRecovery: recordedGateRecoveryPass{order: &order},
		KillSwitch:   recordedKillSwitchPass{order: &order, err: passErr},
		Deadline:     recordedDeadlinePass{order: &order}, Interval: DefaultReconcile,
		Observer: loopObserverFunc(func(_ context.Context, result ControlLoopResult) error {
			order = append(order, "observe")
			if !errors.Is(result.Err, passErr) {
				t.Fatal("observer did not receive actual pass failure", result.Err)
			}
			return ErrControlHealthFence
		}),
		OnResult: func(result ControlLoopResult) {
			order = append(order, "callback")
			if !errors.Is(result.Err, passErr) {
				t.Fatal("storage failure replaced original pass result")
			}
		},
	}
	if err := loop.runOnce(context.Background()); !errors.Is(err, ErrControlHealthFence) {
		t.Fatal("loop continued after observer failure", err)
	}
	if !reflect.DeepEqual(order, []string{"gate-recovery", "kill-switch", "deadline", "observe", "callback"}) {
		t.Fatal(order)
	}
}

func TestControlLoopDoesNotObserveAfterCancellationOrGuardFailure(t *testing.T) {
	for _, guardFailure := range []bool{false, true} {
		var order []string
		ctx, cancel := context.WithCancel(context.Background())
		loop := ControlLoop{
			GateRecovery: recordedGateRecoveryPass{order: &order}, KillSwitch: recordedKillSwitchPass{order: &order},
			Deadline: recordedDeadlinePass{order: &order}, Interval: DefaultReconcile,
			Observer: loopObserverFunc(func(context.Context, ControlLoopResult) error { t.Fatal("uncompleted pass observed"); return nil }),
		}
		if guardFailure {
			loop.Guard = ReadinessProbeFunc(func(context.Context) error { return errors.New("admission denied") })
		} else {
			cancel()
		}
		if err := loop.runOnce(ctx); err == nil {
			t.Fatal("uncompleted loop returned success")
		}
		cancel()
		if len(order) != 0 {
			t.Fatal("passes ran without admission", order)
		}
	}
}
