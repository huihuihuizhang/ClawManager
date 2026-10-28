package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type recordedSweepPass struct {
	reports []DeadlineSweepReport
	errors  []error
	calls   int
	onCall  func(int)
}

func (r *recordedSweepPass) RunOnce(ctx context.Context) (DeadlineSweepReport, error) {
	r.calls++
	if r.onCall != nil {
		r.onCall(r.calls)
	}
	index := r.calls - 1
	var report DeadlineSweepReport
	if index < len(r.reports) {
		report = r.reports[index]
	}
	if index < len(r.errors) {
		return report, r.errors[index]
	}
	return report, nil
}

func TestDeadlineLoopReportsPerPassErrorAndContinues(t *testing.T) {
	sweeper := &recordedSweepPass{
		reports: []DeadlineSweepReport{{Selected: 1}, {Selected: 2, Expired: 1}, {Selected: 3, Expired: 2}},
		errors:  []error{errors.New("database unavailable"), nil, nil},
	}
	var results []DeadlineSweepResult
	loop := DeadlineLoop{Sweeper: sweeper, Interval: DefaultReconcile, OnResult: func(result DeadlineSweepResult) {
		results = append(results, result)
	}}
	ticks := make(chan time.Time, 2)
	ticks <- time.Time{}
	ticks <- time.Time{}
	ctx, cancel := context.WithCancel(context.Background())
	sweeper.onCall = func(call int) {
		if call == 3 {
			cancel()
		}
	}
	if err := loop.runOnce(ctx); err != nil {
		t.Fatalf("initial runOnce: %v", err)
	}
	if err := loop.runWithTicks(ctx, ticks); !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithTicks error = %v", err)
	}
	if sweeper.calls != 3 {
		t.Fatalf("sweeper calls = %d, want 3", sweeper.calls)
	}
	if len(results) != 2 {
		t.Fatalf("reported results = %#v", results)
	}
	if results[0].Err == nil || results[0].Report.Selected != 1 || results[1].Err != nil || results[1].Report.Expired != 1 {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestDeadlineLoopCanceledContextDoesNotSweepOrReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sweeper := &recordedSweepPass{}
	var results []DeadlineSweepResult
	loop := DeadlineLoop{Sweeper: sweeper, Interval: DefaultReconcile, OnResult: func(result DeadlineSweepResult) {
		results = append(results, result)
	}}
	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled loop error = %v", err)
	}
	if sweeper.calls != 0 || !reflect.DeepEqual(results, []DeadlineSweepResult(nil)) {
		t.Fatalf("canceled loop performed work: calls=%d results=%#v", sweeper.calls, results)
	}
}

func TestDeadlineLoopRejectsInvalidConfiguration(t *testing.T) {
	for _, loop := range []DeadlineLoop{
		{Interval: DefaultReconcile},
		{Sweeper: &recordedSweepPass{}, Interval: MinReconcileInterval - time.Millisecond},
		{Sweeper: &recordedSweepPass{}, Interval: MaxReconcileInterval + time.Second},
	} {
		if err := loop.Run(context.Background()); err == nil {
			t.Fatalf("invalid loop accepted: %#v", loop)
		}
	}
}
