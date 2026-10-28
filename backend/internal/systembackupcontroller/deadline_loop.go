package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type DeadlineSweepPass interface {
	RunOnce(context.Context) (DeadlineSweepReport, error)
}

type DeadlineSweepResult struct {
	Report DeadlineSweepReport
	Err    error
}

// DeadlineLoop is the first no-provider controller loop. It runs immediately
// after leadership is acquired, then at the configured reconcile interval.
// Per-pass persistence errors are reported and retried on the next tick; loss
// of the leader context stops the loop without starting another database call.
type DeadlineLoop struct {
	Sweeper  DeadlineSweepPass
	Interval time.Duration
	OnResult func(DeadlineSweepResult)
}

func (l DeadlineLoop) validate() error {
	if l.Sweeper == nil {
		return errors.New("nil system backup deadline sweeper")
	}
	if l.Interval < MinReconcileInterval || l.Interval > MaxReconcileInterval {
		return fmt.Errorf("deadline loop interval must be between %s and %s", MinReconcileInterval, MaxReconcileInterval)
	}
	return nil
}

func (l DeadlineLoop) runOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	report, err := l.Sweeper.RunOnce(ctx)
	contextErr := ctx.Err()
	if contextErr == nil && l.OnResult != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		l.OnResult(DeadlineSweepResult{Report: report, Err: err})
	}
	return contextErr
}

func (l DeadlineLoop) Run(ctx context.Context) error {
	if err := l.validate(); err != nil {
		return err
	}
	if err := l.runOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(l.Interval)
	defer ticker.Stop()
	return l.runWithTicks(ctx, ticker.C)
}

func (l DeadlineLoop) runWithTicks(ctx context.Context, ticks <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			if err := l.runOnce(ctx); err != nil {
				return err
			}
		}
	}
}
