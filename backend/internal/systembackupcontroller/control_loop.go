package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type KillSwitchPass interface {
	RunOnce(context.Context) (KillSwitchReport, error)
}

type GateRecoveryPass interface {
	RunOnce(context.Context) (GateRecoveryReport, error)
}

type ControlLoopResult struct {
	GateRecovery GateRecoveryReport
	KillSwitch   KillSwitchReport
	Deadline     DeadlineSweepReport
	Duration     time.Duration
	Err          error
}

// ControlLoopObserver persists only a completed pass. An observation failure
// stops this loop so a fenced/unknown writer cannot silently keep running.
type ControlLoopObserver interface {
	Observe(context.Context, ControlLoopResult) error
}

// ControlLoop orders the D-owned fail-safe passes. Expired gate owners are
// fenced first, then kill-switch projection runs before deadline handling.
// Persistence failures are reported but retried on the next tick. There is
// deliberately no runner, participant implementation, or provider pass here.
type ControlLoop struct {
	Guard        ReadinessProbe
	GateRecovery GateRecoveryPass
	KillSwitch   KillSwitchPass
	Deadline     DeadlineSweepPass
	Interval     time.Duration
	Observer     ControlLoopObserver
	OnResult     func(ControlLoopResult)
}

func (l ControlLoop) validate() error {
	if l.GateRecovery == nil {
		return errors.New("nil system backup gate recovery pass")
	}
	if l.KillSwitch == nil {
		return errors.New("nil system backup kill-switch pass")
	}
	if l.Deadline == nil {
		return errors.New("nil system backup deadline pass")
	}
	if l.Interval < MinReconcileInterval || l.Interval > MaxReconcileInterval {
		return fmt.Errorf("control loop interval must be between %s and %s", MinReconcileInterval, MaxReconcileInterval)
	}
	return nil
}

func (l ControlLoop) runOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	started := time.Now()
	if l.Guard != nil {
		if err := l.Guard.Check(ctx); err != nil {
			return fmt.Errorf("controller control-loop admission guard: %w", err)
		}
	}
	gateRecoveryReport, gateRecoveryErr := l.GateRecovery.RunOnce(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	killSwitchReport, killSwitchErr := l.KillSwitch.RunOnce(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	deadlineReport, deadlineErr := l.Deadline.RunOnce(ctx)
	contextErr := ctx.Err()
	combinedErr := errors.Join(gateRecoveryErr, killSwitchErr, deadlineErr)
	if contextErr == nil && !errors.Is(combinedErr, context.Canceled) && !errors.Is(combinedErr, context.DeadlineExceeded) {
		result := ControlLoopResult{GateRecovery: gateRecoveryReport, KillSwitch: killSwitchReport, Deadline: deadlineReport, Duration: time.Since(started), Err: combinedErr}
		var observationErr error
		if l.Observer != nil {
			observationErr = l.Observer.Observe(ctx, result)
		}
		if ctx.Err() == nil && l.OnResult != nil {
			l.OnResult(result)
		}
		if observationErr != nil {
			return fmt.Errorf("controller completed-pass observation: %w", observationErr)
		}
	}
	return ctx.Err()
}

func (l ControlLoop) Run(ctx context.Context) error {
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

func (l ControlLoop) runWithTicks(ctx context.Context, ticks <-chan time.Time) error {
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
