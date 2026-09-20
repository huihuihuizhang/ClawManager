package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	MinWorkerStopTimeout     = time.Second
	DefaultWorkerStopTimeout = 30 * time.Second
	MaxWorkerStopTimeout     = 2 * time.Minute
)

type BootstrapWorker func(context.Context, BootstrapSnapshot) error

type BootstrapSupervisorResult struct {
	Snapshot      BootstrapSnapshot
	Err           error
	WorkerRunning bool
}

// BootstrapSupervisor continuously revalidates D-owned startup state. A
// failed check cancels the current leader worker. A runtime-relevant config
// change waits for the old worker to exit before starting a replacement, so
// two policies never reconcile concurrently inside one process.
type BootstrapSupervisor struct {
	Checker           BootstrapChecker
	Requirements      BootstrapRequirements
	CheckInterval     time.Duration
	WorkerStopTimeout time.Duration
	Worker            BootstrapWorker
	OnResult          func(BootstrapSupervisorResult)
}

type supervisedWorker struct {
	cancel   context.CancelFunc
	done     <-chan error
	snapshot BootstrapSnapshot
}

func (s BootstrapSupervisor) validate() error {
	if s.Checker == nil {
		return bootstrapFailure(BootstrapInvalidRequirement, errors.New("nil bootstrap supervisor checker"))
	}
	if s.Worker == nil {
		return bootstrapFailure(BootstrapInvalidRequirement, errors.New("nil bootstrap supervisor worker"))
	}
	if err := s.Requirements.Validate(); err != nil {
		return err
	}
	if s.CheckInterval < MinBootstrapCheckInterval || s.CheckInterval > MaxBootstrapCheckInterval {
		return bootstrapFailure(BootstrapInvalidRequirement, fmt.Errorf("bootstrap check interval must be between %s and %s", MinBootstrapCheckInterval, MaxBootstrapCheckInterval))
	}
	if s.WorkerStopTimeout < MinWorkerStopTimeout || s.WorkerStopTimeout > MaxWorkerStopTimeout {
		return bootstrapFailure(BootstrapInvalidRequirement, fmt.Errorf("worker stop timeout must be between %s and %s", MinWorkerStopTimeout, MaxWorkerStopTimeout))
	}
	return nil
}

func (s BootstrapSupervisor) report(result BootstrapSupervisorResult) {
	if s.OnResult != nil {
		s.OnResult(result)
	}
}

func (s BootstrapSupervisor) check(ctx context.Context) (BootstrapSnapshot, error) {
	checkCtx, cancel := context.WithTimeout(ctx, s.CheckInterval)
	defer cancel()
	return s.Checker.Check(checkCtx, s.Requirements)
}

func (s BootstrapSupervisor) start(ctx context.Context, snapshot BootstrapSnapshot) *supervisedWorker {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- s.Worker(workerCtx, snapshot)
		close(done)
	}()
	return &supervisedWorker{cancel: cancel, done: done, snapshot: snapshot}
}

func (s BootstrapSupervisor) stop(ctx context.Context, worker *supervisedWorker) error {
	if worker == nil {
		return nil
	}
	worker.cancel()
	timer := time.NewTimer(s.WorkerStopTimeout)
	defer timer.Stop()
	select {
	case <-worker.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return bootstrapFailure(BootstrapWorkerStopTimeout, errors.New("leader worker did not stop before timeout"))
	}
}

func sameBootstrapRuntime(left, right BootstrapSnapshot) bool {
	return left.InstallationID == right.InstallationID &&
		left.ConfigVersion == right.ConfigVersion &&
		left.ConfigEnabled == right.ConfigEnabled &&
		left.EnvironmentEnabled == right.EnvironmentEnabled &&
		left.EffectiveEnabled == right.EffectiveEnabled &&
		left.StateTransitionRequired == right.StateTransitionRequired &&
		left.MatrixKey == right.MatrixKey &&
		left.Policy == right.Policy &&
		left.MigrationCatalogHash == right.MigrationCatalogHash
}

func (s BootstrapSupervisor) Run(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.CheckInterval)
	defer ticker.Stop()
	return s.runWithTicks(ctx, ticker.C)
}

func (s BootstrapSupervisor) runWithTicks(ctx context.Context, ticks <-chan time.Time) error {
	var active *supervisedWorker
	for {
		if err := ctx.Err(); err != nil {
			if stopErr := s.stop(context.Background(), active); stopErr != nil {
				return stopErr
			}
			return err
		}

		snapshot, checkErr := s.check(ctx)
		if checkErr != nil {
			s.report(BootstrapSupervisorResult{Err: checkErr})
			if active != nil {
				if err := s.stop(ctx, active); err != nil {
					return err
				}
				active = nil
			}
		} else {
			if active != nil && !sameBootstrapRuntime(active.snapshot, snapshot) {
				s.report(BootstrapSupervisorResult{
					Snapshot: active.snapshot,
					Err:      bootstrapFailure(BootstrapRuntimeRestarting, errors.New("runtime-relevant bootstrap state changed")),
				})
				if err := s.stop(ctx, active); err != nil {
					return err
				}
				active = nil
			}
			if active == nil {
				active = s.start(ctx, snapshot)
			}
			s.report(BootstrapSupervisorResult{Snapshot: snapshot, WorkerRunning: true})
		}

		var workerDone <-chan error
		if active != nil {
			workerDone = active.done
		}
		select {
		case <-ctx.Done():
			if stopErr := s.stop(context.Background(), active); stopErr != nil {
				return stopErr
			}
			return ctx.Err()
		case workerErr := <-workerDone:
			failedSnapshot := active.snapshot
			active = nil
			if workerErr == nil {
				workerErr = errors.New("leader worker exited without cancellation")
			}
			s.report(BootstrapSupervisorResult{
				Snapshot: failedSnapshot,
				Err:      bootstrapFailure(BootstrapWorkerExited, workerErr),
			})
		case <-ticks:
		}
	}
}
