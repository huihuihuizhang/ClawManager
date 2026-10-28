package services

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"clawreef/internal/models"
)

type skillMaterializeWorkerService interface {
	BackfillOnce(context.Context, int) (int, error)
	ClaimNextPending(context.Context, int) ([]models.SkillPackageMaterializeJob, error)
	ReleaseToPending(int) error
	ProcessJob(context.Context, int) error
}

type skillMaterializeWorkerRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	err    error // published by closing done
}

type SkillPackageMaterializeWorker struct {
	BackupGate       BackupMutationGate
	service          skillMaterializeWorkerService
	tick             time.Duration
	batchSize        int
	concurrency      int
	perInstanceLimit int
	enabled          bool

	mu  sync.Mutex
	run *skillMaterializeWorkerRun
}

func NewSkillPackageMaterializeWorker(service *SkillPackageMaterializeService, tick time.Duration, batchSize, concurrency, perInstanceLimit int, enabled bool) *SkillPackageMaterializeWorker {
	if tick <= 0 {
		tick = 2 * time.Second
	}
	if batchSize <= 0 {
		batchSize = 5
	}
	if concurrency <= 0 {
		concurrency = 5
	}
	if perInstanceLimit <= 0 {
		perInstanceLimit = 2
	}
	w := &SkillPackageMaterializeWorker{
		tick: tick, batchSize: batchSize, concurrency: concurrency,
		perInstanceLimit: perInstanceLimit, enabled: enabled,
	}
	if service != nil {
		w.service = service // avoid a non-nil interface containing a nil service
	}
	return w
}

func (w *SkillPackageMaterializeWorker) Start() {
	if err := w.StartContext(context.Background()); err != nil {
		log.Printf("skill package materialize start failed: %v", err)
	}
}

// StartContext ties this run to its leader's lifetime. A stopping run must
// actually exit before a replacement can start, even after StopAndWait times out.
func (w *SkillPackageMaterializeWorker) StartContext(ctx context.Context) error {
	if w == nil || !w.enabled || w.service == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		w.mu.Lock()
		previous := w.run
		if previous != nil {
			select {
			case <-previous.done:
			default:
				w.mu.Unlock()
				if previous.ctx.Err() == nil {
					return nil
				}
				select {
				case <-previous.done:
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		runCtx, cancel := context.WithCancel(ctx)
		run := &skillMaterializeWorkerRun{ctx: runCtx, cancel: cancel, done: make(chan struct{})}
		w.run = run
		go w.loop(run)
		w.mu.Unlock()
		return nil
	}
}

func (w *SkillPackageMaterializeWorker) Stop() {
	if err := w.StopAndWait(context.Background()); err != nil {
		log.Printf("skill package materialize stop failed: %v", err)
	}
}

// StopAndWait cancels admission/backfill/jobs and joins the captured run. A
// deadline is a failed wait, never evidence that writes have stopped. This is
// only local worker shutdown, not a maintenance-gate or participant ACK.
func (w *SkillPackageMaterializeWorker) StopAndWait(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	run := w.run
	if run != nil {
		run.cancel()
	}
	w.mu.Unlock()
	if run == nil {
		return nil
	}
	select {
	case <-run.done:
		return run.err
	default:
	}
	select {
	case <-run.done:
		return run.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *SkillPackageMaterializeWorker) loop(run *skillMaterializeWorkerRun) {
	defer close(run.done)
	defer run.cancel()
	if run.ctx.Err() != nil {
		return
	}
	backfillAdmitted, backfillErr := w.backfillAttempt(run.ctx)
	run.err = backfillErr
	ticker := time.NewTicker(w.tick)
	defer ticker.Stop()
	for {
		select {
		case <-run.ctx.Done():
			return
		case <-ticker.C:
			if run.ctx.Err() != nil {
				return
			}
			if !backfillAdmitted {
				backfillAdmitted, backfillErr = w.backfillAttempt(run.ctx)
				if backfillErr != nil && run.err == nil {
					run.err = backfillErr
				}
				if !backfillAdmitted {
					continue
				}
			}
			if run.ctx.Err() != nil {
				return
			}
			if err := w.processBatch(run.ctx); err != nil && run.err == nil {
				// Retain the first incomplete claim/cleanup for the drain result.
				// Repeated outages must not grow an unbounded error chain.
				run.err = err
			}
		}
	}
}

// Admission refusal must defer this once-per-run backfill until a later tick.
// The permit is held through all child writes; a release failure is not an ACK.
func (w *SkillPackageMaterializeWorker) backfill(ctx context.Context) error {
	_, err := w.backfillAttempt(ctx)
	return err
}

func (w *SkillPackageMaterializeWorker) backfillAttempt(ctx context.Context) (admitted bool, releaseErr error) {
	if ctx.Err() != nil {
		return false, nil
	}
	release, err := enterBackupMutation(ctx, w.BackupGate, "skill-backfill")
	if err != nil {
		return false, nil
	}
	defer func() { releaseErr = release() }()
	if ctx.Err() != nil {
		return true, nil
	}
	if count, err := w.service.BackfillOnce(ctx, 500); err != nil {
		if ctx.Err() == nil {
			log.Printf("skill package materialize backfill failed: %v", err)
		}
	} else if count > 0 {
		log.Printf("skill package materialize backfill enqueued %d jobs", count)
	}
	return true, nil
}

func (w *SkillPackageMaterializeWorker) processBatch(ctx context.Context) (resultErr error) {
	if ctx.Err() != nil {
		return nil
	}
	releaseGate, gateErr := enterBackupMutation(ctx, w.BackupGate, "skill-materialize")
	if gateErr != nil {
		return nil
	}
	defer func() { resultErr = errors.Join(resultErr, releaseGate()) }()
	if ctx.Err() != nil {
		return nil
	}
	jobs, claimErr := w.service.ClaimNextPending(ctx, w.batchSize)
	if claimErr != nil {
		log.Printf("skill package materialize claim failed: %v", claimErr)
	}
	var releaseMu sync.Mutex
	var releaseErr error
	release := func(id int) {
		// Cleanup must finish even when the run is canceled; StopAndWait waits
		// for it, and a caller's timeout never detaches it as successful cleanup.
		if err := w.service.ReleaseToPending(id); err != nil {
			releaseMu.Lock()
			releaseErr = errors.Join(releaseErr, err)
			releaseMu.Unlock()
			log.Printf("skill package materialize release job %d failed: %v", id, err)
		}
	}
	sem := make(chan struct{}, w.concurrency)
	var activeMu sync.Mutex
	active := make(map[int]int)
	reserve := func(instanceID int) bool {
		activeMu.Lock()
		defer activeMu.Unlock()
		if active[instanceID] >= w.perInstanceLimit {
			return false
		}
		active[instanceID]++
		return true
	}
	finish := func(instanceID int) {
		activeMu.Lock()
		active[instanceID]--
		activeMu.Unlock()
	}
	var wg sync.WaitGroup
	for _, job := range jobs {
		if claimErr != nil || ctx.Err() != nil || !reserve(job.InstanceID) {
			release(job.ID)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			finish(job.InstanceID)
			release(job.ID)
			continue
		}
		wg.Add(1)
		go func(job models.SkillPackageMaterializeJob) {
			defer wg.Done()
			defer finish(job.InstanceID)
			defer func() { <-sem }()
			if ctx.Err() != nil {
				release(job.ID)
				return
			}
			if err := w.service.ProcessJob(ctx, job.ID); err != nil {
				if materializeCancellation(ctx, err) != nil {
					release(job.ID)
				} else {
					log.Printf("skill package materialize job %d failed: %v", job.ID, err)
				}
			}
		}(job)
	}
	wg.Wait()
	return errors.Join(claimErr, releaseErr)
}
