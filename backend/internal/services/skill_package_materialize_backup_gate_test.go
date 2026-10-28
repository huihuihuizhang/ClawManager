package services

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/models"
)

type materializeBackupGateFunc func(context.Context, string) (func() error, error)

func (f materializeBackupGateFunc) Enter(ctx context.Context, name string) (func() error, error) {
	return f(ctx, name)
}

func TestMaterializeBackupGateClosedPreventsBackfillAndClaims(t *testing.T) {
	w := lifecycleWorker(&materializeLifecycleStub{
		backfill: func(context.Context, int) (int, error) {
			t.Fatal("backfill wrote through a closed gate")
			return 0, nil
		},
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			t.Fatal("claimed through a closed gate")
			return nil, nil
		},
	})
	var names []string
	w.BackupGate = materializeBackupGateFunc(func(_ context.Context, name string) (func() error, error) {
		names = append(names, name)
		return nil, errors.New("gate closed")
	})
	if err := w.backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.processBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "skill-backfill" || names[1] != "skill-materialize" {
		t.Fatalf("unexpected participants: %v", names)
	}
}

func TestMaterializeBackupGateCanceledRunDoesNotAcquirePermit(t *testing.T) {
	w := lifecycleWorker(&materializeLifecycleStub{})
	w.BackupGate = materializeBackupGateFunc(func(context.Context, string) (func() error, error) {
		t.Fatal("acquired after cancellation")
		return nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.backfill(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.processBatch(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeBackupGatePermitSpansCanceledJobCleanup(t *testing.T) {
	started, cleanup, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var active, cleanupDone atomic.Bool
	var releases, claims atomic.Int32
	w := lifecycleWorker(&materializeLifecycleStub{
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			if !active.Load() {
				t.Error("claim outside backup permit")
			}
			if claims.Add(1) != 1 {
				return nil, nil
			}
			return []models.SkillPackageMaterializeJob{{ID: 1, InstanceID: 1}}, nil
		},
		process: func(ctx context.Context, _ int) error {
			if !active.Load() {
				t.Error("job outside backup permit")
			}
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
		release: func(int) error {
			close(cleanup)
			<-finish
			if !active.Load() {
				t.Error("permit released before claim cleanup")
			}
			cleanupDone.Store(true)
			return nil
		},
	})
	w.BackupGate = materializeBackupGateFunc(func(_ context.Context, name string) (func() error, error) {
		if name == "skill-backfill" {
			return func() error { return nil }, nil
		}
		active.Store(true)
		return func() error {
			if !cleanupDone.Load() {
				t.Error("permit released before cleanup completed")
			}
			active.Store(false)
			releases.Add(1)
			return nil
		}, nil
	})
	var once sync.Once
	defer func() {
		once.Do(func() { close(finish) })
		stopMaterializeWorker(t, w)
	}()
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitMaterializeSignal(t, started)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := w.StopAndWait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop before cleanup completed: %v", err)
	}
	awaitMaterializeSignal(t, cleanup)
	if !active.Load() || releases.Load() != 0 {
		t.Fatal("timed-out drain released a live permit")
	}
	once.Do(func() { close(finish) })
	stopMaterializeWorker(t, w)
	if active.Load() || releases.Load() != 1 {
		t.Fatal("completed drain did not release exactly one permit")
	}
}

func TestMaterializeBackupGateReleasePreservesClaimAndCleanupErrors(t *testing.T) {
	claimErr, cleanupErr, permitErr := errors.New("claim"), errors.New("cleanup"), errors.New("permit")
	var released bool
	w := lifecycleWorker(&materializeLifecycleStub{
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			return []models.SkillPackageMaterializeJob{{ID: 1}}, claimErr
		},
		release: func(int) error { released = true; return cleanupErr },
		process: func(context.Context, int) error { t.Error("processed a partial claim"); return nil },
	})
	w.BackupGate = materializeBackupGateFunc(func(context.Context, string) (func() error, error) {
		return func() error {
			if !released {
				t.Error("permit released before partial claim cleanup")
			}
			return permitErr
		}, nil
	})
	err := w.processBatch(context.Background())
	for _, want := range []error{claimErr, cleanupErr, permitErr} {
		if !errors.Is(err, want) {
			t.Fatalf("lost %v: %v", want, err)
		}
	}
}

func TestMaterializeBackupGateBackfillReleaseFailureReachesStop(t *testing.T) {
	permitErr := errors.New("backfill permit release failed")
	released := make(chan struct{})
	var active atomic.Bool
	w := lifecycleWorker(&materializeLifecycleStub{backfill: func(context.Context, int) (int, error) {
		if !active.Load() {
			t.Error("backfill outside backup permit")
		}
		return 0, nil
	}})
	w.BackupGate = materializeBackupGateFunc(func(_ context.Context, name string) (func() error, error) {
		if name != "skill-backfill" {
			return nil, errors.New("gate closed")
		}
		active.Store(true)
		return func() error { close(released); return permitErr }, nil
	})
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopMaterializeWorkerIgnoringExpectedError(w)
	awaitMaterializeSignal(t, released)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.StopAndWait(ctx); !errors.Is(err, permitErr) {
		t.Fatalf("stop lost permit release failure: %v", err)
	}
}

func stopMaterializeWorkerIgnoringExpectedError(w *SkillPackageMaterializeWorker) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = w.StopAndWait(ctx)
}

func TestMaterializeBackupGateReopensDeferredBackfillExactlyOnceBeforeClaims(t *testing.T) {
	denied, claimedTwice := make(chan struct{}), make(chan struct{})
	var deniedOnce sync.Once
	var open, backfillActive, backfillReleased atomic.Bool
	var backfills, claims, backfillReleases atomic.Int32
	w := lifecycleWorker(&materializeLifecycleStub{
		backfill: func(ctx context.Context, _ int) (int, error) {
			if ctx.Err() != nil || !backfillActive.Load() || backfills.Add(1) != 1 {
				t.Error("backfill canceled, outside permit, or repeated after admission")
			}
			return 1, nil
		},
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			if backfills.Load() != 1 || !backfillReleased.Load() || backfillActive.Load() {
				t.Error("claim preceded the admitted backfill and permit release")
			}
			if claims.Add(1) == 2 {
				close(claimedTwice)
			}
			return nil, nil
		},
	})
	w.tick = time.Millisecond
	w.BackupGate = materializeBackupGateFunc(func(_ context.Context, name string) (func() error, error) {
		if !open.Load() {
			deniedOnce.Do(func() { close(denied) })
			return nil, errors.New("gate closed")
		}
		if name == "skill-backfill" {
			backfillActive.Store(true)
			return func() error {
				backfillActive.Store(false)
				backfillReleased.Store(true)
				backfillReleases.Add(1)
				return nil
			}, nil
		}
		return func() error { return nil }, nil
	})
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopMaterializeWorker(t, w)
	awaitMaterializeSignal(t, denied)
	if backfills.Load() != 0 || claims.Load() != 0 {
		t.Fatal("closed gate allowed initial backfill or claims")
	}
	open.Store(true)
	awaitMaterializeSignal(t, claimedTwice)
	stopMaterializeWorker(t, w)
	if backfills.Load() != 1 || backfillReleases.Load() != 1 || claims.Load() < 2 {
		t.Fatal("deferred backfill was dropped or retried after admission")
	}
}

func TestMaterializeBackupGateStopCancelsDeferredBackfillWithoutWrites(t *testing.T) {
	denied := make(chan struct{})
	var deniedOnce sync.Once
	var permits atomic.Int32
	w := lifecycleWorker(&materializeLifecycleStub{
		backfill: func(context.Context, int) (int, error) {
			t.Error("backfill wrote during deferred admission")
			return 0, nil
		},
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			t.Error("claim wrote during deferred admission")
			return nil, nil
		},
	})
	w.BackupGate = materializeBackupGateFunc(func(ctx context.Context, name string) (func() error, error) {
		if name != "skill-backfill" {
			t.Error("claim crossed deferred backfill")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		permits.Add(1)
		deniedOnce.Do(func() { close(denied) })
		return nil, errors.New("gate closed")
	})
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopMaterializeWorker(t, w)
	awaitMaterializeSignal(t, denied)
	stopMaterializeWorker(t, w)
	before := permits.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.backfill(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.processBatch(ctx); err != nil || permits.Load() != before {
		t.Fatal("canceled deferred run acquired a permit")
	}
}
