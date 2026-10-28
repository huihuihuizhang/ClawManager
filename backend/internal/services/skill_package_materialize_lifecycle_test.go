package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/repository"
)

type materializeLifecycleStub struct {
	backfill func(context.Context, int) (int, error)
	claim    func(context.Context, int) ([]models.SkillPackageMaterializeJob, error)
	process  func(context.Context, int) error
	release  func(int) error
}

func (s *materializeLifecycleStub) BackfillOnce(ctx context.Context, n int) (int, error) {
	if s.backfill != nil {
		return s.backfill(ctx, n)
	}
	return 0, nil
}
func (s *materializeLifecycleStub) ClaimNextPending(ctx context.Context, n int) ([]models.SkillPackageMaterializeJob, error) {
	if s.claim != nil {
		return s.claim(ctx, n)
	}
	return nil, nil
}
func (s *materializeLifecycleStub) ProcessJob(ctx context.Context, id int) error {
	return s.process(ctx, id)
}
func (s *materializeLifecycleStub) ReleaseToPending(id int) error { return s.release(id) }

func lifecycleWorker(s *materializeLifecycleStub) *SkillPackageMaterializeWorker {
	w := NewSkillPackageMaterializeWorker(nil, time.Millisecond, 5, 1, 2, true)
	w.service = s
	return w
}
func awaitMaterializeSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not reach expected state")
	}
}
func stopMaterializeWorker(t *testing.T, w *SkillPackageMaterializeWorker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.StopAndWait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeWorkerStopTimeoutDoesNotAllowOverlappingRestart(t *testing.T) {
	entered, unblock, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := &materializeLifecycleStub{backfill: func(ctx context.Context, _ int) (int, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-unblock // models a DB call that cannot yet accept context
		}
		return 0, ctx.Err()
	}}
	w := lifecycleWorker(s)
	defer stopMaterializeWorker(t, w)
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitMaterializeSignal(t, entered)
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A live run's repeated Start must not create another backfill.
	if calls.Load() != 1 {
		t.Fatal("duplicate run")
	}
	deadline, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := w.StopAndWait(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop = %v", err)
	}
	awaitMaterializeSignal(t, canceled)
	restartCtx, restartCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer restartCancel()
	if err := w.StartContext(restartCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restart = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("restart overlapped unfinished work")
	}
	once.Do(func() { close(unblock) })
	stopMaterializeWorker(t, w)
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopMaterializeWorker(t, w)
}

func TestMaterializeWorkerStopJoinsJobsAndReleasesUnstartedClaims(t *testing.T) {
	started, observedCancel, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var claimCalls, processCalls atomic.Int32
	var mu sync.Mutex
	released := map[int]int{}
	s := &materializeLifecycleStub{
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			if claimCalls.Add(1) != 1 {
				return nil, nil
			}
			return []models.SkillPackageMaterializeJob{{ID: 1, InstanceID: 1}, {ID: 2, InstanceID: 2}, {ID: 3, InstanceID: 3}}, nil
		},
		process: func(ctx context.Context, _ int) error {
			processCalls.Add(1)
			close(started)
			<-ctx.Done()
			close(observedCancel)
			<-finish
			return ctx.Err()
		},
		release: func(id int) error { mu.Lock(); defer mu.Unlock(); released[id]++; return nil },
	}
	w := lifecycleWorker(s)
	defer stopMaterializeWorker(t, w)
	var once sync.Once
	defer once.Do(func() { close(finish) })
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitMaterializeSignal(t, started)
	stopped := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stopped <- w.StopAndWait(ctx)
		}()
	}
	awaitMaterializeSignal(t, observedCancel)
	select {
	case err := <-stopped:
		t.Fatalf("stop returned before job exited: %v", err)
	default:
	}
	once.Do(func() { close(finish) })
	for i := 0; i < 2; i++ {
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
	}
	if processCalls.Load() != 1 || claimCalls.Load() != 1 {
		t.Fatalf("process=%d claim=%d", processCalls.Load(), claimCalls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range []int{1, 2, 3} {
		if released[id] != 1 {
			t.Fatalf("job %d release count = %d", id, released[id])
		}
	}
}

func TestMaterializeWorkerParentCancellationStopsBackfill(t *testing.T) {
	entered := make(chan struct{})
	s := &materializeLifecycleStub{backfill: func(ctx context.Context, _ int) (int, error) {
		close(entered)
		<-ctx.Done()
		return 0, ctx.Err()
	}, claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
		t.Error("claimed after backfill cancellation")
		return nil, nil
	}}
	w := lifecycleWorker(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.StartContext(ctx); err != nil {
		t.Fatal(err)
	}
	awaitMaterializeSignal(t, entered)
	cancel()
	stopMaterializeWorker(t, w)
}

func TestMaterializeWorkerPartialClaimsAreReleasedAndErrorsPreserved(t *testing.T) {
	claimErr, releaseErr := errors.New("claim interrupted"), errors.New("release failed")
	released := []int{}
	s := &materializeLifecycleStub{
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			return []models.SkillPackageMaterializeJob{{ID: 1}, {ID: 2}}, claimErr
		},
		process: func(context.Context, int) error { t.Error("processed partial batch"); return nil },
		release: func(id int) error {
			released = append(released, id)
			if id == 1 {
				return releaseErr
			}
			return nil
		},
	}
	err := lifecycleWorker(s).processBatch(context.Background())
	if !errors.Is(err, claimErr) || !errors.Is(err, releaseErr) {
		t.Fatalf("lost error: %v", err)
	}
	if len(released) != 2 {
		t.Fatalf("released=%v", released)
	}
}

func TestMaterializeWorkerStopReportsCleanupFailure(t *testing.T) {
	entered := make(chan struct{})
	cleanupErr := errors.New("queue unavailable")
	s := &materializeLifecycleStub{
		claim: func(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
			return []models.SkillPackageMaterializeJob{{ID: 1}}, nil
		},
		process: func(ctx context.Context, _ int) error { close(entered); <-ctx.Done(); return ctx.Err() },
		release: func(int) error { return cleanupErr },
	}
	w := lifecycleWorker(s)
	if err := w.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitMaterializeSignal(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		if err := w.StopAndWait(ctx); !errors.Is(err, cleanupErr) {
			t.Fatalf("stop = %v", err)
		}
	}
}

type cancellationMaterializer struct {
	materialize func(context.Context) (*models.SkillBlob, error)
	sync        func() error
}

func (m cancellationMaterializer) materializeSkillPackageFromWorkspace(ctx context.Context, _ int, _, _ string, _ int) (*models.SkillBlob, error) {
	return m.materialize(ctx)
}
func (m cancellationMaterializer) syncSkillRecordFromBlob(int, *models.SkillBlob) error {
	return m.sync()
}

func TestMaterializeProcessCancellationDoesNotWriteTerminalStatus(t *testing.T) {
	for _, stage := range []string{"before", "materialize_error", "materialize_success", "sync_error", "sync_success", "child_deadline"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			job := &models.SkillPackageMaterializeJob{ID: 1, Status: MaterializeJobStatusRunning}
			repo := &materializeJobRepoStub{created: []*models.SkillPackageMaterializeJob{job}}
			syncCalls := 0
			m := cancellationMaterializer{
				materialize: func(context.Context) (*models.SkillBlob, error) {
					if stage == "before" {
						t.Fatal("called materializer after cancellation")
					}
					if stage == "child_deadline" {
						return nil, context.DeadlineExceeded
					}
					if stage == "materialize_error" || stage == "materialize_success" {
						cancel()
					}
					if stage == "materialize_error" {
						return nil, errors.New("request aborted")
					}
					return &models.SkillBlob{}, nil
				},
				sync: func() error {
					syncCalls++
					cancel()
					if stage == "sync_error" {
						return errors.New("aborted")
					}
					return nil
				},
			}
			if stage == "before" {
				cancel()
			}
			err := NewSkillPackageMaterializeService(repo, nil, m).ProcessJob(ctx, 1)
			expected := context.Canceled
			if stage == "child_deadline" {
				expected = context.DeadlineExceeded
			}
			if !errors.Is(err, expected) {
				t.Fatalf("error=%v", err)
			}
			if job.Status != MaterializeJobStatusRunning || job.LastError != nil {
				t.Fatalf("wrote terminal state: %#v", job)
			}
			wantSync := 0
			if stage == "sync_error" || stage == "sync_success" {
				wantSync = 1
			}
			if syncCalls != wantSync {
				t.Fatalf("sync calls=%d want=%d", syncCalls, wantSync)
			}
		})
	}
}

func TestMaterializeProcessRejectsTerminalJobs(t *testing.T) {
	for _, status := range []string{MaterializeJobStatusSucceeded, MaterializeJobStatusFailed, MaterializeJobStatusCancelled} {
		t.Run(status, func(t *testing.T) {
			repo := &materializeJobRepoStub{latest: &models.SkillPackageMaterializeJob{ID: 1, Status: status}}
			m := cancellationMaterializer{materialize: func(context.Context) (*models.SkillBlob, error) { t.Fatal("terminal job executed"); return nil, nil }}
			if err := NewSkillPackageMaterializeService(repo, nil, m).ProcessJob(context.Background(), 1); err == nil {
				t.Fatal("expected non-running error")
			}
		})
	}
}

type canceledBackfillRepo struct {
	repository.SkillPackageMaterializeJobRepository
	cancel context.CancelFunc
}

func (r canceledBackfillRepo) ListBackfillCandidates(int) ([]repository.SkillPackageMaterializeBackfillCandidate, error) {
	r.cancel()
	return []repository.SkillPackageMaterializeBackfillCandidate{{InstanceID: 1, SkillID: 1, BlobID: 1, WorkspaceDir: "demo", ContentHash: "hash"}}, nil
}
func TestMaterializeBackfillCancellationPreventsEnqueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := NewSkillPackageMaterializeService(canceledBackfillRepo{cancel: cancel}, nil, nil)
	count, err := svc.BackfillOnce(ctx, 10)
	if count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("count=%d error=%v", count, err)
	}
}

type cancelingSkillScanner struct {
	SkillScannerClient
	cancel   context.CancelFunc
	expected context.Context
	t        *testing.T
}

func (s cancelingSkillScanner) ScanArchive(ctx context.Context, _ string, _ []byte, _ map[string]string) (string, map[string]interface{}, string, error) {
	if ctx != s.expected {
		s.t.Error("scanner lost worker context")
	}
	s.cancel()
	return "", nil, "", ctx.Err()
}
func TestMaterializeScanCancellationDoesNotWriteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := &skillService{scanner: cancelingSkillScanner{cancel: cancel, expected: ctx, t: t}}
	// A nil repo deliberately fails if cancellation causes any scan-result/blob write.
	blob := &models.SkillBlob{ID: 1, FileName: "demo.zip", ScanStatus: "pending"}
	dir := &extractedSkillDirectory{Name: "demo", Files: map[string][]byte{"SKILL.md": []byte("# Demo")}}
	if err := svc.recordScanContext(ctx, blob, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("scan=%v", err)
	}
	if blob.ScanStatus != "pending" {
		t.Fatalf("scan status=%s", blob.ScanStatus)
	}
}

type cancelAfterMaterializeUpload struct {
	ObjectStorageService
	cancel context.CancelFunc
}

func (s cancelAfterMaterializeUpload) PutObject(context.Context, string, []byte, string) error {
	s.cancel()
	return nil
}

type absentMaterializeBlobRepo struct{ repository.SkillRepository }

func (absentMaterializeBlobRepo) GetBlobByContentHash(string) (*models.SkillBlob, error) {
	return nil, nil
}

func TestMaterializeUploadCancellationPreventsBlobWrite(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc := &skillService{repo: absentMaterializeBlobRepo{}, storage: cancelAfterMaterializeUpload{cancel: cancel}}
			var blob *models.SkillBlob
			if existing {
				blob = &models.SkillBlob{ID: 1, ContentHash: "hash"}
			}
			dir := extractedSkillDirectory{Name: "demo", Files: map[string][]byte{"SKILL.md": []byte("# Demo")}}
			// A nil embedded repository panics if upload cancellation reaches CreateBlob/UpdateBlob.
			if _, err := svc.persistDiscoveredSkillPackage(ctx, 1, dir, "hash", blob); !errors.Is(err, context.Canceled) {
				t.Fatalf("persist=%v", err)
			}
		})
	}
}

type cancelMaterializeEnqueueRepo struct {
	repository.SkillPackageMaterializeJobRepository
	cancel context.CancelFunc
}

func (r cancelMaterializeEnqueueRepo) GetByIdempotencyKey(string) (*models.SkillPackageMaterializeJob, error) {
	r.cancel()
	return &models.SkillPackageMaterializeJob{ID: 1, Status: MaterializeJobStatusFailed}, nil
}
func TestMaterializeEnqueueCancellationPreventsRequeue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := NewSkillPackageMaterializeService(cancelMaterializeEnqueueRepo{cancel: cancel}, nil, nil)
	_, err := svc.Enqueue(ctx, EnqueueMaterializeRequest{InstanceID: 1, SkillID: 1, BlobID: 1, WorkspaceDir: "demo", ContentHash: "hash"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("enqueue=%v", err)
	}
}
