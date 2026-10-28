package services

import (
	"context"
	"testing"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/repository"
)

func TestSkillPackageMaterializeWorkerReleasesWhenInstanceLimitReached(t *testing.T) {
	unblock := make(chan struct{})
	repo := &workerMaterializeJobRepoStub{
		onRelease: func() { close(unblock) },
		jobs: []models.SkillPackageMaterializeJob{
			{ID: 1, InstanceID: 9, Status: MaterializeJobStatusRunning},
			{ID: 2, InstanceID: 9, Status: MaterializeJobStatusRunning},
			{ID: 3, InstanceID: 9, Status: MaterializeJobStatusRunning},
		},
	}
	// Hold admitted jobs until the excess claim is released. Fast no-op jobs
	// can finish before admission and do not test a concurrent instance limit.
	service := NewSkillPackageMaterializeService(repo, nil, cancellationMaterializer{
		materialize: func(context.Context) (*models.SkillBlob, error) {
			select {
			case <-unblock:
			case <-time.After(3 * time.Second):
				t.Error("excess claim was not released")
			}
			return &models.SkillBlob{}, nil
		},
		sync: func() error { return nil },
	})
	worker := NewSkillPackageMaterializeWorker(service, time.Second, 3, 5, 2, true)

	worker.processBatch(context.Background())

	if repo.released != 1 {
		t.Fatalf("released = %d, want 1", repo.released)
	}
}

type stubMaterializer struct{}

func (stubMaterializer) materializeSkillPackageFromWorkspace(context.Context, int, string, string, int) (*models.SkillBlob, error) {
	return &models.SkillBlob{ObjectKey: "discovered/1/demo/hash.zip", ScanStatus: "completed"}, nil
}

func (stubMaterializer) syncSkillRecordFromBlob(int, *models.SkillBlob) error { return nil }

type workerMaterializeJobRepoStub struct {
	jobs      []models.SkillPackageMaterializeJob
	released  int
	onRelease func()
}

func (s *workerMaterializeJobRepoStub) Create(*models.SkillPackageMaterializeJob) error { return nil }
func (s *workerMaterializeJobRepoStub) GetByID(id int) (*models.SkillPackageMaterializeJob, error) {
	for i := range s.jobs {
		if s.jobs[i].ID == id {
			job := s.jobs[i]
			return &job, nil
		}
	}
	return nil, nil
}
func (s *workerMaterializeJobRepoStub) GetByIdempotencyKey(string) (*models.SkillPackageMaterializeJob, error) {
	return nil, nil
}
func (s *workerMaterializeJobRepoStub) ClaimNextPending(context.Context, int) ([]models.SkillPackageMaterializeJob, error) {
	return s.jobs, nil
}
func (s *workerMaterializeJobRepoStub) MarkSucceeded(int) error            { return nil }
func (s *workerMaterializeJobRepoStub) MarkFailed(int, string, bool) error { return nil }
func (s *workerMaterializeJobRepoStub) MarkRunning(int) error              { return nil }
func (s *workerMaterializeJobRepoStub) ReleaseToPending(int) error {
	s.released++
	if s.onRelease != nil {
		s.onRelease()
	}
	return nil
}
func (s *workerMaterializeJobRepoStub) ResetForRetry(int) error { return nil }
func (s *workerMaterializeJobRepoStub) RequeueExisting(int, int, string, string) error {
	return nil
}
func (s *workerMaterializeJobRepoStub) FindLatestBySkillID(int) (*models.SkillPackageMaterializeJob, error) {
	return nil, nil
}
func (s *workerMaterializeJobRepoStub) CountPendingByInstance(int) (int, error) { return 0, nil }
func (s *workerMaterializeJobRepoStub) ListBackfillCandidates(int) ([]repository.SkillPackageMaterializeBackfillCandidate, error) {
	return nil, nil
}
