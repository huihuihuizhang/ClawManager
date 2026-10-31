package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
)

func TestSourceRedisOriginalHistorySurvivesWorkerDeadlineUnderNewPublisherClaimMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	f := newPublisherHistoryFixture(t, func(options *consumerFixtureOptions) {
		options.PartName, options.Category = "source_redis", "source"
		options.RequestedParts = []string{"redis"}
		options.JobDeadlineSeconds = 1
		options.PrepareSource = func(_ *os.Root, i *worker.Invocation) {
			i.Request.Operation = "capture-source-redis"
			i.Request.Binding.Path = "source_redis"
			i.ProviderKey.Request.Context.Part = "source_redis"
			i.WorkspacePath = ""
			i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
			i.Request.SourceRedis = &c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("e", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "functional_test", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40)}
		}
		options.Configure = func(i *worker.Invocation, _ *sql.DB, _ *sql.DB, a d.Authority) {
			// This is fixed BEFORE the actual plan/candidate is encrypted. The
			// v2 task keeps its original longer four-minute absolute deadline.
			i.Request.Deadline = time.Now().UTC().Add(8 * time.Second)
			i.FormalCapture.SourceConfigSHA256 = a.ConfigSHA256
		}
		options.ConfigureWorkload = func(request *kube.JobRequest) { request.Source = corev1.Volume{}; request.SourceSubPath = "" }
		options.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "original-redis-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-redis-source", Kind: "Secret", Name: "original-redis-source", Directory: "/run/backup/materials/redis-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}
		options.RewriteCandidate = func(_ *os.Root, i worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult) {
			return forgeRedisSourceSQLCandidate(t, i, candidate, keys, "valid-nonempty")
		}
	})
	ctx := context.Background()
	if f.scope.Part != "source_redis" || !f.original.DeadlineAt.After(f.invocation.Request.Deadline) {
		t.Fatal("history fixture borrowed workspace or moved task deadline")
	}
	before, err := f.owner.Gate.Records.LoadPublisherCapture(ctx, f.access)
	if err != nil {
		t.Fatal("original current Redis history", err)
	}
	originalInvocation, _ := json.Marshal(f.invocation)
	// Same original bytes are read after the collector's window. Neither its
	// deadline nor the task/claim/plan/candidate is updated to manufacture this.
	if wait := time.Until(f.invocation.Request.Deadline) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if !time.Now().Before(f.access.ValidUntil()) || !time.Now().Before(f.original.DeadlineAt) {
		t.Fatal("current publisher/task authority expired during fixture")
	}
	if !worker.ValidateRecordedInvocation(f.invocation) || !worker.ValidateFormalCaptureResult(f.invocation, &f.candidate) {
		t.Fatal("same original historical candidate lost pure shape after worker deadline")
	}
	hash, _ := f.invocation.Hash()
	if worker.ValidateControl(worker.ControlRequest{Invocation: f.invocation, InvocationSHA256: hash, Action: "ready"}) {
		t.Fatal("historical shape revived live source execution")
	}
	after, err := f.owner.Gate.Records.LoadPublisherCapture(ctx, f.access)
	if err != nil || after.Input.TaskPublicID != f.original.TaskPublicID || after.Input.CaptureAttemptNo != 3 || after.PartResult.Part != "source_redis" || !bytes.Equal(before.CandidateJSON, after.CandidateJSON) || after.CandidateSHA256 != before.CandidateSHA256 || after.Plan.SHA256 != before.Plan.SHA256 || !after.KeyUse.Until.Equal(f.invocation.Request.Deadline) {
		t.Fatal("new concrete publisher did not read exact original Redis history after worker expiry", err)
	}
	reloaded, _ := json.Marshal(after.Invocation)
	if !bytes.Equal(originalInvocation, reloaded) {
		t.Fatal("publisher history rewrote original invocation to extend deadline")
	}
	if _, err := f.owner.ReadFormalCandidate(ctx, f.original, f.job, false); err == nil {
		t.Fatal("new publisher resurrected old capture claim")
	}
}
