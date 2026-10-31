package worker

import (
	"context"
	"io"
	"time"

	c "clawreef/internal/systembackup"
)

func sourceRedisOperation(operation string) bool { return operation == "capture-source-redis" }

func validSourceRedisRequest(r Request) bool {
	if r.ControlEvidence != nil {
		return false
	}
	return sourceRedisOperation(r.Operation) && r.Version == Version && !r.Deadline.IsZero() && r.SourceRedis != nil && r.SourceRedis.Validate() == nil && r.SkillObjects == nil && r.SkillWorkspace == nil && r.Teams == nil && r.Resources == nil && r.Database == nil && r.RuntimePolicy == nil && r.WorkBuddyIdentity == nil && r.TeamWorkspace == nil && r.PolicyVersion == "" && len(r.Files) == 0 && r.MaxFiles == 0 && r.MaxFileBytes == 0 && r.ArtifactName != "" && r.MaxArchiveBytes > 0 && r.MaxArchiveBytes <= 32<<20 && r.MaxCompressedBytes > 0 && r.MaxCompressedBytes <= 32<<20 && r.SourceRedis.Policy.MaxBytes <= r.MaxArchiveBytes
}

func captureSourceRedis(ctx context.Context, i Invocation, client *c.RedisClient, dst io.Writer, authorize func(context.Context, Invocation) error, check func() error) error {
	if client == nil || authorize == nil || check == nil || !validSourceRedisRequest(i.Request) || !time.Now().Before(i.Request.Deadline) {
		return ErrNotReady
	}
	guard := func(ctx context.Context) error {
		if check() != nil || authorize(ctx, i) != nil {
			return ErrNotReady
		}
		return ctx.Err()
	}
	return c.CaptureSourceRedis(ctx, client, dst, *i.Request.SourceRedis, guard)
}
