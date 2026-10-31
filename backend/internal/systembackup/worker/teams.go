package worker

import (
	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/team"
	"context"
	"encoding/json"
	"github.com/minio/minio-go/v7"
	"io"
)

// Credential-free scope. A/D bind source clients through the ORIGINAL Job's
// source grant, independently of its KEK permission. No default grant exists.
type TeamCaptureSpec struct {
	InventorySHA256 string           `json:"inventory_sha256"`
	Redis           *team.RedisScope `json:"redis,omitempty"`
	Objects         []team.ObjectRef `json:"objects,omitempty"`
	MaxItems        int              `json:"max_items"`
}
type TeamCaptureSources struct {
	Redis     *c.RedisClient
	Objects   *minio.Client
	Authorize func(context.Context, Invocation) error
}

// Source authority callbacks observe detached original facts. They cannot
// mutate the frozen Redis/object scope while authorizing or retaining it.
func authorizeTeamSources(ctx context.Context, env *TeamCaptureSources, i Invocation) error {
	if env == nil || env.Authorize == nil {
		return ErrNotReady
	}
	raw, err := json.Marshal(i)
	if err != nil || len(raw) > 1<<20 {
		return ErrRequest
	}
	var bound Invocation
	if json.Unmarshal(raw, &bound) != nil {
		return ErrRequest
	}
	return env.Authorize(ctx, bound)
}

func teamCaptureOperation(op string) bool {
	return op == "capture-team-redis" || op == "capture-team-objects"
}
func validTeamCapture(r Request) bool {
	if r.ControlEvidence != nil {
		return false
	}
	if r.SourceRedis != nil || r.Resources != nil || r.TeamWorkspace != nil {
		return false
	}
	s := r.Teams
	if s == nil || !keyUseHash.MatchString(s.InventorySHA256) || !teamCaptureOperation(r.Operation) || r.Version != Version || s.MaxItems <= 0 || s.MaxItems > 10000 || r.Database != nil || r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil || r.PolicyVersion != "" || len(r.Files) != 0 || r.MaxFiles != 0 || r.MaxFileBytes != 0 || r.MaxArchiveBytes <= 0 || r.MaxArchiveBytes > 32<<20 || r.MaxCompressedBytes <= 0 || r.MaxCompressedBytes > 32<<20 || r.ArtifactName == "" {
		return false
	}
	if r.Operation == "capture-team-redis" {
		return s.Redis != nil && s.Redis.Validate() == nil && len(s.Objects) == 0
	}
	if s.Redis != nil || len(s.Objects) == 0 || len(s.Objects) > s.MaxItems {
		return false
	}
	seen := map[string]bool{}
	for _, o := range s.Objects {
		id := o.Bucket + "\x00" + o.Key
		if o.Validate() != nil || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func captureTeamSource(ctx context.Context, i Invocation, env *TeamCaptureSources, dst io.Writer, check func() error) error {
	if env == nil || env.Authorize == nil || !validTeamCapture(i.Request) {
		return ErrNotReady
	}
	guard := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if check() != nil || authorizeTeamSources(ctx, env, i) != nil {
			return ErrNotReady
		}
		return nil
	}
	r := i.Request
	s := r.Teams
	if guard(ctx) != nil {
		return ErrNotReady
	}
	if s.Redis != nil {
		return c.CaptureTeamRedisScope(ctx, env.Redis, dst, c.RedisBudget{MaxItems: s.MaxItems, MaxBytes: r.MaxArchiveBytes, MaxInventoryBytes: r.MaxArchiveBytes}, *s.Redis, guard)
	}
	return c.CaptureTeamObjectRefs(ctx, env.Objects, dst, c.ObjectBudget{MaxItems: s.MaxItems, MaxBytes: r.MaxArchiveBytes}, s.Objects, guard)
}
