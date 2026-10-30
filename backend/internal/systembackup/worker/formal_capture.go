package worker

import (
	"context"
	"database/sql"
	"io"
	"os"
	"regexp"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/workspace"
	w "clawreef/internal/systembackupwire"
)

const FormalCaptureVersion = "public-c-stream-job.v1alpha1"

var formalFileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

// This additive spec is in the ORIGINAL frozen invocation hash. ConfigSHA256
// pins the independent deployment mapping/permit mounts, not user JSON. The
// original ProviderKey contains C's full frozen request/context; no context hash
// is inferred from source data here. A/D/C must sign off its business source.
type FormalCaptureSpec struct {
	Version      string `json:"schema_version"`
	ConfigSHA256 string `json:"config_sha256"`
	EnvelopeName string `json:"envelope_name"`
	MaxFrames    uint64 `json:"max_frames"`
}

type FormalCaptureEnvironment struct {
	Teams              *TeamCaptureSources
	Workspace, Staging *os.Root
	Database           *sql.DB // already SELECT-only admitted source; never opened from artifact
}
type FormalCaptureResult struct {
	Version          string          `json:"schema_version"`
	InvocationSHA256 string          `json:"invocation_sha256"`
	Ciphertext       staging.Receipt `json:"ciphertext"`
	Envelope         staging.Receipt `json:"envelope"`
	Files            int64           `json:"files"`
	Bytes            int64           `json:"bytes"`
	Rows             int64           `json:"rows"`
	Tables           int             `json:"tables"`
}

func validFormalInvocation(i Invocation) bool {
	f := i.FormalCapture
	if f == nil || i.ProviderKey == nil || f.Version != FormalCaptureVersion || !keyUseHash.MatchString(f.ConfigSHA256) || !formalFileName.MatchString(f.EnvelopeName) || f.EnvelopeName == i.Request.ArtifactName || !formalFileName.MatchString(i.Request.ArtifactName) || f.MaxFrames < 2 || f.MaxFrames > w.MaxStreamFrames || i.Request.MaxCompressedBytes <= 0 || i.Request.MaxCompressedBytes > int64(f.MaxFrames-1)*w.ChunkSize {
		return false
	}
	return i.Request.Operation == "capture-workspace" || i.Request.Operation == "capture-database" || (teamCaptureOperation(i.Request.Operation) && validTeamCapture(i.Request))
}

type formalKeyUse interface {
	WithDEK(context.Context, func(context.Context, []byte) error) (w.WrappedKey, error)
	Recheck(context.Context) error
	recheckDuringUse(context.Context) error
}

type originalUseSink struct {
	ctx context.Context
	job formalKeyUse
	dst io.Writer
}

func (s originalUseSink) Write(p []byte) (int, error) {
	if s.ctx.Err() != nil {
		return 0, s.ctx.Err()
	}
	if s.job.recheckDuringUse(s.ctx) != nil {
		return 0, w.ErrStreamAuthority
	}
	n, e := s.dst.Write(p)
	if e != nil {
		return n, e
	}
	if s.job.recheckDuringUse(s.ctx) != nil {
		return n, w.ErrStreamAuthority
	}
	return n, nil
}

// RunFormalCapture consumes the actual A CaptureKeyJob. Local candidates and
// the part envelope are NOT a legacy Result, Complete ACK or published backup.
// No detached producers: archive/SQL encoding exits before the DEK callback.
func RunFormalCapture(ctx context.Context, i Invocation, job *CaptureKeyJob, env FormalCaptureEnvironment) (FormalCaptureResult, error) {
	if job == nil {
		return FormalCaptureResult{}, ErrNotReady
	}
	return runFormalCapture(ctx, i, job, env)
}
func runFormalCapture(ctx context.Context, i Invocation, job formalKeyUse, env FormalCaptureEnvironment) (FormalCaptureResult, error) {
	var zero FormalCaptureResult
	if ctx == nil || job == nil || !validFormalInvocation(i) || !ValidateRecordedInvocation(i) || !time.Now().Before(i.Request.Deadline) || env.Staging == nil {
		return zero, ErrRequest
	}
	r := i.Request
	if (r.Teams == nil && r.Database == nil && (env.Workspace == nil || !separateRoots(env.Workspace, env.Staging))) || (r.Database != nil && env.Database == nil) || (r.Teams != nil && (env.Teams == nil || env.Teams.Authorize == nil || (r.Teams.Redis != nil && env.Teams.Redis == nil) || (len(r.Teams.Objects) > 0 && env.Teams.Objects == nil))) {
		return zero, ErrNotReady
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	check := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if job.Recheck(ctx) != nil {
			return ErrNotReady
		}
		if r.Teams != nil && authorizeTeamSources(ctx, env.Teams, i) != nil {
			return ErrNotReady
		}
		return nil
	}
	if e := check(); e != nil {
		return zero, e
	}
	// A known candidate/partial must be reconciled by the original owner; do
	// not consume a new Generate for the same envelope or overwrite old bytes.
	for _, name := range []string{r.ArtifactName, i.FormalCapture.EnvelopeName, "." + r.ArtifactName + ".partial", "." + i.FormalCapture.EnvelopeName + ".partial"} {
		if _, e := env.Staging.Lstat(name); !os.IsNotExist(e) {
			return zero, ErrNotReady
		}
	}
	invocationHash, err := i.Hash()
	if err != nil {
		return zero, ErrRequest
	}
	result := FormalCaptureResult{Version: "public-c-stream-candidate.v1alpha1", InvocationSHA256: invocationHash}
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: r.ArtifactName, MaxPlaintextBytes: r.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	var seal w.StreamSeal
	wrapped, err := job.WithDEK(ctx, func(useCtx context.Context, key []byte) error {
		inUseCheck := func() error {
			if useCtx.Err() != nil {
				return useCtx.Err()
			}
			if job.recheckDuringUse(useCtx) != nil {
				return ErrNotReady
			}
			return nil
		}
		if e := inUseCheck(); e != nil {
			return e
		}
		var err error
		result.Ciphertext, err = staging.WriteUnpublishedFile(useCtx, env.Staging, r.ArtifactName, func(dst io.Writer) error {
			var e error
			seal, e = w.EncryptStream(useCtx, spec, key, originalUseSink{useCtx, job, dst}, func(stream io.Writer) error {
				if r.Teams != nil {
					return staging.Compress(stream, func(compressed io.Writer) error {
						return captureTeamSource(useCtx, i, env.Teams, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, inUseCheck)
					})
				}
				if r.Database != nil {
					s, e := domain.CaptureSource(useCtx, env.Database, domain.Limits{MaxRows: r.Database.MaxRows, MaxBytes: r.Database.MaxMemoryBytes}, r.Database.Name, r.Database.ServerUUID)
					if e != nil {
						return ErrExecution
					}
					defer clearSnapshot(s)
					if r.Database.TeamsInventory != nil && domain.VerifyTeamCapture(s, *r.Database.TeamsInventory) != nil {
						return ErrExecution
					}
					counts := snapshotCounts(s)
					result.Rows, result.Tables = counts.Rows, counts.Tables
					return staging.Compress(stream, func(compressed io.Writer) error {
						if e := domain.Encode(&budgetWriter{w: compressed, left: r.MaxArchiveBytes}, s); e != nil {
							return ErrExecution
						}
						return inUseCheck()
					})
				}
				if r.WorkBuddyIdentity != nil && domain.VerifyWorkBuddyUIDWorkspace(env.Workspace, *r.WorkBuddyIdentity) != nil {
					return ErrExecution
				}
				var layout workspace.Layout
				if r.RuntimePolicy != nil {
					if e := CheckRuntimeFiles(useCtx, env.Workspace, *r.RuntimePolicy); e != nil {
						return e
					}
					layout = r.RuntimePolicy.WorkspaceLayout
				}
				e := staging.Compress(stream, func(compressed io.Writer) error {
					report, e := workspace.ArchiveWithLayout(useCtx, env.Workspace, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, workspace.Limits{MaxFiles: r.MaxFiles, MaxBytes: r.MaxFileBytes}, layout)
					if e != nil {
						return ErrExecution
					}
					result.Files, result.Bytes = report.Files, report.Bytes
					return inUseCheck()
				})
				if e != nil {
					return e
				}
				if r.WorkBuddyIdentity != nil && domain.VerifyWorkBuddyUIDWorkspace(env.Workspace, *r.WorkBuddyIdentity) != nil {
					return ErrExecution
				}
				return inUseCheck()
			})
			return e
		})
		return err
	})
	if err != nil {
		return zero, formalFailure(err)
	} // unknown use/provider outcome is never retried here
	if result.Ciphertext.SHA256 != seal.CiphertextSHA256() || result.Ciphertext.Size != seal.CiphertextBytes() {
		return zero, ErrExecution
	}
	if err = check(); err != nil {
		return zero, err
	}
	envelope, err := seal.EnvelopeJSON(wrapped)
	if err != nil {
		return zero, ErrExecution
	}
	result.Envelope, err = staging.WriteUnpublishedFile(ctx, env.Staging, i.FormalCapture.EnvelopeName, func(dst io.Writer) error {
		if e := check(); e != nil {
			return e
		}
		_, e := dst.Write(envelope)
		return e
	})
	if err != nil {
		return zero, ErrExecution
	}
	if err = check(); err != nil {
		return zero, err
	}
	return result, nil
}
