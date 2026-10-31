package worker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/workspace"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

const FormalCaptureVersion = "public-c-stream-job.v1alpha1"

var formalFileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

// This additive spec is in the ORIGINAL frozen invocation hash. ConfigSHA256
// pins the independent deployment mapping/permit mounts, not user JSON. The
// original ProviderKey contains C's full frozen request/context; no context hash
// is inferred from source data here. A/D/C must sign off its business source.
type FormalCaptureSpec struct {
	Version            string               `json:"schema_version"`
	ConfigSHA256       string               `json:"config_sha256"`
	EnvelopeName       string               `json:"envelope_name"`
	MaxFrames          uint64               `json:"max_frames"`
	PermitDelivery     *k.PermitDeliveryPin `json:"permit_delivery,omitempty"`
	SourceConfigSHA256 string               `json:"source_config_sha256,omitempty"`
}

type FormalCaptureEnvironment struct {
	ControlEvidence    *ControlEvidenceCaptureSources
	Teams              *TeamCaptureSources
	SourceRedis        *c.RedisClient
	Workspace, Staging *os.Root
	Database           *sql.DB // already SELECT-only admitted source; never opened from artifact
	Resources          *ResourceCaptureSources
	SkillObjects       *SkillObjectCaptureSources
	SourceAuthorize    func(context.Context, Invocation) error
	SourceValidUntil   time.Time
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

// This validates only the original unpublished report's shape and binding.
// It proves neither stream authenticity nor immutable artifact publication.
func ValidateFormalCaptureResult(i Invocation, r *FormalCaptureResult) bool {
	// Durable candidate shape uses the original bytes after the collector's
	// deadline too. Live execution still uses ValidateControl/runFormalCapture.
	if r == nil || i.FormalCapture == nil || i.ProviderKey == nil || !ValidateRecordedInvocation(i) || r.Version != "public-c-stream-candidate.v1alpha1" || !validReceipt(r.Ciphertext) || !validReceipt(r.Envelope) || r.Ciphertext.Name != i.Request.ArtifactName || r.Envelope.Name != i.FormalCapture.EnvelopeName || r.Envelope.Size > 32<<20 || !keyUseHash.MatchString(r.Ciphertext.SHA256) || !keyUseHash.MatchString(r.Envelope.SHA256) || r.Files < 0 || r.Bytes < 0 || r.Rows < 0 || r.Tables < 0 {
		return false
	}
	hash, err := i.Hash()
	if err != nil || r.InvocationSHA256 != hash || r.Ciphertext.Size > i.Request.MaxCompressedBytes+int64(i.FormalCapture.MaxFrames)*4096+8192 {
		return false
	}
	if i.Request.Database != nil {
		return r.Files == 0 && r.Bytes == 0 && r.Rows <= i.Request.Database.MaxRows && r.Tables > 0 && r.Tables <= 1000
	}
	if i.Request.ControlEvidence != nil || i.Request.SourceRedis != nil || i.Request.Teams != nil || i.Request.Resources != nil || i.Request.SkillObjects != nil {
		return r.Files == 0 && r.Bytes == 0 && r.Rows == 0 && r.Tables == 0
	}
	return r.Files <= int64(i.Request.MaxFiles) && r.Bytes <= i.Request.MaxFileBytes && r.Rows == 0 && r.Tables == 0
}

func FormalCandidateSHA256(i Invocation, r *FormalCaptureResult) string {
	if !ValidateFormalCaptureResult(i, r) {
		return ""
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ReportCandidate retries ONLY the same metadata, bounded by the original key
// window. It never reserves another nonce, invokes Generate, or reports a
// completed module. A lost ACK cannot create a second stream.
func (j *CaptureKeyJob) ReportCandidate(ctx context.Context, i Invocation, r FormalCaptureResult) error {
	if j == nil || j.original == nil || j.original.client == nil || ctx == nil || !ValidateFormalCaptureResult(i, &r) {
		return ErrExecution
	}
	a := j.original
	hash, err := i.Hash()
	if err != nil || hash != a.lease.Identity.InvocationSHA256 {
		return ErrExecution
	}
	ctx, cancel := context.WithDeadline(ctx, a.lease.Until)
	defer cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || !a.used {
		return ErrExecution
	}
	for {
		lease, err := a.client.send(ctx, ControlRequest{Invocation: a.invocation, InvocationSHA256: hash, Action: "candidate", Point: a.lease.Nonce, Candidate: &r})
		if err == nil {
			if lease.KeyUse == nil {
				err = ErrExecution
			} else {
				got, want := *lease.KeyUse, a.lease
				got.State, want.State = "", ""
				if got != want {
					err = ErrExecution
				}
			}
		}
		lease.Clear()
		if !errors.Is(err, ErrNotReady) {
			return err
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validFormalInvocation(i Invocation) bool {
	if i.Request.TeamWorkspace != nil {
		return false
	}
	f := i.FormalCapture
	if f == nil || i.ProviderKey == nil || f.Version != FormalCaptureVersion || !keyUseHash.MatchString(f.ConfigSHA256) || !formalFileName.MatchString(f.EnvelopeName) || f.EnvelopeName == i.Request.ArtifactName || !formalFileName.MatchString(i.Request.ArtifactName) || f.MaxFrames < 2 || f.MaxFrames > w.MaxStreamFrames || i.Request.MaxCompressedBytes <= 0 || i.Request.MaxCompressedBytes > int64(f.MaxFrames-1)*w.ChunkSize {
		return false
	}
	if f.PermitDelivery != nil && !k.ValidPermitDeliveryPin(*f.PermitDelivery) {
		return false
	}
	if i.Request.ControlEvidence != nil && (f.PermitDelivery == nil || f.SourceConfigSHA256 != i.Request.ControlEvidence.Expected.ConfigSHA256) {
		return false
	}
	if f.SourceConfigSHA256 != "" && (!keyUseHash.MatchString(f.SourceConfigSHA256) || (i.Request.ControlEvidence == nil && i.Request.SourceRedis == nil && i.Request.Database == nil && i.Request.Teams == nil && i.Request.SkillObjects == nil)) {
		return false
	}
	return i.Request.Operation == "capture-workspace" || i.Request.Operation == "capture-database" || (controlEvidenceOperation(i.Request.Operation) && validControlEvidenceRequest(i.Request)) || (sourceRedisOperation(i.Request.Operation) && validSourceRedisRequest(i.Request)) || (teamCaptureOperation(i.Request.Operation) && validTeamCapture(i.Request)) || (resourceCaptureOperation(i.Request.Operation) && validResourceCapture(i.Request)) || (skillObjectOperation(i.Request.Operation) && validSkillObjectRequest(i.Request))
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
	if (r.ControlEvidence != nil && env.ControlEvidence == nil) || (r.ControlEvidence == nil && r.SourceRedis == nil && r.Teams == nil && r.Resources == nil && r.Database == nil && r.SkillObjects == nil && (env.Workspace == nil || !separateRoots(env.Workspace, env.Staging))) || (r.SourceRedis != nil && (env.SourceRedis == nil || env.SourceAuthorize == nil)) || (r.Database != nil && env.Database == nil) || (r.Teams != nil && (env.Teams == nil || env.Teams.Authorize == nil || (r.Teams.Redis != nil && env.Teams.Redis == nil) || (len(r.Teams.Objects) > 0 && env.Teams.Objects == nil))) || (r.Resources != nil && (env.Resources == nil || env.Resources.Client == nil || env.Resources.Authorize == nil)) || (r.SkillObjects != nil && (env.SkillObjects == nil || env.SkillObjects.Reader == nil || env.SkillObjects.Authorize == nil)) {
		return zero, ErrNotReady
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	if i.FormalCapture.SourceConfigSHA256 != "" {
		if env.SourceAuthorize == nil || env.SourceValidUntil.IsZero() || !time.Now().Before(env.SourceValidUntil) {
			return zero, ErrNotReady
		}
		var sourceCancel context.CancelFunc
		ctx, sourceCancel = context.WithDeadline(ctx, env.SourceValidUntil)
		defer sourceCancel()
	}
	check := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if job.Recheck(ctx) != nil {
			return ErrNotReady
		}
		if r.ControlEvidence != nil && env.ControlEvidence.Authorize(ctx, i) != nil {
			return ErrNotReady
		}
		if (r.SourceRedis != nil || r.Database != nil) && env.SourceAuthorize != nil && env.SourceAuthorize(ctx, i) != nil {
			return ErrNotReady
		}
		if r.Teams != nil && authorizeTeamSources(ctx, env.Teams, i) != nil {
			return ErrNotReady
		}
		if r.SkillObjects != nil && authorizeSkillObjects(ctx, env.SkillObjects, i) != nil {
			return ErrNotReady
		}
		if r.Resources != nil && authorizeResourceSource(ctx, env.Resources, i) != nil {
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
			if r.ControlEvidence != nil && env.ControlEvidence.Authorize(useCtx, i) != nil {
				return ErrNotReady
			}
			if (r.SourceRedis != nil || r.Database != nil) && env.SourceAuthorize != nil && env.SourceAuthorize(useCtx, i) != nil {
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
				if r.ControlEvidence != nil {
					return captureControlEvidence(useCtx, i, env.ControlEvidence, &budgetWriter{w: stream, left: r.MaxArchiveBytes}, inUseCheck)
				}
				if r.SourceRedis != nil {
					return staging.Compress(stream, func(compressed io.Writer) error {
						return captureSourceRedis(useCtx, i, env.SourceRedis, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, env.SourceAuthorize, inUseCheck)
					})
				}
				if r.SkillObjects != nil {
					return staging.Compress(stream, func(compressed io.Writer) error {
						return captureSkillObjects(useCtx, env.SkillObjects, i, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, inUseCheck)
					})
				}
				if r.Resources != nil {
					return staging.Compress(stream, func(compressed io.Writer) error {
						return captureResourceSource(useCtx, env.Resources, i, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, inUseCheck)
					})
				}
				if r.Teams != nil {
					return staging.Compress(stream, func(compressed io.Writer) error {
						return captureTeamSource(useCtx, i, env.Teams, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, inUseCheck)
					})
				}
				if r.Database != nil {
					capture := domain.CaptureSource
					if env.SourceAuthorize != nil {
						capture = func(ctx context.Context, db *sql.DB, limits domain.Limits, name, uuid string) (domain.Snapshot, error) {
							checkSource := func(ctx context.Context) error {
								if env.SourceAuthorize(ctx, i) != nil {
									return ErrNotReady
								}
								return inUseCheck()
							}
							if r.Database.SourceScope == domain.BusinessTableSourceScope {
								if r.Database.SchemaCensus == nil {
									return domain.Snapshot{}, ErrNotReady
								}
								return domain.CaptureBusinessSourceGuarded(ctx, db, limits, name, uuid, checkSource, *r.Database.SchemaCensus)
							}
							return domain.CaptureSourceGuarded(ctx, db, limits, name, uuid, checkSource)
						}
					}
					if r.Database.SourceScope != "" && env.SourceAuthorize == nil {
						return ErrNotReady
					}
					s, e := capture(useCtx, env.Database, domain.Limits{MaxRows: r.Database.MaxRows, MaxBytes: r.Database.MaxMemoryBytes}, r.Database.Name, r.Database.ServerUUID)
					if e != nil {
						return ErrExecution
					}
					defer clearSnapshot(s)
					if r.Database.SourceScope == domain.BusinessTableSourceScope && (r.Database.CaptureSchema == nil || r.Database.CaptureSchema.PolicySHA256 != domain.BusinessCapturePolicySHA256() || domain.VerifyBusinessCapturedSnapshot(s, *r.Database.CaptureSchema) != nil) {
						return ErrExecution
					}
					if r.Database.TeamsInventory != nil && domain.VerifyTeamCapture(s, *r.Database.TeamsInventory) != nil {
						return ErrExecution
					}
					if r.Database.SkillsInventory != nil && domain.VerifySkillCapture(s, *r.Database.SkillsInventory) != nil {
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
