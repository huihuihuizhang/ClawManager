// Package worker runs bounded domain data-plane operations. Authorization,
// source quiescence and observed target isolation are supplied by the controller;
// this package never loads kubeconfig or starts an application runtime.
package worker

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/workspace"
)

const Version = "users-instances-worker.v1alpha1"

var (
	ErrRequest   = errors.New("invalid backup worker request")
	ErrNotReady  = errors.New("backup worker authorization or isolation unavailable")
	ErrExecution = errors.New("backup worker operation failed; quarantine is not ready")
)

type FileRule struct {
	Path     string            `json:"path"`
	Format   string            `json:"format,omitempty"`
	Required bool              `json:"required"`
	Fields   []domain.JSONRule `json:"fields"`
}
type Request struct {
	Version            string          `json:"version"`
	Operation          string          `json:"operation"`
	Binding            staging.Binding `json:"binding"`
	Deadline           time.Time       `json:"deadline"`
	ArtifactName       string          `json:"artifact_name"`
	Receipt            staging.Receipt `json:"receipt"`
	MaxFiles           int64           `json:"max_files"`
	MaxFileBytes       int64           `json:"max_file_bytes"`
	MaxArchiveBytes    int64           `json:"max_archive_bytes"`
	MaxCompressedBytes int64           `json:"max_compressed_bytes"`
	PolicyVersion      string          `json:"policy_version"`
	Files              []FileRule      `json:"files"`
	Database           *DatabaseSpec   `json:"database,omitempty"`
	RuntimePolicy      *RuntimePolicy  `json:"runtime_policy,omitempty"`
	// Expected identity comes from the authenticated SQL snapshot and is frozen
	// into the authorized invocation, never inferred from workspace content.
	WorkBuddyIdentity *domain.WorkBuddyUIDIdentity `json:"workbuddy_identity,omitempty"`
}
type Environment struct {
	Workspace     *os.Root
	Staging       *os.Root
	Key           []byte
	PreserveOwner bool
	// Check must revalidate the authorized request, source capture fence or
	// observed target identity at every boundary. A nil check never permits IO.
	Check func(context.Context, string, Request) error
}
type Result struct {
	Receipt         staging.Receipt `json:"receipt"`
	Files           int64           `json:"files"`
	Bytes           int64           `json:"bytes"`
	NormalizedFiles int             `json:"normalized_files"`
	// Even a successful restore remains quarantined until an independent
	// verifier and the shared controller complete their own checks.
	Quarantined bool            `json:"quarantined"`
	Rows        int64           `json:"rows,omitempty"`
	Tables      int             `json:"tables,omitempty"`
	Verified    bool            `json:"verified,omitempty"`
	Evidence    staging.Receipt `json:"evidence,omitempty"`
}

func Run(ctx context.Context, r Request, env Environment) (Result, error) {
	if assetOperation(r.Operation) {
		return RunAssets(ctx, r, env)
	}
	if r.Database != nil || r.Version != Version || (r.Operation != "capture-workspace" && r.Operation != "restore-workspace") || !time.Now().Before(r.Deadline) || r.MaxFiles <= 0 || r.MaxFiles > 1_000_000 || r.MaxFileBytes <= 0 || r.MaxArchiveBytes < r.MaxFileBytes || r.MaxCompressedBytes <= 0 || r.MaxArchiveBytes > 1<<50 || r.MaxCompressedBytes > 1<<50 || len(env.Key) != 32 || env.Workspace == nil || env.Staging == nil {
		return Result{}, ErrRequest
	}
	if env.Check == nil {
		return Result{}, ErrNotReady
	}
	if !validWorkBuddyIdentityRequest(r) {
		return Result{}, ErrRequest
	}
	if !separateRoots(env.Workspace, env.Staging) {
		return Result{}, ErrRequest
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	check := func(point string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if env.Check(ctx, point, r) != nil {
			return ErrNotReady
		}
		return nil
	}
	if e := check("prepare"); e != nil {
		return Result{}, e
	}
	key := append([]byte(nil), env.Key...)
	defer clear(key)
	limits := workspace.Limits{MaxFiles: r.MaxFiles, MaxBytes: r.MaxFileBytes}
	var layout workspace.Layout
	if r.RuntimePolicy != nil {
		if r.RuntimePolicy.Validate() != nil {
			return Result{}, ErrRequest
		}
		layout = r.RuntimePolicy.WorkspaceLayout
		// Rules and release version must be the same policy frozen in the plan.
		if r.Operation == "restore-workspace" && !reflect.DeepEqual(r.Files, r.RuntimePolicy.Files) {
			return Result{}, ErrRequest
		}
	}
	if r.Operation == "capture-workspace" {
		if r.WorkBuddyIdentity != nil && domain.VerifyWorkBuddyUIDWorkspace(env.Workspace, *r.WorkBuddyIdentity) != nil {
			return Result{}, ErrExecution
		}
		if r.RuntimePolicy != nil {
			if e := CheckRuntimeFiles(ctx, env.Workspace, *r.RuntimePolicy); e != nil {
				return Result{}, e
			}
		}
		if r.ArtifactName == "" || len(r.Files) != 0 || r.PolicyVersion != "" {
			return Result{}, ErrRequest
		}
		if e := check("before-capture"); e != nil {
			return Result{}, e
		}
		var report workspace.Report
		receipt, e := staging.SealFile(ctx, env.Staging, r.ArtifactName, key, r.Binding, func(encrypted io.Writer) error {
			return staging.Compress(&budgetWriter{w: encrypted, left: r.MaxCompressedBytes}, func(compressed io.Writer) error {
				var e error
				report, e = workspace.ArchiveWithLayout(ctx, env.Workspace, &budgetWriter{w: compressed, left: r.MaxArchiveBytes}, limits, layout)
				if e != nil {
					return e
				}
				return check("before-seal")
			})
		})
		if e != nil {
			return Result{}, captureFailure(e)
		}
		if e = check("sealed"); e != nil {
			return Result{}, e
		}
		if r.WorkBuddyIdentity != nil && domain.VerifyWorkBuddyUIDWorkspace(env.Workspace, *r.WorkBuddyIdentity) != nil {
			return Result{}, ErrExecution
		}
		return Result{Receipt: receipt, Files: report.Files, Bytes: report.Bytes}, nil
	}
	if r.PolicyVersion == "" || len(r.Files) == 0 || len(r.Files) > 256 || r.Receipt.Name == "" {
		return Result{}, ErrRequest
	}
	if r.RuntimePolicy != nil && r.RuntimePolicy.Validate() != nil {
		return Result{}, ErrRequest
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if !relativeFile(f.Path) || seen[f.Path] || len(f.Fields) == 0 || !domain.ConfigFormatSupported(f.Format) {
			return Result{}, ErrRequest
		}
		seen[f.Path] = true
	}
	f, e := staging.OpenFile(ctx, env.Staging, r.Receipt)
	if e != nil {
		return Result{}, ErrExecution
	}
	defer f.Close()
	// Authenticate and decompress the whole object before any target mutation.
	if e = staging.ConsumeCompressed(ctx, f, key, r.Binding, r.MaxCompressedBytes, r.MaxArchiveBytes, func(plain io.Reader) error { _, e := io.Copy(io.Discard, plain); return e }); e != nil {
		return Result{}, ErrExecution
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return Result{}, ErrExecution
	}
	if e = check("before-restore"); e != nil {
		return Result{}, e
	}
	var report workspace.Report
	e = staging.ConsumeCompressed(ctx, f, key, r.Binding, r.MaxCompressedBytes, r.MaxArchiveBytes, func(plain io.Reader) error {
		var e error
		report, e = workspace.RestoreWithLayout(ctx, env.Workspace, plain, limits, env.PreserveOwner, layout)
		return e
	})
	if e != nil {
		return Result{}, ErrExecution
	}
	if e = check("before-normalize"); e != nil {
		return Result{}, e
	}
	n, e := normalizeFiles(ctx, env.Workspace, r.Files)
	if e != nil {
		return Result{}, ErrExecution
	}
	if e = check("restored-quarantine"); e != nil {
		return Result{}, e
	}
	if r.WorkBuddyIdentity != nil && domain.VerifyWorkBuddyUIDWorkspace(env.Workspace, *r.WorkBuddyIdentity) != nil {
		return Result{}, ErrExecution
	}
	return Result{Receipt: r.Receipt, Files: report.Files, Bytes: report.Bytes, NormalizedFiles: n, Quarantined: true}, nil
}

func validWorkBuddyIdentityRequest(r Request) bool {
	if r.WorkBuddyIdentity == nil {
		return true
	}
	w := r.WorkBuddyIdentity
	return (r.Operation == "capture-workspace" || r.Operation == "restore-workspace") && r.RuntimePolicy != nil && r.RuntimePolicy.Validate() == nil && r.RuntimePolicy.Runtime.Type == "workbuddy" && r.RuntimePolicy.Runtime.Mode == "lite" && w.Schema == 1 && w.InstanceID > 0 && w.InstanceID <= 2147483647 && w.UserID > 0 && w.UserID <= 2147483647 && w.UID >= 10000 && w.UID <= 65533 && w.GID == w.UID
}

type budgetWriter struct {
	w    io.Writer
	left int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, ErrExecution
	}
	n, e := w.w.Write(p)
	w.left -= int64(n)
	return n, e
}
func relativeFile(p string) bool {
	return p != "" && p != "." && !path.IsAbs(p) && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00:\r\n")
}
func separateRoots(a, b *os.Root) bool {
	ai, e := a.Stat(".")
	if e != nil {
		return false
	}
	bi, e := b.Stat(".")
	if e != nil || os.SameFile(ai, bi) {
		return false
	}
	ap, e := filepath.EvalSymlinks(a.Name())
	if e != nil {
		return false
	}
	bp, e := filepath.EvalSymlinks(b.Name())
	if e != nil {
		return false
	}
	for _, pair := range [][2]string{{ap, bp}, {bp, ap}} {
		rel, e := filepath.Rel(pair[0], pair[1])
		if e != nil {
			return false
		}
		if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
			return false
		}
	}
	return true
}
func normalizeFiles(ctx context.Context, root *os.Root, rules []FileRule) (int, error) {
	n := 0
	for _, rule := range rules {
		before, e := root.Lstat(rule.Path)
		if os.IsNotExist(e) && !rule.Required {
			continue
		}
		if e != nil || !before.Mode().IsRegular() || before.Size() > 8<<20 {
			return 0, ErrExecution
		}
		f, e := root.Open(rule.Path)
		if e != nil {
			return 0, ErrExecution
		}
		actual, e := f.Stat()
		if e != nil || !os.SameFile(before, actual) {
			f.Close()
			return 0, ErrExecution
		}
		b, e := io.ReadAll(io.LimitReader(f, 8<<20+1))
		f.Close()
		if e != nil || len(b) > 8<<20 {
			return 0, ErrExecution
		}
		normalized, e := domain.NormalizeDocument(ctx, rule.Format, b, rule.Fields)
		clear(b)
		if e != nil {
			return 0, ErrExecution
		}
		f, e = root.OpenFile(rule.Path, os.O_WRONLY, 0)
		if e != nil {
			clear(normalized.Bytes)
			return 0, ErrExecution
		}
		actual, e = f.Stat()
		if e != nil || !os.SameFile(before, actual) {
			f.Close()
			clear(normalized.Bytes)
			return 0, ErrExecution
		}
		if f.Truncate(0) != nil {
			f.Close()
			clear(normalized.Bytes)
			return 0, ErrExecution
		}
		written, writeErr := f.Write(normalized.Bytes)
		expected := len(normalized.Bytes)
		clear(normalized.Bytes)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || written != expected || syncErr != nil || closeErr != nil || root.Chtimes(rule.Path, before.ModTime(), before.ModTime()) != nil {
			return 0, ErrExecution
		}
		n++
	}
	return n, nil
}
