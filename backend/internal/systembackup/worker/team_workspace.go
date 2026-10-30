package worker

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"strconv"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/workspace"
)

const TeamWorkspaceVersion = domain.TeamWorkspaceVersion

// Construct this from the authenticated FINAL shared SQL capture, not a live
// post-capture query. D must bind both digests and this exact original part to
// its restore grant. Merely choosing a Team ID grants no source/target access.
type TeamWorkspaceSpec = domain.TeamWorkspaceSpec

func NewTeamWorkspaceSpec(source domain.Snapshot, inventory team.Inventory, teamID int, sourceSQLCiphertextSHA256 string) (*TeamWorkspaceSpec, error) {
	spec, err := domain.NewTeamWorkspaceSpec(source, inventory, teamID, sourceSQLCiphertextSHA256)
	if err != nil {
		return nil, ErrRequest
	}
	return spec, nil
}

func validTeamWorkspace(r Request) bool {
	s := r.TeamWorkspace
	if s == nil || s.Version != TeamWorkspaceVersion || s.TeamID <= 0 || !keyUseHash.MatchString(s.InventorySHA256) || !keyUseHash.MatchString(s.SourceSQLCiphertextSHA256) || len(s.ArtifactRefs) > 100000 || r.Version != Version || (r.Operation != "restore-workspace" && r.Operation != "verify-team-workspace") || r.PolicyVersion != TeamWorkspaceVersion || r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil || r.Teams != nil || r.Database != nil || len(r.Files) != 0 || r.ArtifactName != "" || !validReceipt(r.Receipt) || r.MaxFiles <= 0 || r.MaxFiles > 1_000_000 || r.MaxFileBytes <= 0 || r.MaxArchiveBytes < r.MaxFileBytes || r.MaxArchiveBytes > 1<<50 || r.MaxCompressedBytes <= 0 || r.MaxCompressedBytes > 1<<50 || !time.Now().Before(r.Deadline) {
		return false
	}
	if r.Binding.Path != "team_"+strconv.Itoa(s.TeamID)+"_workspace" {
		return false
	}
	seen := map[string]bool{}
	for _, ref := range s.ArtifactRefs {
		p, err := domain.TeamArtifactPath(ref)
		if err != nil || p != ref || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

// RunTeamWorkspace extends the SAME worker: shared files are inert data, not a
// Runtime config tree requiring fabricated normalization rules. It authenticates
// the whole staged object before writes, requires an empty observed quarantine,
// and never deletes source data or a partial/uncertain restore.
func RunTeamWorkspace(ctx context.Context, r Request, env Environment) (Result, error) {
	if !validTeamWorkspace(r) || env.Workspace == nil || env.Staging == nil || !separateRoots(env.Workspace, env.Staging) || len(env.Key) != 32 {
		return Result{}, ErrRequest
	}
	if env.Check == nil {
		return Result{}, ErrNotReady
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	check := func(point string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Authorization cannot mutate or retain aliases of the original scope.
		raw, err := json.Marshal(r)
		var detached Request
		if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &detached) != nil {
			return ErrRequest
		}
		if env.Check(ctx, point, detached) != nil {
			return ErrNotReady
		}
		return nil
	}
	if err := check("prepare"); err != nil {
		return Result{}, err
	}
	key := append([]byte(nil), env.Key...)
	defer clear(key)
	f, err := staging.OpenFile(ctx, env.Staging, r.Receipt)
	if err != nil {
		return Result{}, ErrExecution
	}
	defer f.Close()
	consume := func(fn func(io.Reader) error) error {
		if _, e := f.Seek(0, io.SeekStart); e != nil {
			return e
		}
		return staging.ConsumeCompressed(ctx, f, key, r.Binding, r.MaxCompressedBytes, r.MaxArchiveBytes, fn)
	}
	if consume(func(src io.Reader) error { _, e := io.Copy(io.Discard, src); return e }) != nil {
		return Result{}, ErrExecution
	}
	limits := workspace.Limits{MaxFiles: r.MaxFiles, MaxBytes: r.MaxFileBytes}
	restoring := r.Operation == "restore-workspace"
	point := "before-verify"
	if restoring {
		point = "before-restore"
	}
	if err = check(point); err != nil {
		return Result{}, err
	}
	if restoring {
		entries, e := fs.ReadDir(env.Workspace.FS(), ".")
		if e != nil || len(entries) != 0 {
			return Result{}, ErrExecution
		}
		if consume(func(src io.Reader) error {
			_, e := workspace.Restore(ctx, env.Workspace, src, limits, env.PreserveOwner)
			return e
		}) != nil {
			return Result{}, ErrExecution
		}
	}
	var report workspace.Report
	if consume(func(src io.Reader) error {
		var e error
		report, e = workspace.Verify(ctx, env.Workspace, src, limits, env.PreserveOwner)
		return e
	}) != nil {
		return Result{}, ErrExecution
	}
	for _, ref := range r.TeamWorkspace.ArtifactRefs {
		for parent := path.Dir(ref); parent != "."; parent = path.Dir(parent) {
			info, e := env.Workspace.Lstat(parent)
			if e != nil || !info.IsDir() {
				return Result{}, ErrExecution
			}
		}
		info, e := env.Workspace.Lstat(ref)
		if e != nil || !info.Mode().IsRegular() {
			return Result{}, ErrExecution
		}
	}
	point = "verified-quarantine"
	if restoring {
		point = "restored-quarantine"
	}
	if err = check(point); err != nil {
		return Result{}, err
	}
	return Result{Receipt: r.Receipt, Files: report.Files, Bytes: report.Bytes, Quarantined: true, Verified: !restoring}, nil
}
