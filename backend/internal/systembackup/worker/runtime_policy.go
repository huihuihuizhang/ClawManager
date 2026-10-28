package worker

import (
	"context"
	"io"
	"os"
	"strings"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/workspace"
)

// RuntimePolicy is a release-specific allowlist, shared by capture and drill.
// The archive always includes the entire workspace (files, sessions, Skills and
// task definitions). Only the listed executable/configuration files normalize.
// No agent brand or mutable image tag implicitly authorizes an unknown release.
type RuntimePolicy struct {
	Version, Image  string
	Runtime         scope.Runtime
	Files           []FileRule
	WorkspaceLayout workspace.Layout `json:",omitempty"`
}

func (p RuntimePolicy) Validate() error {
	if p.Version == "" || len(p.Files) == 0 || len(p.Files) > 256 {
		return ErrRequest
	}
	runtime, e := scope.PlanRuntime(p.Runtime)
	if e != nil || !p.WorkspaceLayout.Known() {
		return ErrRequest
	}
	if (p.WorkspaceLayout == workspace.WorkBuddyWineV1 || p.WorkspaceLayout == workspace.WorkBuddyInstanceWineV1) && (runtime.Type != "workbuddy" || runtime.Mode != "lite") {
		return ErrRequest
	}
	if p.WorkspaceLayout == workspace.DeepSeekHarnessV1 && runtime.Type != "deepseek-harness" {
		return ErrRequest
	}
	parts := strings.Split(p.Image, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 {
		return ErrRequest
	}
	for _, c := range parts[1] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrRequest
		}
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if !relativeFile(f.Path) || seen[f.Path] || len(f.Fields) == 0 {
			return ErrRequest
		}
		seen[f.Path] = true
		switch f.Format {
		case "", "json", "yaml", "toml", "dotenv":
		default:
			return ErrRequest
		}
		for _, r := range f.Fields {
			switch r.Action {
			case "preserve", "stub", "disable", "disable-string":
			default:
				return ErrRequest
			}
		}
	}
	return nil
}

// CheckRuntimeFiles evaluates the exact same field coverage before export, but
// never rewrites the source. Credentials are normalized only in memory and
// discarded; the encrypted archive keeps their original bytes.
func CheckRuntimeFiles(ctx context.Context, root *os.Root, policy RuntimePolicy) error {
	if root == nil || policy.Validate() != nil {
		return ErrRequest
	}
	for _, rule := range policy.Files {
		info, e := root.Lstat(rule.Path)
		if os.IsNotExist(e) && !rule.Required {
			continue
		}
		if e != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return ErrExecution
		}
		f, e := root.Open(rule.Path)
		if e != nil {
			return ErrExecution
		}
		actual, e := f.Stat()
		if e != nil || !os.SameFile(info, actual) {
			f.Close()
			return ErrExecution
		}
		b, e := io.ReadAll(io.LimitReader(f, 8<<20+1))
		f.Close()
		if e != nil || len(b) > 8<<20 {
			clear(b)
			return ErrExecution
		}
		n, e := domain.NormalizeDocument(ctx, rule.Format, b, rule.Fields)
		clear(b)
		clear(n.Bytes)
		if e != nil {
			return ErrExecution
		}
	}
	return ctx.Err()
}
