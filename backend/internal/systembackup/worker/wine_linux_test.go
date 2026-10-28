//go:build linux

package worker

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/workspace"
)

func TestWineWorkerUsesFrozenPolicyForEncryptedCaptureAndRestore(t *testing.T) {
	r, env, target := fixture(t)
	prefix := workspace.WinePrefix
	for _, dir := range []string{prefix + "/dosdevices", prefix + "/drive_c"} {
		if e := env.Workspace.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, file := range []string{"system.reg", "user.reg", "userdef.reg"} {
		if e := env.Workspace.WriteFile(prefix+"/"+file, []byte("synthetic registry"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := env.Workspace.Symlink("/", prefix+"/dosdevices/z:"); e != nil {
		t.Fatal(e)
	}
	if e := env.Workspace.Symlink("../drive_c", prefix+"/dosdevices/c:"); e != nil {
		t.Fatal(e)
	}
	if _, e := Run(context.Background(), r, env); !errors.Is(e, ErrExecution) {
		t.Fatal("unconfigured layout did not fail closed", e)
	}
	r.ArtifactName = "wine.enc"
	r.RuntimePolicy = &RuntimePolicy{Version: "wine-fixture", Image: "workbuddy@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "workbuddy", Mode: "lite", Variant: "linux", OS: "linux"}, Files: restoreRequest(r, r.Receipt).Files, WorkspaceLayout: workspace.WorkBuddyWineV1}
	b, e := Run(context.Background(), r, env)
	if e != nil {
		t.Fatal(e)
	}
	savedSource := env.Workspace
	env.Workspace = target
	env.PreserveOwner = true
	rr := restoreRequest(r, b.Receipt)
	result, e := Run(context.Background(), rr, env)
	if e != nil || !result.Quarantined {
		t.Fatal(e)
	}
	if got, e := target.Readlink(prefix + "/dosdevices/z:"); e != nil || got != "/" {
		t.Fatal(got, e)
	}
	if _, e = target.Open(prefix + "/dosdevices/z:/etc/passwd"); e == nil {
		t.Fatal("escaped target root")
	}
	// A request cannot substitute a less restrictive config policy at restore.
	other, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	env.Workspace = other
	rr.Files = rr.Files[:0]
	if _, e = Run(context.Background(), rr, env); !errors.Is(e, ErrRequest) {
		t.Fatal("policy mismatch accepted", e)
	}
	if entries, e := os.ReadDir(other.Name()); e != nil || len(entries) != 0 {
		t.Fatal("invalid request mutated target")
	}
	if data, e := savedSource.ReadFile("config.json"); e != nil || !strings.Contains(string(data), "source-fixture-secret") {
		t.Fatal("source configuration changed")
	}
}
