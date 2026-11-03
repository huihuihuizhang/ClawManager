//go:build linux

package quiesce

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoppedProCRIEnumSemantics(t *testing.T) {
	for _, x := range []struct{ raw, want string }{{`"CONTAINER_RUNNING"`, "running"}, {`1`, "running"}, {`"CONTAINER_EXITED"`, "exited"}, {`2`, "exited"}, {`"CONTAINER_UNKNOWN"`, "unknown"}, {`3`, "unknown"}} {
		if stoppedProContainerState(json.RawMessage(x.raw)) != x.want {
			t.Fatal("native enum representation mismatch", x.raw)
		}
	}
	if stoppedProSandboxState(json.RawMessage(`0`)) != stoppedProSandboxState(json.RawMessage(`"SANDBOX_READY"`)) || stoppedProSandboxState(json.RawMessage(`2`)) != "unknown" {
		t.Fatal("sandbox enum accepted drift or unknown")
	}
}
func TestStoppedProNativeMountAliasIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	other := filepath.Join(root, "other")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(other, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(source, "data")
	if e := os.WriteFile(file, []byte("source"), 0600); e != nil {
		t.Fatal(e)
	}
	// The admitted B7 Linux test helper reads actual /proc mountinfo/stat; it
	// does not mint a Node/CRI proof. Production still restricts source FS types.
	paths := observationTestSources(t, source)
	o := &NodeObserver{HostRoot: "/", HostProc: "/proc"}
	files, e := o.files(ctx, paths)
	if e != nil {
		t.Fatal(e)
	}
	if e = o.stoppedProMountSource(ctx, other, paths, files); e != nil {
		t.Fatal("unrelated same-FS native directory rejected", e)
	}
	if e = o.stoppedProMountSource(ctx, source, paths, files); e == nil {
		t.Fatal("actual writable source mount accepted")
	}
	alias := filepath.Join(other, "file-alias")
	if e = os.Link(file, alias); e != nil {
		t.Fatal(e)
	}
	if e = o.stoppedProMountSource(ctx, alias, paths, files); e == nil {
		t.Fatal("source inode hard-link alias escaped path check")
	}
}
