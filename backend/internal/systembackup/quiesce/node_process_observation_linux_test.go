//go:build linux

package quiesce

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Local kernel scope checks, not CRI or field-coverage receipts. Each actual
// child has a distinct cgroup, PID namespace and mount namespace.
func coldNativeTestProcess(t *testing.T, ctx context.Context) (*exec.Cmd, observedProcess) {
	t.Helper()
	root := os.Getenv("P2_NATIVE_CGROUP_ROOT")
	if root == "" {
		t.Skip("explicit local native cgroup test environment required")
	}
	dir, err := os.MkdirTemp(root, "cold-")
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	cmd := exec.CommandContext(ctx, "sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	if err = cmd.Start(); err != nil {
		os.Remove(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
	})
	p, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid)))
	if err != nil {
		t.Fatal(err)
	}
	// Keep the test's namespace objects alive after explicit process exit so
	// the disjoint replacement scenario cannot accidentally recycle their
	// inode numbers. The production scanner must still refuse any namespace
	// collision; this test does not weaken that original protection.
	for _, namespace := range []string{"pid", "mnt"} {
		handle, err := os.Open(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "ns", namespace))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { handle.Close() })
	}
	return cmd, p
}

func TestColdProcessNativeExitAndPartialRecoveryScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	original, a := coldNativeTestProcess(t, ctx)
	_, untouched := coldNativeTestProcess(t, ctx)
	o := &NodeObserver{HostRoot: "/", HostProc: "/proc"}
	anchor := nodeObservationAnchor{Binding: ObservationBinding{Kind: NodeObservationColdProcesses}, Processes: []observedProcess{a}}
	if _, _, err := o.scan(ctx, anchor, nil); err == nil {
		t.Fatal("running original accepted as absent")
	}
	if _, err := o.scanOriginalRecovery(ctx, nil, []observedProcess{a}, []observedProcess{untouched}, nil, nil); err == nil {
		t.Fatal("partial recovery ignored running affected original")
	}
	if err := original.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = original.Wait()
	if tasks, _, err := o.scan(ctx, anchor, nil); err != nil || tasks <= 0 {
		t.Fatal("actual exited original not absent", tasks, err)
	}
	if tasks, err := o.scanOriginalRecovery(ctx, nil, []observedProcess{a}, []observedProcess{untouched}, nil, nil); err != nil || tasks <= 0 {
		t.Fatal("untouched actual process prevented partial recovery", tasks, err)
	}
	_, replacement := coldNativeTestProcess(t, ctx)
	if tasks, err := o.scanOriginalRecovery(ctx, nil, []observedProcess{a}, []observedProcess{untouched, replacement}, nil, nil); err != nil || tasks <= 0 {
		t.Fatal("actual replacement failed final original-scope absence", tasks, err)
	}
}
