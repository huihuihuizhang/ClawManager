//go:build linux

package quiesce

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSharedCgroupEventsRejectIncompleteOrAmbiguousKernelState(t *testing.T) {
	for _, raw := range []string{"", "frozen 1\n", "populated 1\nfrozen 2\n", "populated 1\nfrozen 1\nfrozen 0\n", "populated 1\nfrozen 1 extra\n"} {
		if _, _, err := parseSharedCgroupEvents([]byte(raw)); err == nil {
			t.Fatalf("ambiguous kernel state accepted: %q", raw)
		}
	}
	frozen, populated, err := parseSharedCgroupEvents([]byte("populated 1\nfrozen 1\n"))
	if err != nil || !frozen || !populated {
		t.Fatal("complete kernel state rejected")
	}
}

func TestSharedCgroupNativeWorker(t *testing.T) {
	if os.Getenv("SBK_SHARED_CGROUP_CHILD") != "1" {
		t.Skip("native child only")
	}
	f, err := os.OpenFile(os.Getenv("SBK_SHARED_CGROUP_COUNTER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Println("NATIVE_CHILD_READY")
	if _, err = io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = f.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Requires an explicitly delegated, private cgroup-v2 namespace. The fixture
// creates/removes only a child beneath its own container root, and never joins
// or freezes any existing host/container scope. This is a kernel primitive
// integration test, not Kubernetes/CRI/shared-agent/source-gate acceptance.
func TestSharedCgroupNativeKernelFreezeThawSameIncarnation(t *testing.T) {
	if os.Getenv("SBK_SHARED_CGROUP_NATIVE") != "1" {
		t.Skip("explicit private delegated cgroup required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	root := "/sys/fs/cgroup"
	self, err := observationProcess(ctx, "/proc/self")
	if err != nil || self.Cgroup != "/" {
		t.Fatal("not an isolated cgroup namespace")
	}
	path, err := os.MkdirTemp(root, "sbk-owned-freezer-")
	if err != nil {
		t.Fatal("owned cgroup unavailable", err)
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			t.Error("owned cgroup cleanup", err)
		}
	}()
	counter := filepath.Join(t.TempDir(), "counter")
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSharedCgroupNativeWorker$", "-test.v")
	child.Env = append(os.Environ(), "SBK_SHARED_CGROUP_CHILD=1", "SBK_SHARED_CGROUP_COUNTER="+counter)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready := false
	for n := 0; n < 5; n++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "NATIVE_CHILD_READY" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("native child did not initialize")
	}
	if err = os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = stdin.Write([]byte("s")); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	process, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(child.Process.Pid)))
	if err != nil || process.Cgroup != "/"+filepath.Base(path) {
		t.Fatal("child not in owned scope", err)
	}
	handle, err := openSharedCgroup(ctx, root, "/proc", process, nil)
	if err != nil {
		t.Fatal("real owned cgroup rejected", err)
	}
	defer handle.close()
	defer func() {
		recovery, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if handle.owned {
			_ = handle.thaw(recovery)
		}
	}()
	if _, err = openSharedCgroup(ctx, root, "/proc", self, nil); err == nil {
		t.Fatal("freezer root accepted")
	}
	for n := 0; n < 50; n++ {
		st, e := os.Stat(counter)
		if e == nil && st.Size() > 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = handle.freeze(ctx); err != nil {
		t.Fatal("native freeze", err)
	}
	if err = handle.checkFrozen(ctx); err != nil {
		t.Fatal("native freeze not read back", err)
	}
	before, err := os.Stat(counter)
	if err != nil || before.Size() < 1 {
		t.Fatal("no live counter")
	}
	time.Sleep(100 * time.Millisecond)
	after, err := os.Stat(counter)
	if err != nil || before.Size() != after.Size() {
		t.Fatal("kernel freeze did not stop native writer")
	}
	if foreign, err := openSharedCgroup(ctx, root, "/proc", process, nil); err == nil {
		foreign.close()
		t.Fatal("pre-existing freeze borrowed without original pin")
	}
	wrong := handle.pin
	wrong.Inode++
	if foreign, err := openSharedCgroup(ctx, root, "/proc", process, &wrong); err == nil {
		foreign.close()
		t.Fatal("wrong original inode accepted")
	}
	reopened, err := openSharedCgroup(ctx, root, "/proc", process, &handle.pin)
	if err != nil {
		t.Fatal("actual original recovery pin rejected", err)
	}
	defer reopened.close()
	if err = reopened.thaw(ctx); err != nil {
		t.Fatal("same original incarnation failed thaw", err)
	}
	resumed := false
	for n := 0; n < 50; n++ {
		st, e := os.Stat(counter)
		if e == nil && st.Size() > after.Size() {
			resumed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !resumed {
		t.Fatal("original writer did not resume")
	}
	actual, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(child.Process.Pid)))
	if err != nil || actual != process {
		t.Fatal("PID/start/ns/cgroup continuity lost")
	}
	if err = handle.freeze(ctx); err != nil {
		t.Fatal(err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	waited = true
	orphan, err := openSharedCgroup(ctx, root, "/proc", process, &handle.pin)
	if err != nil {
		t.Fatal("original orphan cleanup handle unavailable", err)
	}
	defer orphan.close()
	if err = orphan.thaw(ctx); err == nil {
		t.Fatal("dead original process claimed restored")
	}
	frozen, _, err := orphan.state(ctx)
	if err != nil || frozen {
		t.Fatal("owned orphan remained frozen", err)
	}
}

func TestSharedCgroupNativeRejectsOriginalProcessMigration(t *testing.T) {
	if os.Getenv("SBK_SHARED_CGROUP_NATIVE") != "1" {
		t.Skip("explicit private delegated cgroup required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	self, err := observationProcess(ctx, "/proc/self")
	if err != nil || self.Cgroup != "/" {
		t.Fatal("not an isolated cgroup namespace")
	}
	root := "/sys/fs/cgroup"
	path, err := os.MkdirTemp(root, "sbk-owned-rename-")
	if err != nil {
		t.Fatal(err)
	}
	moved := path + "-replacement"
	defer func() {
		for _, p := range []string{path, moved} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Error("owned cgroup cleanup", err)
			}
		}
	}()
	dir := t.TempDir()
	start := func(name string) (*exec.Cmd, observedProcess, func()) {
		counter := filepath.Join(dir, name)
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSharedCgroupNativeWorker$", "-test.v")
		child.Env = append(os.Environ(), "SBK_SHARED_CGROUP_CHILD=1", "SBK_SHARED_CGROUP_COUNTER="+counter)
		out, e := child.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		in, e := child.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = child.Start(); e != nil {
			t.Fatal(e)
		}
		stop := func() { _ = child.Process.Kill(); _ = child.Wait() }
		reader := bufio.NewReader(out)
		ready := false
		for n := 0; n < 5; n++ {
			line, e := reader.ReadString('\n')
			if e != nil {
				stop()
				t.Fatal(e)
			}
			if strings.TrimSpace(line) == "NATIVE_CHILD_READY" {
				ready = true
				break
			}
		}
		if !ready {
			stop()
			t.Fatal("native child initialization")
		}
		if e = os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(child.Process.Pid)), 0600); e != nil {
			stop()
			t.Fatal(e)
		}
		_, e = in.Write([]byte("s"))
		in.Close()
		if e != nil {
			stop()
			t.Fatal(e)
		}
		p, e := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(child.Process.Pid)))
		if e != nil {
			stop()
			t.Fatal(e)
		}
		return child, p, stop
	}
	first, process, stopFirst := start("first")
	defer stopFirst()
	_, _, stopSecond := start("second")
	defer stopSecond()
	h, err := openSharedCgroup(ctx, root, "/proc", process, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	defer func() {
		recovery, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if h.owned {
			_ = h.thaw(recovery)
		}
	}()
	if err = h.freeze(ctx); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(moved, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(moved, "cgroup.procs"), []byte(strconv.Itoa(first.Process.Pid)), 0600); err != nil {
		t.Fatal("actual root migration", err)
	}
	actual, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(first.Process.Pid)))
	want := process
	want.Cgroup = "/" + filepath.Base(moved)
	if err != nil || actual != want {
		t.Fatal("counterexample did not preserve PID/start/ns while migrating original process", err)
	}
	frozen, populated, err := h.state(ctx)
	if err != nil || !frozen || !populated {
		t.Fatal("counterexample did not retain old populated frozen scope", err)
	}
	if err = h.checkFrozen(ctx); err == nil {
		t.Fatal("old fd frozen state falsely attested migrated original process")
	}
	if err = h.thaw(ctx); err == nil {
		t.Fatal("original process migration claimed recovery")
	}
	frozen, _, err = h.state(ctx)
	if err != nil || frozen {
		t.Fatal("original fd cleanup did not thaw old scope", err)
	}
	replacement, err := os.ReadFile(filepath.Join(moved, "cgroup.freeze"))
	if err != nil || strings.TrimSpace(string(replacement)) != "0" {
		t.Fatal("replacement scope was modified", err)
	}
}
