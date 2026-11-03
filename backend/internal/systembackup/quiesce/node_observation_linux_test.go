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
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests exercise actual Linux file descriptors/maps, not a substitute
// for a full Node/CRI/reservation positive integration.
func TestNodeObserverNativeWritableFDAndSharedMap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := filepath.Join(t.TempDir(), "source")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Truncate(4096); e != nil {
		t.Fatal(e)
	}
	var s unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &s); e != nil {
		t.Fatal(e)
	}
	files := map[observationInode]observationFileState{{Major: unix.Major(uint64(s.Dev)), Minor: unix.Minor(uint64(s.Dev)), Inode: s.Ino}: {}}
	sources := observationTestSources(t, p)
	if observationWritableHandles(ctx, "/proc/self", "/proc", files, sources) == nil {
		t.Fatal("actual writable source FD accepted")
	}
	mapped, e := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if mapped != nil {
			unix.Munmap(mapped)
		}
	}()
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if observationWritableHandles(ctx, "/proc/self", "/proc", files, sources) == nil {
		t.Fatal("actual shared writable source mapping accepted after FD close")
	}
	if e = unix.Munmap(mapped); e != nil {
		t.Fatal(e)
	}
	mapped = nil
	readOnly, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer readOnly.Close()
	if e = observationWritableHandles(ctx, "/proc/self", "/proc", files, sources); e != nil {
		t.Fatal("native read-only source FD was inconclusive", e)
	}
}

func observationTestSources(t *testing.T, p string) []observedPath {
	t.Helper()
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		t.Fatal(e)
	}
	best := ""
	length := -1
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if mountSeparator(f) < 0 {
			continue
		}
		point, e := mountUnescape(f[4])
		if e != nil {
			t.Fatal(e)
		}
		if withinObservation(p, point) && len(point) > length {
			best = line
			length = len(point)
		}
	}
	var st unix.Stat_t
	if best == "" || unix.Stat(p, &st) != nil {
		t.Fatal("native source/mount unavailable")
	}
	return []observedPath{{Path: p, Device: uint64(st.Dev), Inode: st.Ino, Mount: best}}
}

func TestNodeObserverNativeSameFSUnrelatedDeletedFiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := t.TempDir()
	source := filepath.Join(d, "source")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(source, "data")
	if e := os.WriteFile(p, []byte("source"), 0600); e != nil {
		t.Fatal(e)
	}
	sources := observationTestSources(t, source)
	o := NodeObserver{HostRoot: "/"}
	files, e := o.files(ctx, sources)
	if e != nil {
		t.Fatal(e)
	}
	other, e := os.CreateTemp(d, "unrelated-")
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.Truncate(4096); e != nil {
		t.Fatal(e)
	}
	var st unix.Stat_t
	if unix.Fstat(int(other.Fd()), &st) != nil || uint64(st.Dev) != sources[0].Device {
		t.Fatal("fixture is not on the same real filesystem")
	}
	mapping, e := unix.Mmap(int(other.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Munmap(mapping)
	if e = os.Remove(other.Name()); e != nil {
		t.Fatal(e)
	}
	if e = observationWritableHandles(ctx, "/proc/self", "/proc", files, sources); e != nil {
		t.Fatal("proven unrelated same-FS deleted FD/mmap blocked source", e)
	}
	// A writable hard-link alias still targets a current source inode.
	alias := filepath.Join(d, "alias")
	if e = os.Link(p, alias); e != nil {
		t.Fatal(e)
	}
	holder, e := os.OpenFile(alias, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer holder.Close()
	if observationWritableHandles(ctx, "/proc/self", "/proc", files, sources) == nil {
		t.Fatal("actual source hard-link writer escaped")
	}
	if e = holder.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(alias); e != nil {
		t.Fatal(e)
	}
	// Removing a source file must not hide its still-open writable handle,
	// even when that inode no longer appears in the current source tree.
	deleted, e := os.OpenFile(p, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer deleted.Close()
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	files, e = o.files(ctx, sources)
	if e != nil {
		t.Fatal(e)
	}
	if observationWritableHandles(ctx, "/proc/self", "/proc", files, sources) == nil {
		t.Fatal("deleted source writer accepted")
	}
}

func TestNodeObserverPinnedUnrelatedProcessExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	source := filepath.Join(t.TempDir(), "source")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	sources := observationTestSources(t, source)
	o := NodeObserver{HostRoot: "/"}
	files, e := o.files(ctx, sources)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeObserverUnrelatedProcessHelper$")
	cmd.Env = append(os.Environ(), "CLAW_NODE_OBSERVER_HELPER=1", "CLAW_NODE_OBSERVER_HELPER_DIRECTORY="+filepath.Dir(source))
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		input.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	line, e := bufio.NewReader(output).ReadString('\n')
	if e != nil || line != "ready\n" {
		t.Fatal("native helper unavailable", e)
	}
	pinned, e := observationPinTask(ctx, fmt.Sprintf("/proc/%d/task/%d", cmd.Process.Pid, cmd.Process.Pid), "/proc")
	if e != nil {
		t.Fatal(e)
	}
	defer pinned.close()
	if e = observationWritableHandles(ctx, pinned.base, "/proc", files, sources); e != nil {
		t.Fatal("unrelated active native process blocked source", e)
	}
	if e = input.Close(); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	if !pinned.exited() {
		t.Fatal("actual exited process was not resolved through native identity handle")
	}
	if _, e = observationProcess(ctx, pinned.base); e == nil {
		t.Fatal("pinned dead proc directory returned a live replacement identity")
	}
}

func TestNodeObserverUnrelatedProcessHelper(t *testing.T) {
	if os.Getenv("CLAW_NODE_OBSERVER_HELPER") != "1" {
		return
	}
	f, e := os.CreateTemp(os.Getenv("CLAW_NODE_OBSERVER_HELPER_DIRECTORY"), "unrelated-process-")
	if e != nil {
		os.Exit(2)
	}
	if os.Remove(f.Name()) != nil || f.Truncate(4096) != nil {
		f.Close()
		os.Exit(2)
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				if _, e := f.WriteAt([]byte("active"), 0); e != nil {
					return
				}
			}
		}
	}()
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin)
	close(done)
	<-finished
	f.Close()
	os.Exit(0)
}

func TestNodeObserverNativePIDIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cgroups, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(cgroups), "0::/") {
		t.Skip("native cgroup v2 not available; observer must refuse this host")
	}
	p, e := observationProcess(ctx, "/proc/self")
	if e != nil {
		t.Fatal(e)
	}
	if p.PID != os.Getpid() || p.Start == "" || p.PIDNamespace == "" || p.MountNamespace == "" || p.Cgroup == "" {
		t.Fatal("actual process identity incomplete")
	}
	other, e := observationProcess(ctx, "/proc/self")
	if e != nil || other != p {
		t.Fatal("same native process drifted", e)
	}
}

func TestNodeObserverAnchorTamperingAndScope(t *testing.T) {
	o, e := NewNodeObserver("node", "node-uid", "machine", "boot", "/", "/proc", CRICommand{Binary: "/usr/local/bin/crictl", Endpoint: "unix:///run/containerd/containerd.sock"}, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	a := nodeObservationAnchor{Binding: ObservationBinding{OperationID: "original"}, BootID: "boot", Processes: []observedProcess{{PID: 123, Start: "456", PIDNamespace: "pid:[77]", MountNamespace: "mnt:[88]", Cgroup: "/kubepods/pod-original"}}}
	token, e := o.seal(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.open(token + "0"); e == nil {
		t.Fatal("tampered original observation accepted")
	}
	other := *o
	other.key = append([]byte(nil), o.key...)
	other.key[0] = 1
	if _, e = other.open(token); e == nil {
		t.Fatal("another node key accepted original observation")
	}
	if !originalObservationScope(observedProcess{PID: 999, Start: "1", PIDNamespace: "pid:[99]", MountNamespace: "mnt:[98]", Cgroup: "/kubepods/pod-original/new-container"}, a) {
		t.Fatal("new descendant cgroup escaped old Pod scope")
	}
	if originalObservationScope(observedProcess{PID: 123, Start: "457", PIDNamespace: "pid:[99]", MountNamespace: "mnt:[98]", Cgroup: "/kubepods/pod-original-suffix"}, a) {
		t.Fatal("PID reuse or sibling prefix was classified as original")
	}
}

func TestNodeObserverPrivateKeyPathRefusals(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "key")
	if e := os.WriteFile(p, make([]byte, 32), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadNodeObservationKey(p); e == nil {
		t.Fatal("public or untrusted ancestor key path accepted")
	}
	link := filepath.Join(d, "symlink")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadNodeObservationKey(link); e == nil {
		t.Fatal("symlink key accepted")
	}
}
