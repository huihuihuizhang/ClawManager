//go:build linux

package quiesce

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSharedFrozenReaderBindingRequiresSameOriginalGate(t *testing.T) {
	b := ObservationBinding{Kind: NodeObservationWholePodColdCut, InstallationID: "i", OperationID: "task", ReservationID: "cold-reservation", InventorySHA256: strings.Repeat("a", 64), Namespace: "ns", NamespaceUID: "ns-uid", Node: "node", NodeUID: "node-uid", Generation: 4, FenceEpoch: 9, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	s := b
	s.Kind = SharedRuntimeNodeKind
	s.ReservationID = strings.Repeat("b", 32)
	if !sharedFrozenBindingMatches(b, s) {
		t.Fatal("same original gate rejected")
	}
	for _, mutate := range []func(*ObservationBinding){func(x *ObservationBinding) { x.OperationID = "successor" }, func(x *ObservationBinding) { x.InventorySHA256 = strings.Repeat("c", 64) }, func(x *ObservationBinding) { x.Generation++ }, func(x *ObservationBinding) { x.FenceEpoch++ }, func(x *ObservationBinding) { x.ExpiresAt = x.ExpiresAt.Add(time.Second) }, func(x *ObservationBinding) { x.Kind = b.Kind }} {
		x := s
		mutate(&x)
		if sharedFrozenBindingMatches(b, x) {
			t.Fatal("foreign gate scope accepted")
		}
	}
}

func TestSharedFrozenReaderRequiresPrivateFixedStoreAndDoesNotAcquireWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owner")
	o := &NodeObserver{key: bytes.Repeat([]byte{5}, 32)}
	releases := map[string]SharedRuntimeAgentRelease{"openclaw": {strings.Repeat("a", 64), "/var/lib/openclaw-agent"}}
	config := SharedRuntimeFrozenReaderConfig{Directory: dir, CgroupMount: "/sys/fs/cgroup", Releases: releases}
	if _, err := NewSharedRuntimeFrozenObserver(o, config); err == nil {
		t.Fatal("reader created a missing original store")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	reader, err := NewSharedRuntimeFrozenObserver(o, config)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := newSharedRuntimeNodeOwner(o, config.CgroupMount, dir, map[string]sharedRuntimeAgentRelease{"openclaw": {releases["openclaw"].ExecutableSHA256, releases["openclaw"].DataDir}})
	if err != nil {
		t.Fatal("read-only source took the mutating guard", err)
	}
	defer writer.close()
	releases["openclaw"] = SharedRuntimeAgentRelease{strings.Repeat("b", 64), "/other"}
	if reader.sharedFrozen.Releases["openclaw"].ExecutableSHA256 != strings.Repeat("a", 64) {
		t.Fatal("caller mutated approved reader release")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSharedRuntimeFrozenObserver(o, config); err == nil {
		t.Fatal("public source ledger accepted")
	}
}

// Native kernel/FD/mmap scan test in a private delegated cgroup namespace.
// It does not manufacture an Agent/CRI/SQL reservation or a full source proof.
func TestSharedFrozenNativeScanExemptsOnlyActualFrozenContainer(t *testing.T) {
	if os.Getenv("SBK_SHARED_CGROUP_NATIVE") != "1" {
		t.Skip("explicit private delegated cgroup required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	self, err := observationProcess(ctx, "/proc/self")
	if err != nil || self.Cgroup != "/" {
		t.Fatal("not private cgroup namespace", err)
	}
	cg, err := os.MkdirTemp("/sys/fs/cgroup", "sbk-owned-readonly-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cg); err != nil {
			t.Error("owned cgroup cleanup", err)
		}
	}()
	source := t.TempDir()
	counter := filepath.Join(source, "counter")
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
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	reader := bufio.NewReader(stdout)
	ready := false
	for i := 0; i < 6; i++ {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if strings.TrimSpace(line) == "NATIVE_CHILD_READY" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("native writer did not start")
	}
	if err = os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = stdin.Write([]byte("s")); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	p, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(child.Process.Pid)))
	if err != nil {
		t.Fatal(err)
	}
	h, err := openSharedCgroup(ctx, "/sys/fs/cgroup", "/proc", p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	defer func() {
		recovery, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if h.owned {
			_ = h.thaw(recovery)
		}
	}()
	for i := 0; i < 50; i++ {
		st, e := os.Stat(counter)
		if e == nil && st.Size() > 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = h.freeze(ctx); err != nil {
		t.Fatal(err)
	}
	o := &NodeObserver{HostRoot: "/", HostProc: "/proc"}
	paths := observationTestSources(t, source)
	files, err := o.files(ctx, paths)
	if err != nil {
		t.Fatal(err)
	}
	a := nodeObservationAnchor{Paths: paths}
	if _, _, err = o.scan(ctx, a, files); err == nil {
		t.Fatal("ordinary scan ignored actual frozen source FD")
	}
	if _, _, err = o.scanWithSharedFrozen(ctx, a, files, []*sharedCgroupHandle{h}); err != nil {
		t.Fatal("actual pinned frozen writer rejected", err)
	}
	external, err := os.OpenFile(counter, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.scanWithSharedFrozen(ctx, a, files, []*sharedCgroupHandle{h}); err == nil {
		external.Close()
		t.Fatal("unfrozen external source writer exempted")
	}
	external.Close()
	if err = h.thaw(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.scanWithSharedFrozen(ctx, a, files, []*sharedCgroupHandle{h}); err == nil {
		t.Fatal("stale freeze accepted after actual thaw")
	}
}
