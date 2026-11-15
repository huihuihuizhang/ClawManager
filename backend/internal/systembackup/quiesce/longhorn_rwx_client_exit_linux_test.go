//go:build linux

package quiesce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel process/cgroup/namespace and retained-FD checks run for real. The CRI
// reply and NFS table are protocol fixtures, not claims of a live NFS backup.
func TestLonghornRWXStoppedClientNeedsCRIAndActualProcessExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated native process test requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	group, err := os.MkdirTemp("/sys/fs/cgroup", "claw-rwx-client-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(group); err != nil {
			t.Error("isolated test cgroup not removed", err)
		}
	}()
	ready := filepath.Join(dir, "ready")
	command := exec.CommandContext(ctx, "unshare", "--mount", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "/bin/sh", "-c", `echo ready > "$1"; exec sleep 120`, "rwx-client-test", ready)
	command.Stdin = nil
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	child, waited := 0, false
	defer func() {
		if child > 1 {
			_ = unix.Kill(child, unix.SIGKILL)
		}
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	for i := 0; i < 100; i++ {
		raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", command.Process.Pid, command.Process.Pid))
		if fields := strings.Fields(string(raw)); len(fields) == 1 {
			child, _ = strconv.Atoi(fields[0])
		}
		if _, err := os.Stat(ready); err == nil && child > 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if child <= 1 {
		t.Fatal("isolated original process did not become ready")
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(child)), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := observationProcess(ctx, fmt.Sprintf("/proc/%d", child))
	if err != nil || original.Cgroup != "/"+filepath.Base(group) {
		t.Fatal("actual original cgroup was not pinned", err)
	}
	stateFile, inspector := filepath.Join(dir, "cri.json"), filepath.Join(dir, "crictl")
	writeState := func(state string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"status": map[string]any{"id": strings.Repeat("a", 64), "state": state, "finishedAt": "1", "labels": map[string]string{"io.kubernetes.pod.uid": "original-app"}}})
		if err := os.WriteFile(stateFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(inspector, []byte("#!/bin/sh\nexec cat '"+strings.ReplaceAll(stateFile, "'", "'\\''")+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	writeState("CONTAINER_EXITED")
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/root%s", child, dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	_, mountID, _, err := observationFDInfo(ctx, "/proc/self", strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	pin := longhornRWXClientMountPin{mountID: mountID, device: fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))), root: "/", point: "/workspaces", source: "10.0.0.1:/original", endpoint: netip.MustParseAddr("10.0.0.1")}
	table := []byte(fmt.Sprintf("%s 1 %s / /workspaces rw - nfs4 10.0.0.1:/original rw,addr=10.0.0.1\n", pin.mountID, pin.device))
	client := longhornRWXClient{fd: fd, pin: pin, original: original, mountTable: table,
		source: LonghornExt4Source{Binding: ObservationBinding{Node: "node1"}, ProviderPodName: "app", ProviderPodUID: "original-app", ProviderContainerID: "containerd://" + strings.Repeat("a", 64), MountOwnerPID: original.PID, MountOwnerStart: original.Start, MountNamespace: original.MountNamespace}}
	o := &NodeObserver{Node: "node1", HostProc: "/proc", HostRoot: "/", CRI: CRICommand{Binary: inspector, Endpoint: "unix:///fixture.sock"}}
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("a CRI EXITED claim hid the actual live original process")
	}
	if err := unix.Kill(child, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waited, child = true, 0
	if err := o.originalLonghornRWXClientExited(ctx, client); err != nil {
		t.Fatal("original exit could not be independently confirmed", err)
	}
	if err := syncPinnedLonghornRWXClientMount(ctx, fd, client.mountTable, client.pin); err != nil {
		t.Fatal("the same retained mount FD could not sync after process exit", err)
	}
	writeState("CONTAINER_RUNNING")
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("host absence alone replaced the required original CRI evidence")
	}
	if err := os.WriteFile(stateFile, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("a missing CRI record was promoted to stopped")
	}
}
