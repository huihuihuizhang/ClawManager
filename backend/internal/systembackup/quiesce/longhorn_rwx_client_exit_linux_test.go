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
	group, err := os.MkdirTemp("/sys/fs/cgroup", "podclaw-rwx-client-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(group); err != nil {
			t.Error("isolated test cgroup not removed", err)
		}
	}()
	podUID := strings.TrimPrefix(filepath.Base(group), "pod")
	containerGroup := filepath.Join(group, strings.Repeat("a", 64))
	if err := os.Mkdir(containerGroup, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(containerGroup); err != nil {
			t.Error(err)
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
	if err := os.WriteFile(filepath.Join(containerGroup, "cgroup.procs"), []byte(strconv.Itoa(child)), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := observationProcess(ctx, fmt.Sprintf("/proc/%d", child))
	if err != nil || original.Cgroup != "/"+filepath.Base(group)+"/"+strings.Repeat("a", 64) {
		t.Fatal("actual original cgroup was not pinned", err)
	}
	original.Cgroup, err = observationPodCgroup(original.Cgroup, podUID)
	if err != nil {
		t.Fatal(err)
	}
	stateFile, inspector := filepath.Join(dir, "cri.json"), filepath.Join(dir, "crictl")
	writeState := func(state string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"status": map[string]any{"id": strings.Repeat("a", 64), "state": state, "finishedAt": "1", "labels": map[string]string{"io.kubernetes.pod.uid": podUID, "io.kubernetes.pod.name": "app", "io.kubernetes.pod.namespace": "ns"}}, "info": map[string]any{"pid": child}})
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
		source: LonghornExt4Source{Binding: ObservationBinding{Node: "node1", Namespace: "ns"}, ProviderNamespace: "ns", ProviderPodName: "app", ProviderPodUID: podUID, ProviderContainerID: "containerd://" + strings.Repeat("a", 64), MountOwnerPID: original.PID, MountOwnerStart: original.Start, MountNamespace: original.MountNamespace}}
	o := &NodeObserver{Node: "node1", HostProc: "/proc", HostRoot: "/", CRI: CRICommand{Binary: inspector, Endpoint: "unix:///fixture.sock"}}
	// Full sync dispatch below still uses fixture CRI/NFS metadata, while the
	// original kernel process, namespaces, cgroup and retained FD are real.
	hostRoot := filepath.Join(dir, "host")
	if err := os.MkdirAll(filepath.Join(hostRoot, "etc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostRoot, "etc/machine-id"), []byte("fixture-machine"), 0600); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	o.HostRoot, o.MachineID, o.BootID = hostRoot, "fixture-machine", strings.TrimSpace(string(boot))
	now := time.Now().UTC()
	op, reservation := strings.Repeat("1", 32), strings.Repeat("2", 32)
	client.source.Binding = ObservationBinding{Kind: LonghornExt4Protocol, Node: "node1", NodeUID: "fixture-node", Namespace: "ns", NamespaceUID: "fixture-ns", InstallationID: "fixture-installation", OperationID: op, ReservationID: reservation, InventorySHA256: strings.Repeat("3", 64), Generation: 1, ExpiresAt: now.Add(time.Minute)}
	client.source.Claim = LonghornExt4Claim{OriginalOperationID: op, OriginalReservationID: reservation, Owner: "adoption:" + op, MaintenanceOwner: "adoption:" + op, EntryRowVersion: 7, LeaseObservedAt: now.Add(-time.Second), LeaseExpiresAt: now.Add(50 * time.Second)}
	client.source.Attempt, client.source.Identity, client.mustExit = 1, strings.Repeat("4", 64), true
	request := LonghornExt4Request{Action: "sync-client", Binding: client.source.Binding, Claim: client.source.Claim, Attempt: 1, SourceIdentity: client.source.Identity, ClientPodName: client.source.ProviderPodName, ClientPodUID: client.source.ProviderPodUID, ClientContainerID: client.source.ProviderContainerID, RegistrationBoundarySHA256: strings.Repeat("5", 64), DrainBoundarySHA256: strings.Repeat("6", 64), ClientMustExit: true}
	a := &longhornExt4Actions{parent: &SharedRuntimeNodeHandler{owner: &sharedRuntimeNodeOwner{observer: o}}, clients: map[string]longhornRWXClient{longhornRWXClientKey(client): client}}
	writeState("CONTAINER_RUNNING")
	if err := longhornExt4ProviderCurrent(ctx, o, client.source); err != nil {
		t.Fatal("live-provider branch was not exercised", err)
	}
	if _, err := a.syncClient(request); err == nil || !strings.Contains(err.Error(), "longhorn_original_container_exit_unconfirmed") {
		t.Fatal("cold client used the live sync branch", err)
	}
	writeState("CONTAINER_EXITED")
	keeper := client.source
	keeper.Keeper = &LonghornExt4Keeper{OriginalPodUID: client.source.ProviderPodUID}
	keeper.OriginalHolder = &longhornExt4OriginalHolder{Namespace: client.source.ProviderNamespace, PodName: client.source.ProviderPodName, PodUID: client.source.ProviderPodUID, ContainerID: client.source.ProviderContainerID, Process: original}
	keeper.ProviderPodName, keeper.ProviderPodUID, keeper.ProviderContainerID = "keeper", "keeper-pod", "containerd://"+strings.Repeat("b", 64)
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("a CRI EXITED claim hid the actual live original process")
	}
	if err := o.originalLonghornKeeperHolderExited(ctx, keeper); err == nil {
		t.Fatal("keeper accepted the same CRI lie while the actual original holder was live")
	}
	if err := unix.Kill(child, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waited, child = true, 0
	if err := o.originalLonghornRWXClientExited(ctx, client); err != nil {
		t.Fatal("original exit could not be independently confirmed", err)
	}
	if reply, err := a.syncClient(request); err != nil || reply.Phase != "client-synced" {
		t.Fatal("native cold-client sync failed after actual original exit", err)
	}
	downgraded := request
	downgraded.ClientMustExit = false
	if _, err := a.syncClient(downgraded); err == nil {
		t.Fatal("registered exit requirement was downgraded")
	}
	if err := o.originalLonghornKeeperHolderExited(ctx, keeper); err != nil {
		t.Fatal("keeper original exit could not be independently confirmed", err)
	}
	for _, change := range []func(*LonghornExt4Source){
		func(s *LonghornExt4Source) { s.OriginalHolder = nil },
		func(s *LonghornExt4Source) {
			h := *s.OriginalHolder
			h.PodUID = "another-original"
			s.OriginalHolder = &h
		},
		func(s *LonghornExt4Source) {
			h := *s.OriginalHolder
			h.Namespace = "another-namespace"
			s.OriginalHolder = &h
		},
		func(s *LonghornExt4Source) {
			h := *s.OriginalHolder
			h.ContainerID = s.ProviderContainerID
			s.OriginalHolder = &h
		},
		func(s *LonghornExt4Source) {
			h := *s.OriginalHolder
			h.Process.PIDNamespace = ""
			s.OriginalHolder = &h
		},
	} {
		changed := keeper
		change(&changed)
		if err := o.originalLonghornKeeperHolderExited(ctx, changed); err == nil {
			t.Fatal("keeper accepted missing or changed original identity")
		}
	}
	if err := syncPinnedLonghornRWXClientMount(ctx, fd, client.mountTable, client.pin); err != nil {
		t.Fatal("the same retained mount FD could not sync after process exit", err)
	}
	writeState("CONTAINER_RUNNING")
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("host absence alone replaced the required original CRI evidence")
	}
	if err := o.originalLonghornKeeperHolderExited(ctx, keeper); err == nil {
		t.Fatal("keeper accepted host absence while the original CRI state was running")
	}
	if err := os.WriteFile(stateFile, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := o.originalLonghornRWXClientExited(ctx, client); err == nil {
		t.Fatal("a missing CRI record was promoted to stopped")
	}
	if err := o.originalLonghornKeeperHolderExited(ctx, keeper); err == nil {
		t.Fatal("keeper promoted missing CRI data to an exit proof")
	}
}
