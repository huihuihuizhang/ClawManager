//go:build linux

package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/services"
)

func TestSharedNativeJournalUsesActualPrivateBound(t *testing.T) {
	j := sharedRuntimePrivateJournal{OriginalRequests: []json.RawMessage{json.RawMessage(`{"native_request":"` + strings.Repeat("x", 600<<10) + `"}`)}}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var got sharedRuntimePrivateJournal
	if len(raw) <= 512<<10 || sharedRuntimeJournalJSON(raw, &got) != nil || len(got.OriginalRequests) != 1 {
		t.Fatal("real private journal size rejected")
	}
	if sharedRuntimeJournalJSON(append(raw, []byte(` {}`)...), &got) == nil {
		t.Fatal("trailing journal accepted")
	}
	if sharedRuntimeJournalJSON(make([]byte, (4<<20)+1), &got) == nil {
		t.Fatal("over-limit journal accepted")
	}
}

// Real procfs/ELF/environment and file-source primitives. The owned sleep
// process is NOT claimed to be a production Agent or a Kubernetes/CRI fixture.
func sharedNativeProcessFixture(t *testing.T) (context.Context, observedProcess, SharedRuntimeNodeRequest, map[string]sharedRuntimeAgentRelease) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "/bin/sleep", "60")
	cmd.Env = []string{"CLAWMANAGER_RUNTIME_TYPE=openclaw", "POD_UID=owned-pod", "POD_NAME=owned-agent", "POD_NAMESPACE=owned-namespace", "NODE_NAME=owned-node", "CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME=owned-runtime", "RUNTIME_WORKSPACE_ROOT=/workspaces", "RUNTIME_AGENT_CONTROL_TOKEN=" + strings.Repeat("c", 32), "RUNTIME_AGENT_REPORT_TOKEN=" + strings.Repeat("r", 32)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	p, err := observationProcess(ctx, filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.PID), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	r := SharedRuntimeNodeRequest{Binding: ObservationBinding{Namespace: "owned-namespace", Node: "owned-node"}, AgentPod: PodIdentity{Name: "owned-agent", UID: "owned-pod"}, WorkspaceRoot: "/workspaces", AgentDataDir: "/var/lib/openclaw-agent"}
	return ctx, p, r, map[string]sharedRuntimeAgentRelease{"openclaw": {hex.EncodeToString(h[:]), r.AgentDataDir}}
}

func TestSharedNativeLoadedProcessSourceRejectsWrongOriginalIdentity(t *testing.T) {
	ctx, p, r, releases := sharedNativeProcessFixture(t)
	got, err := sharedRuntimeLoadedEnvironment(ctx, "/proc", p, r, "owned-runtime", releases)
	if err != nil {
		t.Fatal("actual initial environment rejected", err)
	}
	h := sha256.Sum256([]byte(strings.Repeat("c", 32)))
	if got.hashes["RUNTIME_AGENT_CONTROL_TOKEN"] != hex.EncodeToString(h[:]) || len(got.hashes) != 2 {
		t.Fatal("not exact loaded token digest")
	}
	wrong := r
	wrong.AgentPod.UID = "replacement-pod"
	if _, err = sharedRuntimeLoadedEnvironment(ctx, "/proc", p, wrong, "owned-runtime", releases); err == nil {
		t.Fatal("replacement Pod accepted")
	}
	if _, err = sharedRuntimeLoadedEnvironment(ctx, "/proc", p, r, "other-runtime", releases); err == nil {
		t.Fatal("foreign deployment accepted")
	}
	if _, err = sharedRuntimeLoadedEnvironment(ctx, "/proc", p, r, "owned-runtime", nil); err == nil {
		t.Fatal("unreviewed release accepted")
	}
}

func TestSharedNativeExecutableReadsOriginalProcessNotFilesystemPath(t *testing.T) {
	ctx, p, _, releases := sharedNativeProcessFixture(t)
	expected := releases["openclaw"].ExecutableSHA256
	if got, err := sharedRuntimeExecutable(ctx, "/proc", p, expected); err != nil || got != expected {
		t.Fatal("native executable rejected", err)
	}
	if _, err := sharedRuntimeExecutable(ctx, "/proc", p, strings.Repeat("a", 64)); err == nil {
		t.Fatal("wrong executable digest accepted")
	}
	wrong := p
	wrong.Start = "1"
	if _, err := sharedRuntimeExecutable(ctx, "/proc", wrong, expected); err == nil {
		t.Fatal("wrong original incarnation accepted")
	}
}

func TestSharedNativePrivateFileSourceRejectsModeAndSymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "agent"), 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "agent/current.json")
	data := []byte(`{"actual":"owned"}`)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	raw, pin, _, err := sharedRuntimeNativeRead(ctx, root, "/agent/current.json", 1024)
	if err != nil || string(raw) != string(data) || pin.Inode == 0 {
		t.Fatal("actual private file rejected", err)
	}
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = sharedRuntimeNativeRead(ctx, root, "/agent/current.json", 1024); err == nil {
		t.Fatal("public-readable journal accepted")
	}
	if err = os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(p, filepath.Join(root, "agent/alias.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = sharedRuntimeNativeRead(ctx, root, "/agent/alias.json", 1024); err == nil {
		t.Fatal("symlink journal accepted")
	}
	if err = os.Rename(p, p+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, replacement, _, err := sharedRuntimeNativeRead(ctx, root, "/agent/current.json", 1024)
	if err != nil || replacement == pin {
		t.Fatal("replacement inode not distinguished", err)
	}
}

func TestSharedNativeGatewayMappingUsesRealNamespaceAndStart(t *testing.T) {
	ctx, p, _, _ := sharedNativeProcessFixture(t)
	container, err := observationProcess(ctx, "/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := gatewayNSpid(ctx, filepath.Join("/proc", strconv.Itoa(p.PID)))
	if err != nil {
		t.Fatal(err)
	}
	entries := []services.RuntimeSharedBackupEntry{{PID: ids[len(ids)-1], PIDStartTicks: p.Start}}
	o := &NodeObserver{HostProc: "/proc"}
	got, err := o.sharedRuntimeGatewayProcesses(ctx, container, entries)
	if err != nil || len(got) != 1 || got[0] != p {
		t.Fatal("actual namespace mapping rejected", err)
	}
	entries[0].PIDStartTicks = "1"
	if _, err = o.sharedRuntimeGatewayProcesses(ctx, container, entries); err == nil {
		t.Fatal("stale PID incarnation accepted")
	}
}
