//go:build linux

package quiesce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"clawreef/internal/services"
	"golang.org/x/sys/unix"
)

// These constructor-fixed release pins are not supplied by a lifecycle request.
// DataDir is the independently reviewed compiled profile default, used only
// when the actual initial Go process environment has no explicit override.
type sharedRuntimeAgentRelease struct{ ExecutableSHA256, DataDir string }
type sharedRuntimeNativeWitness struct {
	Container, Agent                observedProcess
	Gateways                        []observedProcess
	Guard                           gatewayNativePin
	JournalSHA256, ExecutableSHA256 string
	LoadedEnvironmentSHA256         map[string]string
	Paths                           []observedPath
}
type sharedRuntimePrivateJournal struct {
	State            services.RuntimeSharedNativeState
	OriginalRequests []json.RawMessage
}

// Native source DATA only: no reservation, freeze, source flush or authority
// follows from constructing a witness. The lifecycle owner must additionally
// authenticate its original persisted operation and maintain all source gates.
func (o *NodeObserver) sharedRuntimeWitness(ctx context.Context, r SharedRuntimeNodeRequest, expected services.RuntimeSharedNativeState, releases map[string]sharedRuntimeAgentRelease) (sharedRuntimeNativeWitness, error) {
	var out sharedRuntimeNativeWitness
	bad := func() (sharedRuntimeNativeWitness, error) {
		return sharedRuntimeNativeWitness{}, observationFailure("shared_native_source")
	}
	if o == nil || ctx == nil || ctx.Err() != nil || o.hostIdentity(ctx) != nil || expected.Identity.PodUID != r.AgentPod.UID || expected.Identity.Namespace != r.Binding.Namespace || expected.Identity.OperationID != r.Binding.ReservationID || expected.Identity.InventorySHA256 != r.Binding.InventorySHA256 || expected.BootID != o.BootID || expected.OriginalSHA256 != services.SharedRuntimeOriginalSHA(expected) || !validObservationHash(expected.JournalSHA256) || !absoluteObservationPath(r.AgentDataDir) || expected.GuardPath != filepath.Join(r.AgentDataDir, "shared-backup.guard") || expected.JournalPath != filepath.Join(r.AgentDataDir, "shared-backup/current.json") {
		return bad()
	}
	paths, err := o.paths(ctx, r.SourcePaths)
	if err != nil {
		return bad()
	}
	roots, err := o.runningRecoveryScopes(ctx, r.Binding, []PodIdentity{r.AgentPod}, paths, false)
	if err != nil || len(roots) != 1 {
		return bad()
	}
	// runningRecoveryScopes uses a Pod-wide scan scope. Re-read the real CRI
	// process to pin the narrower CONTAINER cgroup before any physical operation.
	out.Container, err = observationProcess(ctx, filepath.Join(o.HostProc, strconv.Itoa(roots[0].PID)))
	if err != nil {
		return bad()
	}
	root := filepath.Join(o.HostProc, strconv.Itoa(out.Container.PID), "root")
	_, guard, _, err := sharedRuntimeNativeRead(ctx, root, expected.GuardPath, 1)
	if err != nil {
		return bad()
	}
	out.Guard = guard
	out.Agent, err = o.gatewayLockOwner(ctx, guard, out.Container)
	if err != nil || out.Agent.Start != expected.AgentStartTicks || out.Agent.PIDNamespace != expected.PIDNamespace || out.Agent.MountNamespace != expected.MountNamespace {
		return bad()
	}
	ids, err := gatewayNSpid(ctx, filepath.Join(o.HostProc, strconv.Itoa(out.Agent.PID)))
	if err != nil || ids[len(ids)-1] != expected.AgentPID {
		return bad()
	}
	loaded, err := sharedRuntimeLoadedEnvironment(ctx, o.HostProc, out.Agent, r, expected.Identity.Deployment, releases)
	if err != nil {
		return bad()
	}
	out.LoadedEnvironmentSHA256 = loaded.hashes
	out.ExecutableSHA256, err = sharedRuntimeExecutable(ctx, o.HostProc, out.Agent, loaded.release.ExecutableSHA256)
	if err != nil {
		return bad()
	}
	raw, _, _, err := sharedRuntimeNativeRead(ctx, root, expected.JournalPath, 4<<20)
	if err != nil {
		return bad()
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	out.JournalSHA256 = hex.EncodeToString(sum[:])
	if out.JournalSHA256 != expected.JournalSHA256 {
		return bad()
	}
	var journal sharedRuntimePrivateJournal
	defer func() {
		for _, b := range journal.OriginalRequests {
			clear(b)
		}
	}()
	if sharedRuntimeJournalJSON(raw, &journal) != nil {
		return bad()
	}
	// The approved Agent writes this exact Go encoding. Re-encoding also rejects
	// duplicate/alias/omitted members that encoding/json alone could normalize.
	encoded, err := json.Marshal(journal)
	if err != nil {
		return bad()
	}
	same := bytes.Equal(encoded, raw)
	clear(encoded)
	if !same {
		return bad()
	}
	want := expected
	want.JournalSHA256 = ""
	if !reflect.DeepEqual(journal.State, want) || journal.OriginalRequests == nil || len(journal.OriginalRequests) != len(want.Entries) {
		return bad()
	}
	for n, request := range journal.OriginalRequests {
		h := sha256.Sum256(request)
		if hex.EncodeToString(h[:]) != want.Entries[n].RequestSHA256 {
			return bad()
		}
	}
	out.Gateways, err = o.sharedRuntimeGatewayProcesses(ctx, out.Container, expected.Entries)
	if err != nil {
		return bad()
	}
	// Read back every source used above after ELF/environment/journal I/O.
	again, err := observationProcess(ctx, filepath.Join(o.HostProc, strconv.Itoa(out.Container.PID)))
	if err != nil || again != out.Container {
		return bad()
	}
	agent, err := o.gatewayLockOwner(ctx, guard, out.Container)
	if err != nil || agent != out.Agent {
		return bad()
	}
	_, lastGuard, _, err := sharedRuntimeNativeRead(ctx, root, expected.GuardPath, 1)
	if err != nil || lastGuard != guard {
		return bad()
	}
	last, _, _, err := sharedRuntimeNativeRead(ctx, root, expected.JournalPath, 4<<20)
	if err != nil {
		return bad()
	}
	same = bytes.Equal(raw, last)
	clear(last)
	if !same {
		return bad()
	}
	lastPaths, err := o.paths(ctx, r.SourcePaths)
	if err != nil || !reflect.DeepEqual(lastPaths, paths) {
		return bad()
	}
	out.Paths = paths
	return out, nil
}

// Private Agent journals have a different bound from the legacy read-only
// observer wire protocol. Preserve the Agent's real 4 MiB journal allowance.
func sharedRuntimeJournalJSON(raw []byte, journal *sharedRuntimePrivateJournal) error {
	if journal == nil || len(raw) == 0 || len(raw) > 4<<20 {
		return ErrNodeObservation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(journal) != nil || d.Decode(new(any)) != io.EOF {
		return ErrNodeObservation
	}
	return nil
}

// Follow only the kernel's already-pinned /proc/<CRI PID>/root link. Every
// subsequent component is opened relative to a directory fd without symlinks.
func sharedRuntimeNativeRead(ctx context.Context, root, path string, limit int64) ([]byte, gatewayNativePin, gatewayNativePin, error) {
	var zero gatewayNativePin
	if ctx == nil || ctx.Err() != nil || !absoluteObservationPath(path) || path == "/" {
		return nil, zero, zero, ErrNodeObservation
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, zero, zero, ErrNodeObservation
	}
	defer func() { unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, p := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, zero, zero, ErrNodeObservation
		}
		unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			return nil, zero, zero, ErrNodeObservation
		}
	}
	var parent unix.Stat_t
	if unix.Fstat(fd, &parent) != nil {
		return nil, zero, zero, ErrNodeObservation
	}
	file, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, zero, zero, ErrNodeObservation
	}
	f := os.NewFile(uintptr(file), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(file, &before) != nil || before.Uid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0777 != 0600 || before.Size < 0 || before.Size > limit {
		return nil, zero, zero, ErrNodeObservation
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) != before.Size || unix.Fstat(file, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Size != after.Size || before.Mode != after.Mode || ctx.Err() != nil {
		clear(b)
		return nil, zero, zero, ErrNodeObservation
	}
	return b, gatewayNativePin{uint64(before.Dev), before.Ino}, gatewayNativePin{uint64(parent.Dev), parent.Ino}, nil
}

type sharedRuntimeLoaded struct {
	hashes  map[string]string
	release sharedRuntimeAgentRelease
}

func sharedRuntimeLoadedEnvironment(ctx context.Context, proc string, agent observedProcess, r SharedRuntimeNodeRequest, deployment string, releases map[string]sharedRuntimeAgentRelease) (sharedRuntimeLoaded, error) {
	var zero sharedRuntimeLoaded
	raw, err := observationRead(ctx, filepath.Join(proc, strconv.Itoa(agent.PID), "environ"), 1<<20)
	if err != nil {
		return zero, err
	}
	defer clear(raw)
	env := map[string][]byte{}
	for _, part := range bytes.Split(raw, []byte{0}) {
		if len(part) == 0 {
			continue
		}
		i := bytes.IndexByte(part, '=')
		if i <= 0 {
			return zero, ErrNodeObservation
		}
		k := string(part[:i])
		if _, ok := env[k]; ok {
			return zero, ErrNodeObservation
		}
		env[k] = part[i+1:]
	}
	value := func(k string) string { return strings.TrimSpace(string(env[k])) }
	release, ok := releases[value("CLAWMANAGER_RUNTIME_TYPE")]
	if !ok || !validObservationHash(release.ExecutableSHA256) || !absoluteObservationPath(release.DataDir) {
		return zero, ErrNodeObservation
	}
	for k, want := range map[string]string{"POD_UID": r.AgentPod.UID, "POD_NAME": r.AgentPod.Name, "POD_NAMESPACE": r.Binding.Namespace, "NODE_NAME": r.Binding.Node, "CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME": deployment, "RUNTIME_WORKSPACE_ROOT": r.WorkspaceRoot} {
		if value(k) != want {
			return zero, ErrNodeObservation
		}
	}
	dir := value("RUNTIME_AGENT_DATA_DIR")
	if dir == "" {
		dir = release.DataDir
	}
	if dir != r.AgentDataDir {
		return zero, ErrNodeObservation
	}
	hashes := map[string]string{}
	for _, k := range []string{"RUNTIME_AGENT_CONTROL_TOKEN", "RUNTIME_AGENT_REPORT_TOKEN"} {
		v := bytes.TrimSpace(env[k])
		if len(v) < 32 {
			return zero, ErrNodeObservation
		}
		h := sha256.Sum256(v)
		hashes[k] = hex.EncodeToString(h[:])
	}
	after, err := observationProcess(ctx, filepath.Join(proc, strconv.Itoa(agent.PID)))
	if err != nil || after != agent {
		return zero, ErrNodeObservation
	}
	return sharedRuntimeLoaded{hashes, release}, nil
}

func sharedRuntimeExecutable(ctx context.Context, proc string, agent observedProcess, expected string) (string, error) {
	if !validObservationHash(expected) {
		return "", ErrNodeObservation
	}
	f, err := os.Open(filepath.Join(proc, strconv.Itoa(agent.PID), "exe"))
	if err != nil {
		return "", ErrNodeObservation
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	total := int64(0)
	for {
		if ctx.Err() != nil {
			return "", ErrNodeObservation
		}
		n, e := f.Read(buffer)
		total += int64(n)
		if total > 64<<20 {
			return "", ErrNodeObservation
		}
		h.Write(buffer[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", ErrNodeObservation
		}
	}
	actual := hex.EncodeToString(h.Sum(nil))
	after, err := observationProcess(ctx, filepath.Join(proc, strconv.Itoa(agent.PID)))
	if err != nil || after != agent || actual != expected || total == 0 {
		return "", ErrNodeObservation
	}
	return actual, nil
}

func (o *NodeObserver) sharedRuntimeGatewayProcesses(ctx context.Context, container observedProcess, entries []services.RuntimeSharedBackupEntry) ([]observedProcess, error) {
	wanted := map[int]string{}
	for _, e := range entries {
		if e.PID > 0 {
			if _, ok := wanted[e.PID]; ok {
				return nil, ErrNodeObservation
			}
			wanted[e.PID] = e.PIDStartTicks
		}
	}
	matched := map[int]observedProcess{}
	list, err := os.ReadDir(o.HostProc)
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		base := filepath.Join(o.HostProc, e.Name())
		cg, err := observationRead(ctx, filepath.Join(base, "cgroup"), 64<<10)
		if err != nil {
			continue
		}
		if !strings.Contains(string(cg), "0::"+container.Cgroup+"\n") && !strings.Contains(string(cg), "0::"+container.Cgroup+"/") {
			continue
		}
		p, err := observationProcess(ctx, base)
		if err != nil {
			return nil, err
		}
		if p.PIDNamespace != container.PIDNamespace || !withinObservation(p.Cgroup, container.Cgroup) {
			continue
		}
		ids, err := gatewayNSpid(ctx, base)
		if err != nil {
			return nil, err
		}
		pid := ids[len(ids)-1]
		start, ok := wanted[pid]
		if !ok {
			continue
		}
		if _, exists := matched[pid]; exists || p.Start != start {
			return nil, ErrNodeObservation
		}
		_, state, err := gatewayParent(ctx, base)
		if err != nil || state == "Z" || state == "X" {
			return nil, ErrNodeObservation
		}
		matched[pid] = p
	}
	out := []observedProcess{}
	for _, e := range entries {
		if e.PID == 0 {
			continue
		}
		p, ok := matched[e.PID]
		if !ok {
			return nil, ErrNodeObservation
		}
		again, err := observationProcess(ctx, filepath.Join(o.HostProc, strconv.Itoa(p.PID)))
		if err != nil || again != p {
			return nil, ErrNodeObservation
		}
		out = append(out, p)
	}
	return out, nil
}
