//go:build linux

package quiesce

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (o *NodeObserver) stoppedProCRIRead(ctx context.Context, action, id string) ([]byte, error) {
	args := []string{"--runtime-endpoint", o.CRI.Endpoint}
	switch action {
	case "containers":
		args = append(args, "ps", "-a", "-o", "json")
	case "sandboxes":
		args = append(args, "pods", "-o", "json")
	case "inspect", "inspectp":
		if !criID.MatchString(id) {
			return nil, ErrNodeObservation
		}
		args = append(args, action, "--output", "json", id)
	default:
		return nil, ErrNodeObservation
	}
	if !absoluteObservationPath(o.CRI.Binary) || !strings.HasPrefix(o.CRI.Endpoint, "unix:///") || strings.ContainsAny(o.CRI.Endpoint, "\x00\r\n") {
		return nil, ErrNodeObservation
	}
	cmd := exec.CommandContext(ctx, o.CRI.Binary, args...)
	var out bytes.Buffer
	cmd.Stdout = &boundedOutputProxy{Buffer: &out, Remaining: 16 << 20}
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, observationFailure("stopped_pro_cri_visibility")
	}
	return out.Bytes(), nil
}

type boundedOutputProxy struct {
	Buffer    *bytes.Buffer
	Remaining int
}

func (b *boundedOutputProxy) Write(p []byte) (int, error) {
	if len(p) > b.Remaining {
		return 0, ErrNodeObservation
	}
	n, e := b.Buffer.Write(p)
	b.Remaining -= n
	return n, e
}
func (o *NodeObserver) stoppedProCRI(ctx context.Context, paths []observedPath, files map[observationInode]observationFileState) (int, int, string, error) {
	containers, e := o.stoppedProCRIRead(ctx, "containers", "")
	if e != nil {
		return 0, 0, "", e
	}
	sandboxes, e := o.stoppedProCRIRead(ctx, "sandboxes", "")
	if e != nil {
		return 0, 0, "", e
	}
	var list struct {
		Containers []struct {
			ID           string          `json:"id"`
			PodSandboxID string          `json:"podSandboxId"`
			State        json.RawMessage `json:"state"`
		} `json:"containers"`
	}
	var pods struct {
		Items []struct {
			ID    string          `json:"id"`
			State json.RawMessage `json:"state"`
		} `json:"items"`
	}
	if json.Unmarshal(containers, &list) != nil || json.Unmarshal(sandboxes, &pods) != nil || list.Containers == nil || pods.Items == nil || len(list.Containers) > 10000 || len(pods.Items) > 10000 {
		return 0, 0, "", observationFailure("stopped_pro_cri_inventory")
	}
	seen := map[string]bool{}
	podIDs := map[string]bool{}
	var hashes []string
	for _, p := range pods.Items {
		if !criID.MatchString(p.ID) || podIDs[p.ID] {
			return 0, 0, "", ErrNodeObservation
		}
		podIDs[p.ID] = true
		raw, e := o.stoppedProCRIRead(ctx, "inspectp", p.ID)
		if e != nil {
			return 0, 0, "", e
		}
		var v struct {
			Status struct {
				ID       string          `json:"id"`
				State    json.RawMessage `json:"state"`
				Metadata struct {
					UID string `json:"uid"`
				} `json:"metadata"`
			} `json:"status"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Status.ID != p.ID || v.Status.Metadata.UID == "" || stoppedProSandboxState(v.Status.State) != stoppedProSandboxState(p.State) {
			return 0, 0, "", observationFailure("stopped_pro_cri_drift")
		}
		state := stoppedProSandboxState(p.State)
		if state == "unknown" {
			return 0, 0, "", ErrNodeObservation
		}
		hashes = append(hashes, observationRawDigest(raw))
	}
	for _, c := range list.Containers {
		if !criID.MatchString(c.ID) || seen[c.ID] || !podIDs[c.PodSandboxID] {
			return 0, 0, "", observationFailure("stopped_pro_cri_inventory")
		}
		seen[c.ID] = true
		raw, e := o.stoppedProCRIRead(ctx, "inspect", c.ID)
		if e != nil {
			return 0, 0, "", e
		}
		var v struct {
			Status struct {
				ID     string          `json:"id"`
				State  json.RawMessage `json:"state"`
				Mounts []struct {
					HostPath string `json:"hostPath"`
					Readonly bool   `json:"readonly"`
				} `json:"mounts"`
			} `json:"status"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Status.ID != c.ID || stoppedProContainerState(v.Status.State) != stoppedProContainerState(c.State) {
			return 0, 0, "", observationFailure("stopped_pro_cri_drift")
		}
		state := stoppedProContainerState(c.State)
		switch state {
		case "exited":
		case "running", "created":
			for _, m := range v.Status.Mounts {
				if m.Readonly {
					continue
				}
				if e = o.stoppedProMountSource(ctx, m.HostPath, paths, files); e != nil {
					return 0, 0, "", e
				}
			}
		default:
			return 0, 0, "", observationFailure("stopped_pro_cri_unknown")
		}
		hashes = append(hashes, observationRawDigest(raw))
	}
	return len(list.Containers), len(pods.Items), observationDigest(hashes), ctx.Err()
}
func stoppedProContainerState(raw json.RawMessage) string {
	switch strings.Trim(string(raw), "\"") {
	case "CONTAINER_CREATED", "0":
		return "created"
	case "CONTAINER_RUNNING", "1":
		return "running"
	case "CONTAINER_EXITED", "2":
		return "exited"
	}
	return "unknown"
}
func stoppedProSandboxState(raw json.RawMessage) string {
	switch strings.Trim(string(raw), "\"") {
	case "SANDBOX_READY", "0":
		return "ready"
	case "SANDBOX_NOTREADY", "1":
		return "notready"
	}
	return "unknown"
}
func stoppedProNamespaceAliases(ctx context.Context, base string, paths []observedPath, files map[observationInode]observationFileState) error {
	raw, e := observationRead(ctx, filepath.Join(base, "mountinfo"), observationReadLimit)
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if mountSeparator(f) < 0 {
			return ErrNodeObservation
		}
		ro := false
		for _, v := range strings.Split(f[5], ",") {
			if v == "ro" {
				ro = true
			}
		}
		if ro {
			continue
		}
		root, e := mountUnescape(f[3])
		if e != nil {
			return e
		}
		point, e := mountUnescape(f[4])
		if e != nil {
			return e
		}
		for _, source := range paths {
			dev, sourceRoot, e := observationSourceCoordinate(source)
			if e != nil {
				return e
			}
			if dev != f[2] {
				continue
			}
			if observationRangesOverlap(root, sourceRoot) {
				return observationFailure("stopped_pro_writable_namespace_alias")
			}
			// A file bind mounted through a hard-link outside the source still
			// targets the source inode; text path disjointness is insufficient.
			var st unix.Stat_t
			if unix.Stat(filepath.Join(base, "root", point), &st) != nil {
				return observationFailure("stopped_pro_cri_mount_unknown")
			}
			if _, ok := files[observationInode{unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino}]; ok {
				return observationFailure("stopped_pro_writable_namespace_alias")
			}
		}
	}
	return ctx.Err()
}
func (o *NodeObserver) stoppedProMountSource(ctx context.Context, hostPath string, paths []observedPath, files map[observationInode]observationFileState) error {
	if !absoluteObservationPath(hostPath) {
		return observationFailure("stopped_pro_cri_mount_unknown")
	}
	native := o.HostRoot
	if hostPath != "/" {
		var e error
		native, e = o.sourceNativePath(hostPath)
		if e != nil {
			return observationFailure("stopped_pro_cri_mount_unknown")
		}
	}
	var st unix.Stat_t
	if unix.Stat(native, &st) != nil {
		return observationFailure("stopped_pro_cri_mount_unknown")
	}
	if _, ok := files[observationInode{unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino}]; ok {
		return observationFailure("stopped_pro_writable_cri_alias")
	}
	mounts, e := observationMountTable(ctx, filepath.Join(o.HostProc, "1"))
	if e != nil {
		return e
	}
	var selected observationMount
	length := -1
	for _, m := range mounts {
		if withinObservation(hostPath, m.Point) && len(m.Point) > length {
			selected = m
			length = len(m.Point)
		}
	}
	if length < 0 {
		return ErrNodeObservation
	}
	physical := filepath.Join(selected.Root, strings.TrimPrefix(strings.TrimPrefix(hostPath, selected.Point), "/"))
	for _, p := range paths {
		device, root, e := observationSourceCoordinate(p)
		if e != nil {
			return e
		}
		if uint64(st.Dev) == p.Device && (st.Ino == p.Inode || selected.Device == device && observationRangesOverlap(physical, root)) {
			return observationFailure("stopped_pro_writable_cri_alias")
		}
	}
	return nil
}
func (o *NodeObserver) stoppedProNative(ctx context.Context, a stoppedProAnchor) (int, int, int, int, string, error) {
	files, e := o.files(ctx, a.Paths)
	if e != nil {
		return 0, 0, 0, 0, "", observationFailure("source_tree_visibility")
	}
	c, p, first, e := o.stoppedProCRI(ctx, a.Paths, files)
	if e != nil {
		return 0, 0, 0, 0, "", e
	}
	hostNS, e := os.Readlink(filepath.Join(o.HostProc, "1/ns/mnt"))
	if e != nil {
		return 0, 0, 0, 0, "", e
	}
	seen := map[string]bool{}
	for round := 0; round < 2; round++ {
		tasks, e := o.tasks(ctx)
		if e != nil {
			return 0, 0, 0, 0, "", e
		}
		for _, base := range tasks {
			t, e := observationPinTask(ctx, base, o.HostProc)
			if e != nil {
				return 0, 0, 0, 0, "", e
			}
			e = func() error {
				defer t.close()
				if t.process.MountNamespace != hostNS {
					if e := stoppedProNamespaceAliases(ctx, t.base, a.Paths, files); e != nil {
						return e
					}
				}
				if e := observationWritableHandles(ctx, t.base, o.HostProc, files, a.Paths); e != nil {
					return e
				}
				after, e := observationProcess(ctx, t.base)
				if e != nil {
					if t.exited() {
						return nil
					}
					return observationFailure("task_identity_lost")
				}
				if after != t.process {
					return observationFailure("task_scope_drift")
				}
				seen[strconv.Itoa(after.PID)+":"+after.Start] = true
				return nil
			}()
			if e != nil {
				return 0, 0, 0, 0, "", e
			}
		}
	}
	after, e := o.files(ctx, a.Paths)
	if e != nil || !reflect.DeepEqual(after, files) {
		return 0, 0, 0, 0, "", observationFailure("source_tree_drift")
	}
	c2, p2, last, e := o.stoppedProCRI(ctx, a.Paths, files)
	if e != nil {
		return 0, 0, 0, 0, "", e
	}
	after, e = o.files(ctx, a.Paths)
	if e != nil || !reflect.DeepEqual(after, files) {
		return 0, 0, 0, 0, "", observationFailure("source_tree_drift")
	}
	paths := make([]string, len(a.Paths))
	for i, p := range a.Paths {
		paths[i] = p.Path
	}
	current, e := o.paths(ctx, paths)
	if e != nil || !reflect.DeepEqual(current, a.Paths) {
		return 0, 0, 0, 0, "", observationFailure("source_mount_drift")
	}
	return len(seen), len(files), c + c2, p + p2, observationDigest([]string{first, last}), ctx.Err()
}
