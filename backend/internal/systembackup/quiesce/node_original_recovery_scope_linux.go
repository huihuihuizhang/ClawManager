//go:build linux

package quiesce

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func recoveryRootMap(pods []PodIdentity, roots []observedProcess) (map[string]observedProcess, error) {
	out := map[string]observedProcess{}
	at := 0
	for _, pod := range pods {
		for _, cid := range pod.Containers {
			if at >= len(roots) {
				return nil, ErrNodeObservation
			}
			if _, exists := out[cid]; exists {
				return nil, ErrNodeObservation
			}
			out[cid] = roots[at]
			at++
		}
	}
	if at != len(roots) {
		return nil, ErrNodeObservation
	}
	return out, nil
}
func (o *NodeObserver) reconcileOriginalRecovery(ctx context.Context, r NodeObservationRequest, a nodeObservationAnchor) (originalRecoveryNativeResult, error) {
	var result originalRecoveryNativeResult
	actors, e := originalRecoveryActors(a)
	if e != nil {
		return result, observationFailure("recovery_actor_anchor")
	}
	p := make([]string, len(a.Paths))
	for n, s := range a.Paths {
		p[n] = s.Path
	}
	currentPaths, e := o.paths(ctx, p)
	if e != nil || !reflect.DeepEqual(currentPaths, a.Paths) {
		return result, observationFailure("source_mount_drift")
	}
	var roots []observedProcess
	if len(r.RecoveredPods) > 0 {
		roots, e = o.runningRecoveryScopes(ctx, r.Binding, r.RecoveredPods, a.Paths, r.Action == "recovery-reconciled")
		if e != nil {
			return result, observationFailure("recovery_current_process")
		}
	}
	if len(roots) > 0 {
		hostMount, e := os.Readlink(filepath.Join(o.HostProc, "1/ns/mnt"))
		if e != nil {
			return result, observationFailure("host_visibility")
		}
		for _, root := range roots {
			if root.MountNamespace == hostMount {
				return result, observationFailure("recovery_current_scope_unknown")
			}
		}
	}
	currentRoots, e := recoveryRootMap(r.RecoveredPods, roots)
	if e != nil {
		return result, e
	}
	current := map[string]PodIdentity{}
	for _, pod := range r.RecoveredPods {
		current[pod.UID] = pod
	}
	fencedPods := []PodIdentity{}
	fenced := []observedProcess{}
	live := []observedProcess{}
	for _, actor := range actors {
		if pod, present := current[actor.Pod.UID]; present {
			if !sameRecoveryPod(pod, actor.Pod) {
				return result, observationFailure("recovery_original_changed")
			}
			for n, cid := range actor.Pod.Containers {
				if observed, ok := currentRoots[cid]; !ok || observed != actor.Roots[n] {
					return result, observationFailure("recovery_original_changed")
				}
			}
			for _, known := range actor.Processes {
				actual, e := observationProcess(ctx, filepath.Join(o.HostProc, strconv.Itoa(known.PID)))
				if e == nil && actual == known {
					live = append(live, actual)
				}
			}
		} else {
			fencedPods = append(fencedPods, actor.Pod)
			fenced = append(fenced, actor.Processes...)
		}
	}
	if len(fencedPods) > 0 && (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, fencedPods) != nil {
		return result, observationFailure("original_cri_exit")
	}
	// Explicitly empty CURRENT membership is never an implicit untouched mode:
	// it must pass the unchanged COMPLETE original scope-absence algorithm.
	if len(r.RecoveredPods) == 0 {
		n, files, e := o.stopped(ctx, a)
		if e != nil {
			return result, e
		}
		if (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, a.Pods) != nil {
			return result, observationFailure("original_cri_exit")
		}
		return originalRecoveryNativeResult{Tasks: n, Files: files}, ctx.Err()
	}
	for _, process := range append(append([]observedProcess(nil), roots...), live...) {
		if originalRecoveryScopeContains(process, fenced) {
			return result, observationFailure("original_process_present")
		}
	}
	files, e := o.files(ctx, a.Paths)
	if e != nil {
		return result, observationFailure("source_tree_visibility")
	}
	tasks, e := o.scanOriginalRecovery(ctx, a.Paths, fenced, roots, live, files)
	if e != nil {
		return result, e
	}
	after, e := o.files(ctx, a.Paths)
	if e != nil {
		return result, observationFailure("source_tree_visibility")
	}
	// Expected current writers may mutate their own files. Inspect the union of
	// actual inode observations and independently resolve every unknown RW FD /
	// shared map against native mount coordinates, rather than declaring a
	// changing tree quiescent or skipping unknown writers.
	for inode, state := range after {
		files[inode] = state
	}
	more, e := o.scanOriginalRecovery(ctx, a.Paths, fenced, roots, live, files)
	if e != nil {
		return result, e
	}
	if len(fencedPods) > 0 && (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, fencedPods) != nil {
		return result, observationFailure("original_cri_exit")
	}
	finalRoots, e := o.runningRecoveryScopes(ctx, r.Binding, r.RecoveredPods, a.Paths, r.Action == "recovery-reconciled")
	if e != nil || !reflect.DeepEqual(finalRoots, roots) {
		return result, observationFailure("recovery_current_drift")
	}
	finalPaths, e := o.paths(ctx, p)
	if e != nil || !reflect.DeepEqual(finalPaths, a.Paths) {
		return result, observationFailure("source_mount_drift")
	}
	return originalRecoveryNativeResult{Processes: len(roots), Tasks: tasks + more, Files: len(files)}, ctx.Err()
}
func (o *NodeObserver) scanOriginalRecovery(ctx context.Context, paths []observedPath, fenced, roots, live []observedProcess, files map[observationInode]observationFileState) (int, error) {
	seen := map[string]bool{}
	for round := 0; round < 2; round++ {
		tasks, e := o.tasks(ctx)
		if e != nil {
			return 0, observationFailure("task_enumeration")
		}
		for _, base := range tasks {
			p, e := observationPinTask(ctx, base, o.HostProc)
			if e != nil {
				return 0, e
			}
			e = func() error {
				defer p.close()
				if originalRecoveryScopeContains(p.process, fenced) {
					return observationFailure("original_process_present")
				}
				if !originalRecoveryLiveContains(p.process, roots, live) {
					if e := observationWritableHandles(ctx, p.base, o.HostProc, files, paths); e != nil {
						return e
					}
					if e := observationRecoveryUnknownHandles(ctx, p.base, o.HostProc, paths); e != nil {
						return e
					}
				}
				after, e := observationProcess(ctx, p.base)
				if e != nil {
					if p.exited() {
						return nil
					}
					return observationFailure("task_identity_lost")
				}
				if !reflect.DeepEqual(after, p.process) {
					return observationFailure("task_scope_drift")
				}
				seen[strconv.Itoa(after.PID)+":"+after.Start] = true
				return nil
			}()
			if e != nil {
				return 0, e
			}
		}
	}
	return len(seen), ctx.Err()
}

// Additional native mount-coordinate checks for unknown tasks while expected
// current writers are live. The existing inode check still catches hard links;
// unknown/deleted/aliased source reachability is never granted by a role flag.
func observationRecoveryUnknownHandles(ctx context.Context, base, hostProc string, sources []observedPath) error {
	mounts, e := observationMountTable(ctx, base)
	if e != nil {
		return e
	}
	devices := map[string]bool{}
	for _, source := range sources {
		dev, _, e := observationSourceCoordinate(source)
		if e != nil {
			return e
		}
		devices[dev] = true
	}
	dir, e := os.Open(filepath.Join(base, "fd"))
	if e != nil {
		return observationFailure("fd_visibility")
	}
	defer dir.Close()
	fds, e := dir.ReadDir(-1)
	if e != nil || len(fds) > 100000 {
		return observationFailure("fd_visibility")
	}
	for _, fd := range fds {
		native := filepath.Join(base, "fd", fd.Name())
		link, e := os.Readlink(native)
		if e != nil {
			return observationFailure("fd_visibility")
		}
		flags, mountID, _, e := observationFDInfo(ctx, base, fd.Name())
		if e != nil {
			return e
		}
		if strings.Contains(link, "io_uring") {
			if !observationMountsDisjoint(mounts, sources) {
				return observationFailure("async_source_scope_unknown")
			}
			continue
		}
		var st, after unix.Stat_t
		if unix.Stat(native, &st) != nil {
			return observationFailure("fd_visibility")
		}
		laterFlags, laterMount, _, e := observationFDInfo(ctx, base, fd.Name())
		if e != nil || unix.Stat(native, &after) != nil || st.Dev != after.Dev || st.Ino != after.Ino || flags != laterFlags || mountID != laterMount {
			return observationFailure("fd_identity_drift")
		}
		if flags&uint64(unix.O_ACCMODE) == uint64(unix.O_RDONLY) || st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		device := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
		if devices[device] && !observationDeletedFDDisjoint(ctx, base, hostProc, link, mountID, device, mounts, sources) {
			return observationFailure("writable_source_fd")
		}
	}
	raw, e := observationRead(ctx, filepath.Join(base, "maps"), observationReadLimit)
	if e != nil {
		return observationFailure("maps_visibility")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || len(f[1]) != 4 {
			return observationFailure("maps_parse")
		}
		if f[1][1] != 'w' || f[1][3] != 's' {
			continue
		}
		parts := strings.Split(f[3], ":")
		if len(parts) != 2 {
			return observationFailure("maps_parse")
		}
		major, e := strconv.ParseUint(parts[0], 16, 32)
		if e != nil {
			return observationFailure("maps_parse")
		}
		minor, e := strconv.ParseUint(parts[1], 16, 32)
		if e != nil {
			return observationFailure("maps_parse")
		}
		device := fmt.Sprintf("%d:%d", major, minor)
		if !devices[device] {
			continue
		}
		if len(f) < 6 || !observationDeletedMapDisjoint(base, hostProc, strings.Join(f[5:], " "), device, mounts, sources) {
			return observationFailure("writable_source_mapping")
		}
	}
	return ctx.Err()
}
