package quiesce

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"time"
)

func originalRecoveryScopedPhase(action string) bool {
	return action == "recovery-source-stopped" || action == "recovery-reconciled"
}
func sameRecoveryPod(a, b PodIdentity) bool {
	if a.Name != b.Name || a.UID != b.UID || a.Node != b.Node || len(a.Containers) != len(b.Containers) {
		return false
	}
	x, y := append([]string(nil), a.Containers...), append([]string(nil), b.Containers...)
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y)
}
func originalRecoverySubset(all, subset []PodIdentity) bool {
	if len(subset) == 0 || len(subset) >= len(all) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range subset {
		if seen[p.UID] {
			return false
		}
		seen[p.UID] = true
		found := false
		for _, old := range all {
			if sameRecoveryPod(old, p) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func originalRecoveryDataValid(r NodeObservationRequest, node string) bool {
	if !originalRecoveryScopedPhase(r.Action) || r.Anchor == "" || len(r.SourcePaths) != 0 || !validObservationHash(r.RecoverySnapshotSHA256) || r.RecoveredGeneration != r.Binding.Generation || r.RecoveredPods == nil || len(r.RecoveredPods) > 0 && !validObservationPods(r.RecoveredPods, node) {
		return false
	}
	old := map[string]PodIdentity{}
	for _, p := range r.Pods {
		old[p.UID] = p
	}
	for _, p := range r.RecoveredPods {
		if previous, ok := old[p.UID]; ok && !sameRecoveryPod(previous, p) {
			return false
		}
	}
	if r.Action == "recovery-reconciled" {
		return len(r.RecoveryAffectedPods) == 0
	}
	if !originalRecoverySubset(r.Pods, r.RecoveryAffectedPods) {
		return false
	}
	for _, affected := range r.RecoveryAffectedPods {
		for _, current := range r.RecoveredPods {
			if affected.UID == current.UID {
				return false
			}
		}
	}
	return true
}
func originalRecoveryFacts(action string) []string {
	switch action {
	case "recovery-source-stopped":
		return []string{"affected_original_cri_containers_exited", "fenced_original_process_scopes_absent", "declared_current_process_scopes_native_verified", "no_observed_unexpected_source_writer", "original_source_mounts_unchanged"}
	case "recovery-reconciled":
		return []string{"original_actors_native_partitioned", "fenced_original_process_scopes_absent", "declared_current_process_scopes_native_verified", "no_observed_unexpected_source_writer", "original_source_mounts_unchanged"}
	}
	return nil
}
func copyRecoveryPods(pods []PodIdentity) []PodIdentity {
	if pods == nil {
		return nil
	}
	out := make([]PodIdentity, len(pods))
	copy(out, pods)
	for n := range out {
		out[n].Containers = append([]string(nil), out[n].Containers...)
	}
	return out
}
func originalRecoveryScopedRequest(in NodeObservationRequest, affected []PodIdentity) (NodeObservationRequest, error) {
	if !originalRecoveryScopedPhase(in.Action) {
		return in, ErrNodeObservation
	}
	if in.Action == "recovery-source-stopped" {
		if len(in.RecoveryAffectedPods) != 0 {
			if len(in.RecoveryAffectedPods) != len(affected) {
				return in, ErrNodeObservation
			}
			for _, p := range affected {
				found := false
				for _, q := range in.RecoveryAffectedPods {
					found = found || sameRecoveryPod(p, q)
				}
				if !found {
					return in, ErrNodeObservation
				}
			}
		}
		in.RecoveryAffectedPods = copyRecoveryPods(affected)
	} else if len(affected) != 0 {
		return in, ErrNodeObservation
	}
	if !nodeObservationPhaseDataValid(in, in.Binding.Node) {
		return in, ErrNodeObservation
	}
	return in, nil
}

// DATA digest of the exact private-journal/API scope. It excludes transport
// nonce/deadline/response, and cannot construct or refresh an opaque proof.
func OriginalRecoveryScopeSHA256(in NodeObservationRequest, affected []PodIdentity) (string, error) {
	r, e := originalRecoveryScopedRequest(in, affected)
	if e != nil {
		return "", e
	}
	canonical := func(p []PodIdentity) []PodIdentity {
		x := copyRecoveryPods(p)
		for n := range x {
			sort.Strings(x[n].Containers)
		}
		sort.Slice(x, func(i, j int) bool { return x[i].UID < x[j].UID })
		return x
	}
	return observationDigest(struct {
		Version, Action              string
		Binding                      ObservationBinding
		AnchorSHA256, SnapshotSHA256 string
		Original, Affected, Current  []PodIdentity
		RecoveredGeneration          uint64
	}{"whole-pod-original-recovery-scope.v1", r.Action, r.Binding, observationRawDigest([]byte(r.Anchor)), r.RecoverySnapshotSHA256, canonical(r.Pods), canonical(r.RecoveryAffectedPods), canonical(r.RecoveredPods), r.RecoveredGeneration}), nil
}

// The affected set is the original actor's real UID/CID subset, not an
// "untouched" assertion. Only a concrete authenticated native roundtrip mints.
func (c *NodeObservationClient) ObserveOriginalRecoveryScope(ctx context.Context, in NodeObservationRequest, affected []PodIdentity) (*VerifiedNodeObservation, error) {
	if in.Action != "recovery-source-stopped" {
		return nil, ErrNodeObservation
	}
	r, e := originalRecoveryScopedRequest(in, affected)
	if e != nil {
		return nil, e
	}
	return c.ObserveVerified(ctx, r)
}
func (v *VerifiedNodeObservation) RecheckOriginalRecoveryScope(ctx context.Context, in NodeObservationRequest, affected []PodIdentity, boot string, now time.Time) error {
	expected, e := OriginalRecoveryScopeSHA256(in, affected)
	if e != nil || v == nil || v.originalRecoverySHA256 == "" || v.originalRecoverySHA256 != expected {
		return ErrNodeObservation
	}
	return v.recheckOriginalBinding(ctx, in.Binding, in.Action, boot, now)
}

// Only native CRI roots may define an allowed namespace/cgroup. Expanded
// current descendants can authorize only their exact observed process tuple;
// a descendant that moved into a host domain cannot whitelist that domain.
func originalRecoveryLiveContains(p observedProcess, roots, observed []observedProcess) bool {
	for _, root := range roots {
		if p.PID == root.PID && p.Start == root.Start || p.PIDNamespace == root.PIDNamespace || p.Cgroup == root.Cgroup || strings.HasPrefix(p.Cgroup, strings.TrimSuffix(root.Cgroup, "/")+"/") {
			return true
		}
	}
	for _, known := range observed {
		if p == known {
			return true
		}
	}
	return false
}

type originalRecoveryActor struct {
	Pod              PodIdentity
	Roots, Processes []observedProcess
}
type originalRecoveryNativeResult struct{ Processes, Tasks, Files int }

func originalRecoveryScopeContains(p observedProcess, scope []observedProcess) bool {
	for _, old := range scope {
		if p.PID == old.PID && p.Start == old.Start || p.PIDNamespace == old.PIDNamespace || p.MountNamespace == old.MountNamespace || p.Cgroup == old.Cgroup || strings.HasPrefix(p.Cgroup, strings.TrimSuffix(old.Cgroup, "/")+"/") {
			return true
		}
	}
	return false
}
func originalRecoveryPodCgroup(cgroup, uid string) bool {
	parts := strings.Split(strings.TrimPrefix(cgroup, "/"), "/")
	for n, s := range parts {
		if s == "pod"+uid || strings.HasSuffix(s, "-pod"+strings.ReplaceAll(uid, "-", "_")+".slice") {
			return "/"+strings.Join(parts[:n+1], "/") == cgroup
		}
	}
	return false
}

// The frozen native prepare producer emits one CRI root per original container,
// in Pods/Containers order; originalScopes preserves that prefix then appends
// the observed original scope. Validate that actual sealed invariant, including
// exact pod-cgroup UID and unambiguous ownership of EVERY stored process.
func originalRecoveryActors(a nodeObservationAnchor) ([]originalRecoveryActor, error) {
	if !validObservationPods(a.Pods, a.Binding.Node) {
		return nil, ErrNodeObservation
	}
	count := 0
	for _, p := range a.Pods {
		count += len(p.Containers)
	}
	if count == 0 || len(a.Processes) < count {
		return nil, ErrNodeObservation
	}
	out := make([]originalRecoveryActor, 0, len(a.Pods))
	at := 0
	for _, p := range a.Pods {
		roots := append([]observedProcess(nil), a.Processes[at:at+len(p.Containers)]...)
		at += len(p.Containers)
		for _, root := range roots {
			if root.PID <= 1 || root.Start == "" || root.PIDNamespace == "" || root.MountNamespace == "" || !originalRecoveryPodCgroup(root.Cgroup, p.UID) {
				return nil, ErrNodeObservation
			}
			for _, previous := range out {
				if originalRecoveryScopeContains(root, previous.Roots) {
					return nil, ErrNodeObservation
				}
			}
		}
		out = append(out, originalRecoveryActor{Pod: p, Roots: roots})
	}
	for _, p := range a.Processes {
		owner := -1
		for n, actor := range out {
			if originalRecoveryScopeContains(p, actor.Roots) {
				if owner != -1 {
					return nil, ErrNodeObservation
				}
				owner = n
			}
		}
		if owner < 0 {
			return nil, ErrNodeObservation
		}
		out[owner].Processes = append(out[owner].Processes, p)
	}
	return out, nil
}
