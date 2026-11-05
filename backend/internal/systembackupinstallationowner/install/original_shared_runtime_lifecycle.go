package install

import (
	"bytes"
	"context"
	"path"
	"sort"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// All physical calls run outside SQL locks and use the SAME original owner.
// These actor objects survive response loss; restart recovery must reconstruct
// them from the existing original authenticated journal, never another census.
type originalSharedRuntimeLifecycle struct {
	source                                          *OriginalSharedRuntimeReservation
	client                                          *q.SharedRuntimeNodeClient
	request                                         q.SharedRuntimeNodeRequest
	prepared, frozen, current, recovered, completed *q.VerifiedSharedRuntimeNodeObservation
	dispatched                                      map[string]bool
	agentResumeDispatched, agentCompleteDispatched  bool
}

// Called after existing whole-node source preparation and original acquiring
// application/SQL gate. The actual source host roots are derived from exact
// original Pod/PVC/PV pins, unioned with existing native capture source roots.
func (s *PreparedOriginalWriterSet) prepareSharedRuntimeLifecycle(ctx context.Context) error {
	if len(s.sharedRuntimes) == 0 {
		return nil
	}
	if len(s.sharedLifecycle) != 0 || s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || s.checkApplicationGate(ctx, "acquiring") != nil {
		return ErrInstall
	}
	endpoints := s.selection.SharedRuntimeEndpoints
	if len(endpoints) == 0 {
		return ErrInstall
	}
	client, err := q.NewSharedRuntimeNodeClient(endpoints, s.selection.ObserverCA.File, s.selection.ObserverCertificate.File, s.selection.ObserverKey.File)
	if err != nil {
		return ErrInstall
	}
	roots := map[string][]string{}
	for _, node := range s.nodes {
		roots[node.request.Binding.Node] = append(roots[node.request.Binding.Node], node.request.SourcePaths...)
	}
	for _, r := range s.sharedRuntimes {
		paths, err := s.actualPodPersistentRoots(ctx, &r.pod)
		if err != nil || len(paths) == 0 {
			return ErrInstall
		}
		roots[r.pod.Spec.NodeName] = append(roots[r.pod.Spec.NodeName], paths...)
	}
	for _, r := range s.sharedRuntimes {
		state, err := r.Reserve(ctx)
		if err != nil || state.Phase != "reserved" || len(r.originalRaw) == 0 {
			return ErrInstall
		}
		node, err := s.owner.operator.installer.kube.CoreV1().Nodes().Get(ctx, r.pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
			return ErrInstall
		}
		workspace := "/workspaces"
		for _, env := range r.pod.Spec.Containers[0].Env {
			if env.Name == "RUNTIME_WORKSPACE_ROOT" {
				if env.ValueFrom != nil {
					return ErrInstall
				}
				workspace = env.Value
			}
		}
		data := path.Dir(r.capabilities.GuardPath)
		if workspace == "/" || !path.IsAbs(workspace) || path.Clean(workspace) != workspace || data == workspace || strings.HasPrefix(data, workspace+"/") {
			return ErrInstall
		}
		p := s.owner
		binding := q.ObservationBinding{Kind: q.SharedRuntimeNodeKind, InstallationID: p.operator.installer.plan.Target.InstallationID, OperationID: p.operation, ReservationID: r.identity.OperationID, InventorySHA256: s.inventorySHA, Namespace: r.row.Namespace, NamespaceUID: p.operator.installer.plan.Target.NamespaceUID, Node: node.Name, NodeUID: string(node.UID), Generation: p.token.Generation, FenceEpoch: p.token.FencingToken, ExpiresAt: p.until.UTC().Truncate(time.Microsecond)}
		actor := &originalSharedRuntimeLifecycle{source: r, client: client, request: q.SharedRuntimeNodeRequest{Binding: binding, AgentPod: q.PodIdentity{Name: r.pod.Name, UID: string(r.pod.UID), Node: node.Name, Containers: []string{r.pod.Status.ContainerStatuses[0].ContainerID}}, WorkspaceRoot: workspace, AgentDataDir: data, Original: state, OriginalRaw: bytes.Clone(r.originalRaw), SourcePaths: originalNonOverlappingRoots(roots[node.Name])}, dispatched: map[string]bool{}}
		// Register before the first uncertain physical RPC so partial recovery
		// retains this original actor even if no complete hold is returned.
		s.sharedLifecycle = append(s.sharedLifecycle, actor)
		proof, err := actor.transition(ctx, "prepare", nil)
		if err != nil || proof.Response().Phase != "prepared" {
			return ErrInstall
		}
		actor.prepared = proof
		actor.request.Anchor = proof.Response().Anchor
	}
	for _, actor := range s.sharedLifecycle {
		peers := []q.SharedRuntimeNodePeer{}
		for _, other := range s.sharedLifecycle {
			if other.request.Binding.Node == actor.request.Binding.Node {
				peers = append(peers, q.SharedRuntimeNodePeer{PodUID: other.request.AgentPod.UID, OriginalSHA256: other.request.Original.OriginalSHA256, Anchor: other.request.Anchor})
			}
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].PodUID < peers[j].PodUID })
		actor.request.Peers = peers
	}
	return nil
}

func (a *originalSharedRuntimeLifecycle) transition(ctx context.Context, action string, fence *originalWriterRecoveryFence) (*q.VerifiedSharedRuntimeNodeObservation, error) {
	if a == nil || a.source == nil || a.client == nil {
		return nil, ErrInstall
	}
	s := a.source.set
	r := a.request
	r.Action = action
	if action != "recovered" && action != "complete" {
		r.Current = nil
		r.CurrentRaw = nil
	}
	if fence == nil {
		if s.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || s.checkApplicationGate(ctx, "acquiring", "held") != nil {
			return nil, ErrInstall
		}
	} else {
		if fence.owner != s.owner || fence.checkReleasing(ctx) != nil || !digestPattern.MatchString(fence.journalSHA) {
			return nil, ErrInstall
		}
		r.RecoveryBoundarySHA256 = fence.journalSHA
	}
	mutating := action == "prepare" || action == "freeze" || action == "thaw" || action == "complete"
	if mutating && a.dispatched[action] {
		// An unknown original mutation is inspected; NEVER resend it. State is
		// data only. Capture subsequently needs a fresh real check-frozen.
		r.Action = "state"
		r.Current = nil
		r.CurrentRaw = nil
		r.RecoveryBoundarySHA256 = ""
	} else if mutating {
		if s.journal.append(ctx, a.source.ID(), "shared_node_"+action+"_send_unknown", nil, r) != nil {
			return nil, ErrInstall
		}
		a.dispatched[action] = true
	}
	proof, raw, err := a.client.Transition(ctx, r)
	if err != nil {
		return nil, ErrCommitUnknown
	}
	if action == "complete" && r.Action == "state" && proof.Response().Phase == "completed" {
		// Readback has confirmed this exact original closure. Obtain a fresh
		// native verification of that ALREADY completed record, not a new close
		// or a replacement reservation. Node complete must be idempotent here.
		r = a.request
		r.Action = "complete"
		r.RecoveryBoundarySHA256 = fence.journalSHA
		proof, raw, err = a.client.Transition(ctx, r)
		if err != nil {
			return nil, ErrCommitUnknown
		}
	}
	if s.journal.append(ctx, a.source.ID(), "shared_node_"+action+"_observed", nil, struct {
		Response q.SharedRuntimeNodeResponse
		Raw      []byte
	}{proof.Response(), raw}) != nil {
		return nil, ErrCommitUnknown
	}
	return proof, nil
}

// All original shared actors freeze before ANY full-source held observation.
func (s *PreparedOriginalWriterSet) freezeSharedRuntimeLifecycle(ctx context.Context) error {
	for _, a := range s.sharedLifecycle {
		proof, err := a.transition(ctx, "freeze", nil)
		if err != nil || proof.Response().Phase != "frozen" {
			return ErrInstall
		}
		a.frozen = proof
	}
	return nil
}

func (s *PreparedOriginalWriterSet) checkSharedRuntimeLifecycle(ctx context.Context) error {
	if len(s.sharedLifecycle) != len(s.sharedRuntimes) {
		return ErrInstall
	}
	for _, a := range s.sharedLifecycle {
		proof, err := a.transition(ctx, "check-frozen", nil)
		if err != nil || proof.Response().Action != "check-frozen" {
			return ErrInstall
		}
		a.current = proof
	}
	return nil
}

func (s *PreparedOriginalWriterSet) sharedRuntimeFrozenScopes(node string) ([]q.SharedRuntimeFrozenScope, error) {
	out := []q.SharedRuntimeFrozenScope{}
	for _, a := range s.sharedLifecycle {
		if a.request.Binding.Node != node {
			continue
		}
		scope, err := a.current.FrozenScope()
		if err != nil {
			return nil, ErrInstall
		}
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentPod.UID < out[j].AgentPod.UID })
	return out, nil
}

// This local check belongs inside the EXISTING originalHeldReadiness actual
// SQL verifier, after checkSharedRuntimeLifecycle + whole-node I/O outside tx.
func (s *PreparedOriginalWriterSet) recheckSharedRuntimeHeld(ctx context.Context, now time.Time) error {
	if len(s.sharedLifecycle) != len(s.sharedRuntimes) {
		return ErrInstall
	}
	for _, a := range s.sharedLifecycle {
		if a.current == nil || a.prepared == nil || a.current.Recheck(ctx, a.request.Binding, "check-frozen", a.prepared.Response().BootID, a.request.Original.OriginalSHA256, a.request.Anchor, q.SharedRuntimeNodeCohortSHA(a.request), q.SharedRuntimeNodeSourcePathsSHA(a.request), now) != nil {
			return ErrInstall
		}
	}
	return nil
}

// Caller is RestoreOriginalSources AFTER the existing actual fresh recovery
// authorization has canceled and WAITED all concrete registered providers.
// Every actor is attempted even when another fails; final common gates remain.
func (s *PreparedOriginalWriterSet) restoreSharedRuntimeLifecycle(ctx context.Context, fence *originalWriterRecoveryFence) error {
	failed := false
	for _, a := range s.sharedLifecycle {
		if a.restore(ctx, fence) != nil {
			failed = true
		}
	}
	if failed {
		return ErrOriginalRecoveryNativeProof
	}
	return nil
}

func (a *originalSharedRuntimeLifecycle) restore(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence == nil || fence.owner != a.source.set.owner || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	// Physical cleanup precedes Agent HTTP. A dead/replaced original can still
	// require old-cgroup thaw but must never be accepted as logical recovery.
	proof, err := a.transition(ctx, "thaw", fence)
	if err != nil || (proof.Response().Phase != "thawed" && proof.Response().Phase != "recovered" && proof.Response().Phase != "completed") {
		return ErrOriginalRecoveryNativeProof
	}
	resumeAction := "state"
	if !a.agentResumeDispatched {
		if a.source.set.journal.append(ctx, a.source.ID(), "shared_agent_resume_send_unknown", nil, a.source.identity) != nil {
			return ErrInstall
		}
		a.agentResumeDispatched = true
		resumeAction = "resume"
	}
	state, raw, err := reconcileOriginalSharedResume(ctx, a.source.callbacks, a.source.row.Endpoint, resumeAction, a.source.identity, a.request.Original.OriginalSHA256, func() error {
		if fence.checkReleasing(ctx) != nil {
			return ErrInstall
		}
		return a.source.set.journal.append(ctx, a.source.ID(), "shared_agent_resume_send_unknown", nil, a.source.identity)
	})
	if err != nil || (state.Phase != "resumed" && state.Phase != "completed") || state.OriginalSHA256 != a.request.Original.OriginalSHA256 {
		return ErrOriginalRecoveryNativeProof
	}
	a.request.Current = &state
	a.request.CurrentRaw = bytes.Clone(raw)
	if state.Phase == "resumed" {
		proof, err = a.transition(ctx, "recovered", fence)
		if err != nil || proof.Response().Phase != "recovered" {
			return ErrOriginalRecoveryNativeProof
		}
		a.recovered = proof
	}
	if !a.agentCompleteDispatched {
		if a.source.set.journal.append(ctx, a.source.ID(), "shared_agent_complete_send_unknown", nil, a.source.identity) != nil {
			return ErrInstall
		}
		a.agentCompleteDispatched = true
	}
	// Complete is an explicit idempotent finalization of THIS original Agent
	// reservation; after a prior readable completed replacement r2 must finish
	// its same in-memory barriers. A state query alone cannot finish that step.
	state, raw, err = a.source.callbacks.Transition(ctx, a.source.row.Endpoint, "complete", a.source.identity)
	if err != nil || state.Phase != "completed" || state.OriginalSHA256 != a.request.Original.OriginalSHA256 {
		return ErrOriginalRecoveryNativeProof
	}
	a.request.Current = &state
	a.request.CurrentRaw = bytes.Clone(raw)
	proof, err = a.transition(ctx, "complete", fence)
	if err != nil || proof.Response().Phase != "completed" {
		return ErrOriginalRecoveryNativeProof
	}
	a.completed = proof
	return nil
}
