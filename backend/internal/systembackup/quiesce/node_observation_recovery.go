package quiesce

import (
	"reflect"
	"time"
)

// These are the only phases allowed after the original capture window. A new
// bounded authenticated RPC is still required. D independently verifies fresh
// recovery/releasing authority for the exact original gate and keeper.
func nodeObservationRecoveryAction(action string) bool {
	return action == "recovery-stopped" || action == "recovered" || originalRecoveryScopedPhase(action)
}

// Correlation DATA checks only; no held-gate, restart or native proof is made.
// In this protocol Generation is the original SQL gate generation. Replacement
// source identities come from D's journal and the actual native CRI checks.
func nodeObservationPhaseDataValid(r NodeObservationRequest, node string) bool {
	if r.Binding.Kind != NodeObservationWholePodColdCut || r.Binding.Generation == 0 || !validObservationPods(r.Pods, node) {
		return false
	}
	if originalRecoveryScopedPhase(r.Action) {
		return originalRecoveryDataValid(r, node)
	}
	if len(r.RecoveryAffectedPods) != 0 || r.RecoverySnapshotSHA256 != "" {
		return false
	}
	switch r.Action {
	case "prepare":
		return r.Anchor == "" && len(r.SourcePaths) > 0 && len(r.SourcePaths) <= 128 && len(r.RecoveredPods) == 0 && r.RecoveredGeneration == 0
	case "stopped", "recovery-stopped":
		return r.Anchor != "" && len(r.SourcePaths) == 0 && len(r.RecoveredPods) == 0 && r.RecoveredGeneration == 0
	case "recovered":
		if r.Anchor == "" || len(r.SourcePaths) != 0 || r.RecoveredGeneration != r.Binding.Generation || !validObservationPods(r.RecoveredPods, node) {
			return false
		}
		for _, old := range r.Pods {
			for _, next := range r.RecoveredPods {
				if old.UID == next.UID {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

// Authenticate the unchanged original Node-sealed anchor, not a newly issued
// capture scope. This private DATA reader cannot mint a client opaque proof.
func (o *NodeObserver) originalNodeObservationAnchor(r NodeObservationRequest, now time.Time) (nodeObservationAnchor, error) {
	var zero nodeObservationAnchor
	if o == nil || now.IsZero() || r.Action == "prepare" || !nodeObservationPhaseDataValid(r, o.Node) {
		return zero, ErrNodeObservation
	}
	a, err := o.open(r.Anchor)
	if err != nil || observationDigest(a.Binding) != observationDigest(r.Binding) || !reflect.DeepEqual(a.Pods, r.Pods) || a.BootID != o.BootID || a.PreparedAt.After(now) || (!nodeObservationRecoveryAction(r.Action) && !now.Before(a.Binding.ExpiresAt)) {
		return zero, ErrNodeObservation
	}
	return a, nil
}
