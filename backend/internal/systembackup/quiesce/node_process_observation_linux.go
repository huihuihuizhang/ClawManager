//go:build linux

package quiesce

import (
	"context"
	"reflect"
)

// Uses the original sealed actor partition and real CRI roots. No filesystem
// source or storage release is implied by this process-only reconciliation.
func (o *NodeObserver) reconcileColdProcesses(ctx context.Context, r NodeObservationRequest, a nodeObservationAnchor, fencedPods []PodIdentity, fenced, roots, live []observedProcess) (originalRecoveryNativeResult, error) {
	if r.Binding.Kind != NodeObservationColdProcesses || len(a.Paths) != 0 || len(r.SourcePaths) != 0 || len(r.SharedFrozenScopes) != 0 {
		return originalRecoveryNativeResult{}, ErrNodeObservation
	}
	for _, process := range append(append([]observedProcess(nil), roots...), live...) {
		if originalRecoveryScopeContains(process, fenced) {
			return originalRecoveryNativeResult{}, observationFailure("original_process_present")
		}
	}
	tasks, err := o.scanOriginalRecovery(ctx, nil, fenced, roots, live, nil)
	if err != nil {
		return originalRecoveryNativeResult{}, err
	}
	if len(fencedPods) > 0 && (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, fencedPods) != nil {
		return originalRecoveryNativeResult{}, observationFailure("original_cri_exit")
	}
	if len(r.RecoveredPods) > 0 {
		current, err := o.runningRecoveryScopes(ctx, r.Binding, r.RecoveredPods, nil, false)
		if err != nil || !reflect.DeepEqual(current, roots) {
			return originalRecoveryNativeResult{}, observationFailure("recovery_current_drift")
		}
	}
	return originalRecoveryNativeResult{Processes: len(roots), Tasks: tasks}, ctx.Err()
}
