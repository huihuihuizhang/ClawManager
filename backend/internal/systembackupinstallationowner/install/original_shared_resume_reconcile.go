package install

import (
	"context"

	"clawreef/internal/services"
)

// Called ONLY after the original lifecycle proved same-incarnation physical
// thaw under its fresh recovery fence. This helper creates no physical proof.
// Transition uses the actual private Agent client and validates original ID,
// hash and journal. Native resume independently checks original entries/PIDs,
// start ticks and running health; it never reconstructs a Start request.
func reconcileOriginalSharedResume(ctx context.Context, callbacks *services.RuntimeSharedBackupCallbacks, endpoint, action string, identity services.RuntimeSharedBackupIdentity, originalSHA string, beforeResend func() error) (services.RuntimeSharedNativeState, []byte, error) {
	var zero services.RuntimeSharedNativeState
	if ctx == nil || ctx.Err() != nil || callbacks == nil || (action != "resume" && action != "state") || len(originalSHA) != 64 {
		return zero, nil, ErrOriginalRecoveryNativeProof
	}
	state, raw, err := callbacks.Transition(ctx, endpoint, action, identity)
	if err != nil || state.OriginalSHA256 != originalSHA {
		return zero, nil, ErrOriginalRecoveryNativeProof
	}
	if action == "state" && state.Phase == "reserved" {
		// A prior send-unknown may mean the request never arrived. Reconcile
		// once per recovery invocation, with a NEW durable dispatch boundary
		// for the SAME identity/operation; no automatic transport retry/loop.
		if ctx.Err() != nil || beforeResend == nil || beforeResend() != nil {
			return zero, nil, ErrOriginalRecoveryNativeProof
		}
		state, raw, err = callbacks.Transition(ctx, endpoint, "resume", identity)
	}
	if err != nil || state.OriginalSHA256 != originalSHA || (state.Phase != "resumed" && state.Phase != "completed") {
		return zero, nil, ErrOriginalRecoveryNativeProof
	}
	return state, raw, nil
}
