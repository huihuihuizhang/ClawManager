package install

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	q "clawreef/internal/systembackup/quiesce"
)

// Independent recovery retains the original register/claim, including its
// registration boundary. A node can then close a not-yet-arrived register;
// an existing unknown freeze still requires its actual custody and journal.
func (h *originalLonghornRWXHold) release(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if h == nil || h.set == nil || fence == nil || fence.owner != h.set.owner || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	if h.registration == nil {
		return nil // No native registration was constructed or sent.
	}
	j := h.set.journal
	j.mu.Lock()
	inspection, err := j.inspect(ctx, j.operation, j.inventory)
	tail := j.tail
	j.mu.Unlock()
	if err != nil || inspection.TailSHA256 != tail {
		return ErrInstall
	}
	want, err := json.Marshal(h.registration)
	if err != nil {
		return ErrInstall
	}
	found := 0
	for _, record := range inspection.Records {
		if record.Writer == h.ID() && record.Action == "longhorn_register_intent" && bytes.Equal(record.Data, want) {
			found++
		}
	}
	if found != 1 {
		return ErrInstall
	}
	request := *h.registration
	request.Action, request.DrainBoundarySHA256 = "release", ""
	request.RecoveryBoundarySHA256 = originalObjectSHA([]any{fence.authorization.operation, tail, *h.registration})
	if fence.checkReleasing(ctx) != nil || j.append(ctx, h.ID(), "longhorn_release_intent", nil, request) != nil {
		return ErrInstall
	}
	proof, _, err := h.set.longhornClient.LonghornExt4Transition(ctx, request)
	if err != nil || !originalLonghornRWXReleaseMatches(h.registration, proof) {
		return ErrOriginalRecoveryNativeProof
	}
	if j.append(ctx, h.ID(), "longhorn_release_observed", nil, proof.Response()) != nil {
		return ErrInstall
	}
	h.released, h.held = proof, nil
	return nil
}

func originalLonghornRWXReleaseMatches(registration *q.LonghornExt4Request, proof *q.VerifiedLonghornExt4Observation) bool {
	if registration == nil || proof == nil {
		return false
	}
	r := proof.Response()
	return r.Action == "release" && r.Phase == "released" && (r.NativeState == "rw" || r.NativeState == "thaw-acknowledged") &&
		r.SourceIdentity == registration.SourceIdentity && r.Attempt == registration.Attempt &&
		reflect.DeepEqual(r.Binding, registration.Binding) && reflect.DeepEqual(r.Claim, registration.Claim)
}

func (s *PreparedOriginalWriterSet) releaseLonghornRWX(ctx context.Context, fence *originalWriterRecoveryFence) error {
	for _, source := range s.longhornRWX {
		if err := source.release(ctx, fence); err != nil {
			return err
		}
	}
	return nil
}
