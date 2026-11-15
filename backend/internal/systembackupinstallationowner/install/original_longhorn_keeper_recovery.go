package install

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
)

// Independent fresh recovery authority consumes the exact durable forward
// intent. Neither an expired lease nor a missing register response permits a
// new keeper/claim to be substituted for the one that may hold the device.
func (h *originalLonghornKeeper) releaseNative(ctx context.Context, fence *originalWriterRecoveryFence) (*q.VerifiedLonghornExt4Observation, error) {
	if h == nil || h.set == nil || fence == nil || fence.owner != h.set.owner || fence.checkReleasing(ctx) != nil || h.registration == nil || h.native == nil {
		return nil, ErrInstall
	}
	j := h.set.journal
	j.mu.Lock()
	inspection, err := j.inspect(ctx, j.operation, j.inventory)
	tail := j.tail
	j.mu.Unlock()
	if err != nil || inspection.TailSHA256 != tail {
		return nil, ErrInstall
	}
	want, err := json.Marshal(h.registration)
	if err != nil {
		return nil, ErrInstall
	}
	found := 0
	for _, record := range inspection.Records {
		if record.Writer == h.writer.ID() && record.Action == "longhorn_register_intent" && bytes.Equal(record.Data, want) {
			found++
		}
	}
	if found != 1 {
		return nil, ErrInstall
	}
	request := *h.registration
	request.Action, request.DrainBoundarySHA256 = "release", ""
	request.RecoveryBoundarySHA256 = originalObjectSHA([]any{fence.authorization.operation, tail, *h.registration})
	if fence.checkReleasing(ctx) != nil || j.append(ctx, h.writer.ID(), "longhorn_release_intent", nil, request) != nil {
		return nil, ErrInstall
	}
	proof, _, err := h.native.LonghornExt4Transition(ctx, request)
	if err != nil {
		return nil, err
	}
	if j.append(ctx, h.writer.ID(), "longhorn_release_observed", nil, proof.Response()) != nil {
		return nil, ErrInstall
	}
	return proof, nil
}

// Keep the attachment until the native release AND business controller
// recovery are observed. Runner performs UID/RV preconditioned deletion and
// refuses to turn a timed-out create followed by 404 into cleanup success.
func (h *originalLonghornKeeper) cleanup(ctx context.Context, fence *originalWriterRecoveryFence, release *q.VerifiedLonghornExt4Observation) (bool, error) {
	if h == nil || h.set == nil || fence == nil || fence.owner != h.set.owner || fence.checkReleasing(ctx) != nil {
		return false, ErrInstall
	}
	if h.registration != nil {
		if release == nil {
			return false, ErrInstall
		}
		out := release.Response()
		if out.Action != "release" || out.Phase != "released" || out.NativeState != "rw" && out.NativeState != "thaw-acknowledged" || out.SourceIdentity != h.registration.SourceIdentity || out.Attempt != h.registration.Attempt || !reflect.DeepEqual(out.Claim, h.registration.Claim) || !reflect.DeepEqual(out.Binding, h.registration.Binding) {
			return false, ErrInstall
		}
	}
	h.writer.recovery = fence
	dep, err := h.writer.current(ctx)
	if err != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != h.writer.replicas || dep.Status.ReadyReplicas != h.writer.replicas || dep.Status.ObservedGeneration < dep.Generation {
		return false, ErrInstall
	}
	pods, err := h.writer.currentPods(ctx, dep, true)
	if err != nil || len(pods) != int(h.writer.replicas) {
		return false, ErrInstall
	}
	clients, ok := fence.operator.installer.kube.(*originalKubernetesClients)
	if !ok || clients.resources == nil {
		return false, ErrInstall
	}
	journal := &originalKeeperResourceJournal{journal: h.set.journal, identity: h.plan.Identity, check: fence.checkReleasing}
	runner := kube.Runner{Client: clients.resources, Journal: journal, CheckFence: fence.checkReleasing}
	return runner.Cleanup(ctx, h.record)
}

func (s *PreparedOriginalWriterSet) releaseLonghornKeepers(ctx context.Context, fence *originalWriterRecoveryFence) error {
	for _, h := range s.longhornKeepers {
		if h.registration == nil {
			continue // No native request was ever prepared or sent.
		}
		proof, err := h.releaseNative(ctx, fence)
		if err != nil {
			return err
		}
		h.released, h.held = proof, nil
	}
	return nil
}

func (s *PreparedOriginalWriterSet) cleanupLonghornKeepers(ctx context.Context, fence *originalWriterRecoveryFence) error {
	for _, h := range s.longhornKeepers {
		if h.cleaned || h.record.Intent.Kind == "" {
			continue // Runner returned before any durable resource intent.
		}
		done, err := h.cleanup(ctx, fence, h.released)
		if err != nil || !done {
			return ErrOriginalRecoveryNativeProof
		}
		h.cleaned = true
	}
	return nil
}
