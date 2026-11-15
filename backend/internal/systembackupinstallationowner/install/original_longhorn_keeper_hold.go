package install

import (
	"context"
	"reflect"
	"time"

	"clawreef/internal/systembackup/kube"
	c "clawreef/internal/systembackupcontroller"
)

// API disappearance supplies the drain boundary, never the physical held
// proof. The node independently verifies the keeper's device and freezes it.
func (h *originalLonghornKeeper) acquire(ctx context.Context) error {
	if h == nil || h.set == nil || h.writer == nil || h.registration == nil || h.native == nil || h.acquireDispatched || !h.registered || !h.writer.stopDispatched || h.checkForward(ctx) != nil {
		return ErrInstall
	}
	dep, err := h.writer.current(ctx)
	if err != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 || dep.Status.ObservedGeneration < dep.Generation {
		return ErrInstall
	}
	pods, err := h.writer.currentPods(ctx, dep, false)
	if err != nil || len(pods) != 0 || h.recheckProcess(ctx) != nil {
		return ErrInstall
	}
	request := *h.registration
	request.Action = "acquire"
	request.DrainBoundarySHA256 = originalObjectSHA([]any{h.writer.original, dep.UID, dep.ResourceVersion, dep.Generation, h.process, pods})
	// Latch before dispatch: a lost reply must go to independent recovery.
	h.acquireDispatched = true
	h.held = nil
	proof, _, err := h.set.owner.forwardLonghorn(ctx, h.native, h.set.journal, h.reservation, &request)
	if err != nil {
		return err
	}
	h.held = proof
	return h.recheckHeld(time.Now())
}

func (h *originalLonghornKeeper) recheckProcess(ctx context.Context) error {
	if h == nil || h.set == nil || h.record.UID == "" || h.process.UID == "" {
		return ErrInstall
	}
	process, err := (kube.WorkerObserver{Client: h.set.owner.operator.installer.kube}).Observe(ctx, h.record, kube.WorkerSecurity{NodeUIDs: map[string]string{h.plan.Node: h.plan.NodeUID}, Volumes: []kube.MountIdentity{h.plan.Source}, ServiceAccountName: h.plan.ServiceAccount, ServiceAccountUID: h.serviceAccountUID})
	if err != nil || !kube.SameWorkerProcess(process, h.process) {
		return ErrInstall
	}
	return nil
}

func (h *originalLonghornKeeper) checkHeld(ctx context.Context) error {
	if h == nil || h.set == nil || h.registration == nil || h.native == nil || !h.acquireDispatched || h.held == nil || h.set.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || h.recheckProcess(ctx) != nil {
		return ErrInstall
	}
	request := *h.registration
	request.Action = "check-held"
	reservation := h.reservation
	// Phase is a current SQL predicate; all acquisition identity stays fixed.
	reservation.Phase = h.set.owner.token.State
	h.held = nil
	proof, _, err := h.set.owner.forwardLonghorn(ctx, h.native, h.set.journal, reservation, &request)
	if err != nil {
		return err
	}
	h.held = proof
	return h.recheckHeld(time.Now())
}

func (h *originalLonghornKeeper) recheckHeld(now time.Time) error {
	if h == nil || h.registration == nil || h.held == nil || !h.acquireDispatched {
		return ErrInstall
	}
	r := h.held.Response()
	if r.Action != "acquire" && r.Action != "check-held" || r.Phase != "held" || r.NativeState != "freeze-stable" || r.SourceIdentity != h.registration.SourceIdentity || r.Attempt != h.registration.Attempt || !reflect.DeepEqual(r.Binding, h.registration.Binding) || !reflect.DeepEqual(r.Claim, h.registration.Claim) || r.HeldObservedAt.IsZero() || now.Before(r.HeldObservedAt) || now.Sub(r.HeldObservedAt) > 10*time.Second || !now.Before(r.ExpiresAt) {
		return ErrInstall
	}
	return nil
}
