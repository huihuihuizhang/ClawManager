package install

import (
	"context"
	"errors"
	"reflect"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// B's concrete authenticated client may implement this read-only scope method.
// Its server must open the ORIGINAL complete anchor and independently prove
// absence of exactly these original affected processes while reconciling the
// remaining native scopes. No caller DTO can create the returned opaque proof.
// An older concrete client refuses this operation; no bool/ACK fallback exists.
type originalScopedRecoveryObserver interface {
	ObserveOriginalRecoveryScope(context.Context, q.NodeObservationRequest, []q.PodIdentity) (*q.VerifiedNodeObservation, error)
}

// This branch is reached only from the genuine private set after an Acquire
// which did not return a complete hold. It never stops an additional actor to
// make a global quiescence test pass. Failures on one source do not suppress a
// safe cancellation/restore of another source; final admission stays closed
// until the COMPLETE current source and native recovery proof succeeds.
func (s *PreparedOriginalWriterSet) restoreOriginalPartial(ctx context.Context, fence *originalWriterRecoveryFence) error {
	failures := []error{}
	if err := s.restoreSharedRuntimeLifecycle(ctx, fence); err != nil {
		failures = append(failures, err)
	}
	for _, writer := range s.deployments {
		if !writer.stopDispatched {
			continue
		}
		writer.recovery = fence
		if writer.redis != nil {
			if e := writer.restore(ctx, fence); e != nil {
				failures = append(failures, e)
			}
			continue
		}
		if writer.minio != nil {
			if e := writer.restore(ctx, fence); e != nil {
				failures = append(failures, e)
			}
			continue
		}
		if fence.checkReleasing(ctx) != nil {
			failures = append(failures, ErrInstall)
			break
		}
		current, err := writer.current(ctx)
		unchanged := false
		if err == nil && *current.Spec.Replicas == writer.replicas && current.Status.ReadyReplicas == writer.replicas {
			pods, e := writer.currentPods(ctx, current, true)
			unchanged = e == nil && reflect.DeepEqual(pods, writer.pods)
		}
		// Cancelling a delayed scale on a still-original ready set adds no process.
		// A stopped/replaced set must have actual old-scope absence before restart.
		if writer.replicas > 0 && !unchanged && s.proveOriginalAffectedAbsent(ctx, fence, writer.pods) != nil {
			failures = append(failures, ErrOriginalRecoveryNativeProof)
			continue
		}
		if err := writer.restore(ctx, fence); err != nil {
			failures = append(failures, err)
		}
	}
	for _, writer := range s.proPods {
		if !writer.stopDispatched {
			continue
		}
		writer.recovery = fence
		if fence.checkReleasing(ctx) != nil {
			failures = append(failures, ErrInstall)
			break
		}
		current, err := fence.operator.installer.kube.CoreV1().Pods(writer.source.Namespace).Get(ctx, writer.source.Pod, metav1.GetOptions{})
		unchanged := false
		if err == nil && string(current.UID) == writer.original.UID && current.DeletionTimestamp == nil && originalObjectSHA(current.Spec) == writer.specSHA {
			process, e := originalMaintenancePodIdentity(current)
			unchanged = e == nil && reflect.DeepEqual(process, writer.process)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			failures = append(failures, ErrInstall)
			continue
		}
		if !unchanged && s.proveOriginalAffectedAbsent(ctx, fence, []q.PodIdentity{writer.process}) != nil {
			failures = append(failures, ErrOriginalRecoveryNativeProof)
			continue
		}
		if err := writer.restore(ctx, fence); err != nil {
			failures = append(failures, err)
		}
	}
	for _, gateway := range s.gateways {
		if !gateway.stopDispatched {
			continue
		}
		gateway.recovery = fence
		if fence.checkReleasing(ctx) != nil {
			failures = append(failures, ErrInstall)
			break
		}
		// Gateway.Resume independently reads the exact operation after an unknown
		// stop/reserve send and requires B's own fresh recovery-native observations.
		if err := gateway.Resume(ctx, gateway.state); err != nil {
			failures = append(failures, err)
		}
	}
	for _, source := range s.stopped {
		source.recovery = fence
		if source.recheckSources(ctx) != nil {
			failures = append(failures, ErrOriginalRecoveryNativeProof)
			continue
		}
		if source.anchor == "" {
			failures = append(failures, ErrOriginalRecoveryNativeProof)
			continue
		}
		if source.observe(ctx, "recovered-stopped") != nil {
			failures = append(failures, ErrOriginalRecoveryNativeProof)
		}
	}
	if len(failures) > 0 {
		return errors.Join(append([]error{ErrOriginalRecoveryNativeProof}, failures...)...)
	}
	// Every original whole-Pod source must still have a genuine native scope.
	// A missing prepare result cannot be converted into an empty proof set.
	covered := map[string]bool{}
	for _, node := range s.nodes {
		if node.prepare == nil {
			return ErrOriginalRecoveryNativeProof
		}
		for _, pod := range node.request.Pods {
			covered[pod.UID] = true
		}
	}
	for _, writer := range s.deployments {
		if writer.redis != nil {
			continue
		}
		if writer.minio != nil {
			continue
		}
		for _, pod := range writer.pods {
			if !covered[pod.UID] {
				return ErrOriginalRecoveryNativeProof
			}
		}
	}
	for _, writer := range s.proPods {
		if !covered[writer.original.UID] {
			return ErrOriginalRecoveryNativeProof
		}
	}
	proof, err := s.observeOriginalRecovered(ctx, fence)
	if err != nil {
		return err
	}
	return s.finishOriginalRecovery(ctx, fence, proof)
}

func (s *PreparedOriginalWriterSet) proveOriginalAffectedAbsent(ctx context.Context, fence *originalWriterRecoveryFence, affected []q.PodIdentity) error {
	if len(affected) == 0 || fence.checkReleasing(ctx) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	grouped := map[*originalWholeNodeScope][]q.PodIdentity{}
	for _, pod := range affected {
		var selected *originalWholeNodeScope
		for _, node := range s.nodes {
			for _, old := range node.request.Pods {
				if reflect.DeepEqual(old, pod) {
					if selected != nil {
						return ErrOriginalRecoveryNativeProof
					}
					selected = node
				}
			}
		}
		if selected == nil || selected.prepare == nil {
			return ErrOriginalRecoveryNativeProof
		}
		grouped[selected] = append(grouped[selected], pod)
	}
	for node, pods := range grouped {
		request := node.request
		request.SourcePaths = nil
		request.Anchor = node.prepare.Response().Anchor
		action := "recovery-stopped"
		var proof *q.VerifiedNodeObservation
		var err error
		if len(pods) == len(node.request.Pods) {
			request.Action = action
			proof, err = s.wholePodClient.ObserveVerified(ctx, request)
		} else {
			reader, ok := any(s.wholePodClient).(originalScopedRecoveryObserver)
			if !ok {
				return ErrOriginalRecoveryNativeProof
			}
			action = "recovery-source-stopped"
			request.Action = action
			peers, e := s.readOriginalRecoveryPeers(ctx, fence, node, pods)
			if e != nil {
				return ErrOriginalRecoveryNativeProof
			}
			request.RecoveredPods = peers.Pods
			request.RecoveryAffectedPods = append([]q.PodIdentity(nil), pods...)
			request.RecoveredGeneration = s.owner.token.Generation
			facts, e := s.persistOriginalRecoveryFacts(ctx, node, request, peers, nil)
			if e != nil {
				return e
			}
			request.RecoverySnapshotSHA256 = facts.sha256
			proof, err = reader.ObserveOriginalRecoveryScope(ctx, request, pods)
			again, e := s.readOriginalRecoveryPeers(ctx, fence, node, pods)
			if e != nil || !sameOriginalRecoveryPeers(peers, again) || err != nil || proof == nil || proof.RecheckOriginalRecoveryScope(ctx, request, pods, node.boot, time.Now()) != nil {
				return ErrOriginalRecoveryNativeProof
			}
		}
		if err != nil || proof == nil || action == "recovery-stopped" && proof.Recheck(ctx, request.Binding, action, node.boot, time.Now()) != nil {
			return ErrOriginalRecoveryNativeProof
		}
		if s.journal.append(ctx, node.claim.WriterID, "native_affected_original_scope_absent", nil, struct {
			Request     q.NodeObservationRequest
			Affected    []q.PodIdentity
			Observation q.NodeObservationResponse
		}{request, pods, proof.Response()}) != nil {
			return ErrInstall
		}
	}
	return fence.checkReleasing(ctx)
}
