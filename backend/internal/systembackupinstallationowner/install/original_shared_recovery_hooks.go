package install

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

func (s *PreparedOriginalWriterSet) refreshSharedRuntimeRecovered(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if len(s.sharedRuntimes) == 0 {
		return nil
	}
	if len(s.sharedLifecycle) != len(s.sharedRuntimes) || fence.checkReleasing(ctx) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	for _, actor := range s.sharedLifecycle {
		if actor.completed == nil || actor.request.Current == nil || actor.request.Current.Phase != "completed" {
			return ErrOriginalRecoveryNativeProof
		}
		proof, err := actor.transition(ctx, "complete", fence)
		if err != nil || proof.Response().Action != "complete" || proof.Response().Phase != "completed" {
			return ErrOriginalRecoveryNativeProof
		}
		actor.completed = proof
	}
	return nil
}

func (s *PreparedOriginalWriterSet) recheckSharedRuntimeRecovered(ctx context.Context, now time.Time) error {
	if len(s.sharedLifecycle) != len(s.sharedRuntimes) {
		return ErrOriginalRecoveryNativeProof
	}
	for _, actor := range s.sharedLifecycle {
		r := actor.request
		if actor.completed == nil || actor.completed.Recheck(ctx, r.Binding, "complete", r.Original.BootID, r.Original.OriginalSHA256, r.Anchor, q.SharedRuntimeNodeCohortSHA(r), q.SharedRuntimeNodeSourcePathsSHA(r), now) != nil {
			return ErrOriginalRecoveryNativeProof
		}
	}
	return nil
}

// Reference data only. The readonly recovery reader must independently open
// the original actual native state and kernel freeze for every complete peer.
// A stored capture receipt never becomes a fresh recovery observation locally.
func (s *PreparedOriginalWriterSet) sharedRecoveryFrozenScopes(node string) ([]q.SharedRuntimeFrozenScope, error) {
	refs := []q.SharedRuntimeFrozenScope{}
	for _, actor := range s.sharedLifecycle {
		if actor.request.Binding.Node != node {
			continue
		}
		var proof *q.VerifiedSharedRuntimeNodeObservation
		if actor.current != nil {
			proof = actor.current
		} else if actor.frozen != nil {
			proof = actor.frozen
		} else {
			return nil, ErrOriginalRecoveryNativeProof
		}
		r := actor.request
		response := proof.Response()
		if response.Phase != "frozen" {
			return nil, ErrOriginalRecoveryNativeProof
		}
		refs = append(refs, q.SharedRuntimeFrozenScope{Binding: r.Binding, AgentPod: r.AgentPod, Anchor: r.Anchor, OriginalSHA256: r.Original.OriginalSHA256, CohortSHA256: q.SharedRuntimeNodeCohortSHA(r), SourcePathsSHA256: q.SharedRuntimeNodeSourcePathsSHA(r), NativeJournalSHA256: response.NativeJournalSHA256})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].AgentPod.UID < refs[j].AgentPod.UID })
	return refs, nil
}

// inspectOriginal holds the actual original journal mutex. Verify each new
// actor's real send-intent against its opaque source/identity/native request,
// not a caller inspection or a copied Passed flag.
func (s *PreparedOriginalWriterSet) inspectSharedOriginalRecords(records []originalWriterJournalRecord) error {
	for _, source := range s.sharedRuntimes {
		if source == nil || source.set != s {
			return ErrInstall
		}
		seenReserve := false
		nativeSeen := map[string]bool{}
		var actor *originalSharedRuntimeLifecycle
		for _, candidate := range s.sharedLifecycle {
			if candidate.source == source {
				if actor != nil {
					return ErrInstall
				}
				actor = candidate
			}
		}
		acquired := false
		for _, record := range records {
			if record.Action == "capture_gate_acquire_send_unknown" {
				acquired = true
			}
			if record.Writer != source.ID() {
				continue
			}
			if record.Action == "shared_reservation_send_unknown" {
				var identity struct{ Protocol, Namespace, PodUID, Deployment, AgentEpoch, OperationID, InventorySHA256 string }
				if !acquired || seenReserve || record.Original != nil || !source.dispatched || json.Unmarshal(record.Data, &identity) != nil || originalObjectSHA(identity) != originalObjectSHA(source.identity) {
					return ErrInstall
				}
				seenReserve = true
			}
			for _, action := range []string{"prepare", "freeze", "thaw", "complete"} {
				if record.Action != "shared_node_"+action+"_send_unknown" {
					continue
				}
				var request q.SharedRuntimeNodeRequest
				if actor == nil || !actor.dispatched[action] || record.Original != nil || json.Unmarshal(record.Data, &request) != nil || request.Action != action || originalObjectSHA(request.Binding) != originalObjectSHA(actor.request.Binding) || request.Original.OriginalSHA256 != actor.request.Original.OriginalSHA256 || !reflect.DeepEqual(request.AgentPod, actor.request.AgentPod) || !reflect.DeepEqual(request.SourcePaths, actor.request.SourcePaths) {
					return ErrInstall
				}
				if action == "prepare" && request.Anchor != "" || action != "prepare" && request.Anchor != actor.request.Anchor {
					return ErrInstall
				}
				nativeSeen[action] = true
			}
		}
		if source.dispatched && !seenReserve {
			return ErrInstall
		}
		if actor != nil {
			for _, action := range []string{"prepare", "freeze", "thaw", "complete"} {
				if actor.dispatched[action] && !nativeSeen[action] {
					return ErrInstall
				}
			}
		}
	}
	return nil
}
