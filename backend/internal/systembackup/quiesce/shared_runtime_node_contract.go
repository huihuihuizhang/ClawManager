package quiesce

import (
	"context"
	"reflect"
	"time"

	"clawreef/internal/services"
)

const SharedRuntimeNodeProtocol = "shared-runtime-node-lifecycle.v1"
const SharedRuntimeNodeKind = "original_shared_container_freeze"
const SharedRuntimeNodeRoute = "/shared-runtime-lifecycle/v1"

// Each peer is another ORIGINAL prepared container in this SAME Node's full
// original cohort. Its anchor is opened by the native owner, never trusted as
// a caller assertion that a process is frozen. Sorted by PodUID, including self.
type SharedRuntimeNodePeer struct {
	PodUID, OriginalSHA256, Anchor string
}

// Distinct from NodeObserver's read-only contract. The external Node lifecycle
// owner implements mutation; the ordinary NodeObserver remains read-only.
// No host path for the Node owner's private recovery store is caller-selected.
type SharedRuntimeNodeRequest struct {
	Version, Action, Nonce      string
	Binding                     ObservationBinding
	Deadline                    time.Time
	AgentPod                    PodIdentity
	WorkspaceRoot, AgentDataDir string
	// Actual original Agent reserved response. Identical in every later action,
	// including recovery. Never replace it with a newer manager incarnation.
	Original    services.RuntimeSharedNativeState
	OriginalRaw []byte
	// Actual authenticated resume/complete reply only, never restart requests.
	Current    *services.RuntimeSharedNativeState
	CurrentRaw []byte
	// Full native host source roots on this Node, identical across its cohorts.
	// Supplied on prepare and bound inside Anchor; repeated unchanged thereafter.
	SourcePaths []string
	// Empty for prepare; complete SAME-node original cohort for other actions.
	Peers  []SharedRuntimeNodePeer
	Anchor string
	// Reference to D/A's existing authenticated, drained original recovery
	// boundary. DATA only to Node; D checks the concrete original recovery fence.
	// Never extends Binding.ExpiresAt or authorizes another capture.
	RecoveryBoundarySHA256 string
}

type SharedRuntimeNodeResponse struct {
	Version, Action, Nonce, RequestSHA256                               string
	Binding                                                             ObservationBinding
	Anchor, BootID, OriginalSHA256, OriginalRawSHA256, CurrentRawSHA256 string
	CohortSHA256, SourcePathsSHA256, NativeJournalSHA256                string
	// prepared/frozen/thawed/recovered/completed/orphan-thawed are native
	// lifecycle states. orphan-thawed is cleanup DATA, never recovery success.
	Phase                             string
	StartedAt, FinishedAt, ValidUntil time.Time
	TasksChecked, Files               int
	Facts                             []string
}

// These facts describe exact bounded native work, NOT SQL/source-gate authority.
// freeze alone deliberately has no source flush or external-writer claim.
func SharedRuntimeNodeFacts(action string) []string {
	switch action {
	case "prepare":
		return []string{"actual_shared_go_agent_and_guard_observed", "original_agent_journal_native_current", "exact_container_cgroup_and_source_mounts_pinned", "original_physical_recovery_obligation_durable"}
	case "freeze":
		return []string{"original_physical_recovery_obligation_durable", "exact_original_container_cgroup_frozen", "original_agent_reservation_native_current"}
	case "check-frozen":
		return []string{"all_original_node_cohort_cgroups_frozen", "original_agent_reservations_native_current", "original_source_mounts_unchanged", "no_observed_unfrozen_external_source_writer", "native_source_flush_boundary_current"}
	case "thaw":
		return []string{"exact_original_container_cgroup_thawed", "original_process_identities_preserved", "physical_recovery_transition_durable"}
	case "recovered":
		return []string{"exact_original_container_cgroup_thawed", "original_process_identities_preserved", "original_agent_resumed_journal_native_current", "original_source_mounts_unchanged"}
	case "complete":
		return []string{"exact_original_container_cgroup_thawed", "original_process_identities_preserved", "original_agent_completed_journal_native_current", "original_physical_recovery_obligation_closed_durable"}
	case "orphan-thawed":
		return []string{"pinned_original_cgroup_thaw_attempt_observed", "original_logical_recovery_unconfirmed", "original_recovery_obligation_retained"}
	case "state":
		return []string{"original_physical_recovery_journal_read", "actual_original_native_lifecycle_state_observed"}
	default:
		return nil
	}
}

// Only the concrete authenticated TLS transport may mint this opaque bounded
// native observation. No deserialization, caller boolean or field constructor.
type VerifiedSharedRuntimeNodeObservation struct {
	response        SharedRuntimeNodeResponse
	originalRequest SharedRuntimeNodeRequest
}

func (p *VerifiedSharedRuntimeNodeObservation) Response() SharedRuntimeNodeResponse {
	if p == nil {
		return SharedRuntimeNodeResponse{}
	}
	r := p.response
	r.Facts = append([]string(nil), r.Facts...)
	return r
}

// Performs NO I/O and never renews the original native observation. Used only
// inside D's existing original held/recovery SQL verifier after outside I/O.
func (p *VerifiedSharedRuntimeNodeObservation) Recheck(ctx context.Context, binding ObservationBinding, action, boot, originalSHA, anchor, cohortSHA, sourcePathsSHA string, now time.Time) error {
	if p == nil || ctx == nil || ctx.Err() != nil || now.IsZero() || observationDigest(binding) != observationDigest(p.response.Binding) || p.response.Action != action || action == "state" || action == "orphan-thawed" || p.response.Phase == "orphan-thawed" || p.response.BootID != boot || boot == "" || p.response.OriginalSHA256 != originalSHA || p.response.Anchor != anchor || anchor == "" || p.response.CohortSHA256 != cohortSHA || p.response.SourcePathsSHA256 != sourcePathsSHA || !validObservationHash(p.response.NativeJournalSHA256) || now.Before(p.response.StartedAt) || !now.Before(p.response.ValidUntil) || !time.Now().Before(p.response.ValidUntil) || !reflect.DeepEqual(p.response.Facts, SharedRuntimeNodeFacts(action)) {
		return ErrNodeObservation
	}
	return nil
}

func SharedRuntimeNodeOriginalSHA(r SharedRuntimeNodeRequest) string {
	return services.SharedRuntimeOriginalSHA(r.Original)
}
func SharedRuntimeNodeCohortSHA(r SharedRuntimeNodeRequest) string { return observationDigest(r.Peers) }
func SharedRuntimeNodeSourcePathsSHA(r SharedRuntimeNodeRequest) string {
	return observationDigest(r.SourcePaths)
}
