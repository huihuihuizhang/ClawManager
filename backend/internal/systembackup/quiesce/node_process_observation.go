package quiesce

// Process observations cover only the original cold Pod process scopes and
// their recovery. CSI/provider actors prove storage independently. This kind
// cannot attest file contents, mounts, or archive eligibility.
const NodeObservationColdProcesses = "original_cold_processes"

func nodeObservationKindValid(kind string) bool {
	return kind == NodeObservationWholePodColdCut || kind == NodeObservationColdProcesses
}

func nodeProcessFacts(action string) []string {
	switch action {
	case "prepare":
		return []string{"original_running_cri_processes_observed"}
	case "stopped", "recovery-stopped":
		return []string{"original_cri_containers_exited", "original_process_scopes_absent"}
	case "recovered":
		return []string{"original_cri_containers_exited", "original_process_scopes_absent", "replacement_cri_processes_running"}
	case "recovery-source-stopped":
		return []string{"affected_original_cri_containers_exited", "fenced_original_process_scopes_absent", "declared_current_process_scopes_native_verified"}
	case "recovery-reconciled":
		return []string{"original_actors_native_partitioned", "fenced_original_process_scopes_absent", "declared_current_process_scopes_native_verified"}
	}
	return nil
}

func nodeObservationPreparePathsValid(r NodeObservationRequest) bool {
	if r.Binding.Kind == NodeObservationColdProcesses {
		return len(r.SourcePaths) == 0
	}
	return r.Binding.Kind == NodeObservationWholePodColdCut && len(r.SourcePaths) > 0 && len(r.SourcePaths) <= 128
}
