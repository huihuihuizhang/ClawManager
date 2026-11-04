package quiesce

// Deployment-pinned release input, never obtained from a lifecycle request.
// ExecutableSHA256 identifies the running Go Agent ELF, not its image label.
type SharedRuntimeAgentRelease struct {
	ExecutableSHA256 string
	DataDir          string
}

type SharedRuntimeNodeOwnerConfig struct {
	CgroupMount   string
	Directory     string
	ControllerURI string
	Releases      map[string]SharedRuntimeAgentRelease
}

// Fixed startup configuration for the read-only whole-node observer. It has
// no mutating owner, freeze handle, callback, request-selected path or lock.
type SharedRuntimeFrozenReaderConfig struct {
	CgroupMount string
	Directory   string
	Releases    map[string]SharedRuntimeAgentRelease
}

func sharedFrozenObservationFacts() []string {
	return []string{"original_cold_pod_cri_containers_exited", "original_cold_process_scopes_absent", "original_shared_container_cgroups_frozen", "no_observed_unfrozen_source_fd_or_shared_mmap", "source_mount_identities_unchanged"}
}
