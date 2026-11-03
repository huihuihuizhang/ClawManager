package main

import (
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

// Constructors only. The original terminal later compares BOTH per-key
// bindings against this concrete owner's BindingSHA256, and prepares the
// shared pointer once. The record content hash is not that composition hash.
func addOriginalSourceRegistryTerminal(base sec.BootstrapOwnerAdapters, capture *install.CaptureSigningConsumer, files install.BootstrapSourceRegistryFiles, native execution.BootstrapSourceNativeRegistryFiles) (sec.BootstrapOwnerAdapters, *execution.BootstrapSourceRegistryTerminalResource, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *execution.BootstrapSourceRegistryTerminalResource, error) {
		return sec.BootstrapOwnerAdapters{}, nil, sec.ErrRegistrationUnavailable
	}
	if capture == nil || base.Candidates != nil {
		return bad()
	}
	for _, key := range []string{"parts", "redis_sources", "secret_allowlist", "source_writers"} {
		if _, exists := base.Registries[key]; exists {
			return bad()
		}
	}
	resource, err := execution.NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, native)
	if err != nil {
		return bad()
	}
	registries := make(map[string]sec.BootstrapResourceValidator, len(base.Registries)+4)
	for key, owner := range base.Registries {
		registries[key] = owner
	}
	for _, key := range []string{"parts", "redis_sources", "secret_allowlist", "source_writers"} {
		registries[key] = resource
	}
	base.Registries = registries
	return base, resource, nil
}

func originalSourceRegistryAliases(owners sec.BootstrapOwnerAdapters, resource *execution.BootstrapSourceRegistryTerminalResource) bool {
	if resource == nil {
		return false
	}
	for _, key := range []string{"parts", "redis_sources", "secret_allowlist", "source_writers"} {
		if owners.Registries[key] != resource {
			return false
		}
	}
	return true
}
