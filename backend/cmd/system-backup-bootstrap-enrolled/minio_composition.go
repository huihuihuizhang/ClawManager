package main

import (
	"strings"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

// This preliminary gate excludes only the five concrete C owner slots which
// are constructed in the next branch. It never marks them linked or passed.
// The final full thirty-owner gate is mandatory after the actual constructor.
func missingBeforeOriginalMinIO(owners sec.BootstrapOwnerAdapters) []string {
	missing := []string{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(owners) {
		switch key {
		case "reference:artifact_delete", "reference:artifact_read", "reference:artifact_write", "reference:catalog_append", "reference:catalog_read":
			continue
		}
		missing = append(missing, key)
	}
	return missing
}

// Only the actual C concrete type can be linked here. Rebuild A's terminal
// map with the SAME existing owner pointers and one grouped five-key C pointer;
// no nonce/CA/capture/resource is constructed or prepared again.
func addOriginalMinIOTerminal(owners sec.BootstrapOwnerAdapters, capture *install.CaptureSigningConsumer, files install.BootstrapTerminalFiles, minio *execution.MinIOBootstrapTerminalResource) (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
		return sec.BootstrapOwnerAdapters{}, nil, sec.ErrRegistrationUnavailable
	}
	if minio == nil || capture == nil || owners.Candidates != nil || owners.References["capture_signing"] != capture {
		return bad()
	}
	resources := map[string]sec.BootstrapTerminalResource{}
	add := func(key string, validator sec.BootstrapResourceValidator) bool {
		resource, ok := validator.(sec.BootstrapTerminalResource)
		if !ok || resource == nil || resources[key] != nil {
			return false
		}
		resources[key] = resource
		return true
	}
	for key, validator := range owners.Registries {
		if !add("registry:"+key, validator) {
			return bad()
		}
	}
	for key, validator := range owners.References {
		if key != "capture_signing" && !add("reference:"+key, validator) {
			return bad()
		}
	}
	if owners.CrossResources != nil && !add("cross_resources", owners.CrossResources) {
		return bad()
	}
	for key, resource := range minio.TerminalResources() {
		if !add(key, resource) {
			return bad()
		}
	}
	original, err := install.NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		return bad()
	}
	linked, err := original.Owners()
	if err != nil {
		return bad()
	}
	linked.KEK = owners.KEK
	// Five exact aliases must come back from the actual terminal, not a map
	// manufactured by the preliminary missing-owner filter.
	for _, key := range minio.TerminalKeys() {
		if linked.References[strings.TrimPrefix(key, "reference:")] != minio {
			return bad()
		}
	}
	return linked, original, nil
}
