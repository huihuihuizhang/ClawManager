package systembackupbootstrapmaterials

import (
	ca "clawreef/internal/systembackupcatrust"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	sec "clawreef/internal/systembackupsecurity"
)

// NewEnrolledTerminalInstallationOwners assembles A's actual terminal
// authority; it has no arbitrary Original callback argument. The SAME concrete
// nonce/CA instances belong to terminal resources and the returned owner maps.
// Constructors perform no file, credential, provider, Kubernetes or SQL I/O.
// Missing owners remain absent: Terminal Prepare and the deployment gate reject
// them. Pass ONLY the returned terminal to NewBootstrapDeploymentCandidates.
// No Materials or capture-candidate wrapper is constructed or returned.
func NewEnrolledTerminalInstallationOwners(base sec.BootstrapOwnerAdapters, capture *install.CaptureSigningConsumer, files install.BootstrapTerminalFiles, n nonce.Binding, artifact, evidence ca.Binding) (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *install.BootstrapTerminalOriginal, error) {
		return sec.BootstrapOwnerAdapters{}, nil, sec.ErrRegistrationUnavailable
	}
	if capture == nil || base.Candidates != nil || artifact.Purpose != "artifact_ca" || evidence.Purpose != "evidence_ca" {
		return bad()
	}
	for _, binding := range []ca.Binding{artifact, evidence} {
		if binding.InstallationID != n.InstallationID || binding.ServerUUID != n.ServerUUID || binding.Database != n.Database || binding.ConfigSHA256 != n.ConfigSHA256 {
			return bad()
		}
	}
	nv, err := nonce.New(n)
	if err != nil {
		return bad()
	}
	av, err := ca.New(artifact)
	if err != nil {
		return bad()
	}
	ev, err := ca.New(evidence)
	if err != nil {
		return bad()
	}
	resources := map[string]sec.BootstrapTerminalResource{}
	add := func(key string, validator sec.BootstrapResourceValidator) bool {
		if nilBoundary(validator) {
			return false
		}
		resource, ok := validator.(sec.BootstrapTerminalResource)
		if !ok || nilBoundary(resource) || resources[key] != nil {
			return false
		}
		resources[key] = resource
		return true
	}
	for key, validator := range base.Registries {
		if !add("registry:"+key, validator) {
			return bad()
		}
	}
	for key, validator := range base.References {
		if !add("reference:"+key, validator) {
			return bad()
		}
	}
	if !nilBoundary(base.CrossResources) && !add("cross_resources", base.CrossResources) {
		return bad()
	}
	for key, validator := range map[string]sec.BootstrapResourceValidator{"reference:nonce_hmac": nv, "reference:artifact_ca": av, "reference:evidence_ca": ev} {
		if !add(key, validator) {
			return bad()
		}
	}
	original, err := install.NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		return bad()
	}
	owners, err := original.Owners()
	if err != nil {
		return bad()
	}
	owners.KEK = base.KEK
	return owners, original, nil
}
