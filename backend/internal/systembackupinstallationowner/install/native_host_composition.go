package install

import (
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// WithNativeHostSource upgrades ONLY the concrete original terminal returned
// by the installation composition. It accepts no generic Original/callback.
// The exact actual capture/nonce/CA/MinIO instances and grouped-source aliases
// are preserved; none is prepared, wrapped with its old material adapter, or
// replaced by source metadata. Constructors perform no I/O.
func (a *BootstrapTerminalOriginal) WithNativeHostSource(files BootstrapNativeHostFiles) (*NativeHostBootstrapTerminalOriginal, error) {
	if a == nil || a.capture == nil {
		return nil, ErrInstall
	}
	return NewNativeHostBootstrapTerminalOriginal(a.capture, a.files, a.resources, files)
}

// NativeHostDeploymentCandidates is the direct corrected D entry seam:
//
// owners, original := NewEnrolledTerminalInstallationMaterials(...)
// candidates, native := original.NativeHostDeploymentCandidates(selections, pins)
// owners.Candidates = candidates
//
// Keep the independently supplied owners.KEK. Do not put capture.CandidateAuthority
// or Materials around native: it already prepares every concrete resource and
// returns the existing six-stage terminal session with the real native host check.
func (a *BootstrapTerminalOriginal) NativeHostDeploymentCandidates(selections []pd.BootstrapCandidateSelection, files BootstrapNativeHostFiles) (*sec.BootstrapDeploymentCandidates, *NativeHostBootstrapTerminalOriginal, error) {
	native, err := a.WithNativeHostSource(files)
	if err != nil {
		return nil, nil, err
	}
	candidates, err := sec.NewBootstrapDeploymentCandidates(selections, native)
	if err != nil {
		return nil, nil, err
	}
	return candidates, native, nil
}
