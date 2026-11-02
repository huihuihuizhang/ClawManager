package systembackupbootstrapmaterials

import (
	ca "clawreef/internal/systembackupcatrust"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	sec "clawreef/internal/systembackupsecurity"
)

// NewEnrolledInstallationMaterials is the D main composition entry for the
// authenticated export/consumer source. Construction does no source/credential
// reads or provider/SQL work. All original mapping authority, concrete nonce/CA
// bindings and remaining owners are still mandatory; no DTO supplies code.
func NewEnrolledInstallationMaterials(base sec.BootstrapOwnerAdapters, original sec.BootstrapCandidateAuthority, capture *install.CaptureSigningConsumer, n nonce.Binding, artifact, evidence ca.Binding) (sec.BootstrapOwnerAdapters, *Materials, error) {
	if capture == nil {
		return sec.BootstrapOwnerAdapters{}, nil, sec.ErrRegistrationUnavailable
	}
	joined, e := capture.CandidateAuthority(original)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, nil, e
	}
	withCapture, e := capture.Owners(base)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, nil, e
	}
	materials, e := New(joined, n, artifact, evidence)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, nil, e
	}
	owners, e := materials.Owners(withCapture)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, nil, e
	}
	owners.KEK = withCapture.KEK
	return owners, materials, nil
}
