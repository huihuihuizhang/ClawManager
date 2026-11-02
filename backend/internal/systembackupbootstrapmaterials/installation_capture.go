package systembackupbootstrapmaterials

import (
	"context"

	ca "clawreef/internal/systembackupcatrust"
	owner "clawreef/internal/systembackupinstallationowner"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// InstallationMaterials composes exactly four concrete resources with the
// independently mandatory original authority. It is not a replacement for
// original provider/host/evidence mapping or the remaining owner requirements.
type InstallationMaterials struct {
	materials *Materials
	capture   *owner.CaptureSigningCandidateAuthority
}

func NewInstallationMaterials(original sec.BootstrapCandidateAuthority, capture *owner.CaptureSigningValidator, n nonce.Binding, artifact, evidence ca.Binding) (*InstallationMaterials, error) {
	joined, e := owner.NewCaptureSigningCandidateAuthority(original, capture)
	if e != nil {
		return nil, e
	}
	materials, e := New(joined, n, artifact, evidence)
	if e != nil {
		return nil, e
	}
	return &InstallationMaterials{materials: materials, capture: joined}, nil
}
func (*InstallationMaterials) String() string   { return "InstallationBootstrapMaterials" }
func (*InstallationMaterials) GoString() string { return "InstallationBootstrapMaterials" }
func (*InstallationMaterials) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (m *InstallationMaterials) Owners(base sec.BootstrapOwnerAdapters) (sec.BootstrapOwnerAdapters, error) {
	if m == nil || m.materials == nil || m.capture == nil {
		return sec.BootstrapOwnerAdapters{}, sec.ErrRegistrationUnavailable
	}
	withCapture, e := m.capture.Owners(base)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, e
	}
	owners, e := m.materials.Owners(withCapture)
	if e != nil {
		return sec.BootstrapOwnerAdapters{}, e
	}
	owners.KEK = withCapture.KEK
	return owners, nil
}
func (m *InstallationMaterials) PrepareBootstrapCandidates(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	if m == nil || m.materials == nil || m.capture == nil {
		return sec.PreparedBootstrapCandidateAuthority{}, sec.ErrRegistrationUnavailable
	}
	return m.materials.PrepareBootstrapCandidates(ctx, grant, config, request)
}

var _ sec.BootstrapCandidateAuthority = (*InstallationMaterials)(nil)
