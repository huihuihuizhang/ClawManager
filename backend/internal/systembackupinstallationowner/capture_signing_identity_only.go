package systembackupinstallationowner

import (
	"bytes"
	"path/filepath"

	sec "clawreef/internal/systembackupsecurity"
)

// NewCaptureSigningIdentityOnlyValidator retains independently deployed
// original signed source checks when physical provider trust material cannot
// be loaded. It has NO observer and can never authorize fresh consumption:
// Prepare records no observation, DependencyDeadline is nil and Recheck fails.
// Existing current admin/head/grant/account/window checks remain mandatory.
func NewCaptureSigningIdentityOnlyValidator(pin TrustPin, files RecordFiles) (*CaptureSigningValidator, error) {
	if !pin.valid() || files.RecordFile == files.SignatureFile {
		return nil, ErrOwner
	}
	for _, path := range []string{files.RecordFile, files.SignatureFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrOwner
		}
	}
	pin.Issuer = bytes.Clone(pin.Issuer)
	return &CaptureSigningValidator{pin: pin, files: files}, nil
}

// IdentityOnlyCandidateAuthority explicitly preserves the original checks
// while supplying no usable new-use dependency and no placeholder observer.
func (v *CaptureSigningValidator) IdentityOnlyCandidateAuthority(original sec.BootstrapCandidateAuthority) (*CaptureSigningCandidateAuthority, error) {
	if nilInterface(original) || v == nil || !v.pin.valid() || v.observer != nil {
		return nil, ErrOwner
	}
	if _, e := NewCaptureSigningIdentityOnlyValidator(v.pin, v.files); e != nil {
		return nil, e
	}
	return &CaptureSigningCandidateAuthority{original: original, capture: v}, nil
}
