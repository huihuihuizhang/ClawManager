package install

import (
	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Preferred D assembly seam. Both aliases retain ONE concrete owner pointer;
// every existing resource and the same primary enrolled capture are preserved.
// Construct before the native-host wrapper and candidate factory. No files,
// credentials, SQL or provider are opened, and remaining owners stay mandatory.
func (a *BootstrapTerminalOriginal) WithSigningResources(inputs []owner.SigningResourceInput) (*BootstrapTerminalOriginal, *owner.SigningResources, error) {
	if a == nil || a.capture == nil {
		return nil, nil, ErrInstall
	}
	for _, key := range []string{"reference:acceptance_signing", "reference:catalog_signing"} {
		if _, exists := a.resources[key]; exists {
			return nil, nil, ErrInstall
		}
	}
	signers, e := owner.NewSigningResources(inputs)
	if e != nil {
		return nil, nil, ErrInstall
	}
	resources := make(map[string]sec.BootstrapTerminalResource, len(a.resources)+2)
	for key, value := range a.resources {
		resources[key] = value
	}
	for _, key := range signers.TerminalKeys() {
		resources[key] = signers
	}
	terminal, e := NewBootstrapTerminalOriginal(a.capture, a.files, resources)
	if e != nil {
		return nil, nil, ErrInstall
	}
	return terminal, signers, nil
}
