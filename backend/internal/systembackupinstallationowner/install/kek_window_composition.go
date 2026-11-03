package install

import (
	kek "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
)

// Preserve every actual resource and the same enrolled capture. Root must put
// the returned SINGLE object into both owners.References["kek"] and owners.KEK.
// Omitting the independent KEK call cannot enable a fresh attempt: the private
// terminal check refuses before that exact attempt's preparation has completed.
func (a *BootstrapTerminalOriginal) WithOriginalWindowKEK(preparation *kek.SQLBootstrapKEKPreparation, files BootstrapKEKWindowFiles) (*BootstrapTerminalOriginal, *OriginalWindowKEK, error) {
	if a == nil || a.capture == nil {
		return nil, nil, ErrInstall
	}
	if _, exists := a.resources["reference:kek"]; exists {
		return nil, nil, ErrInstall
	}
	owner, err := NewOriginalWindowKEK(a.capture, preparation, files)
	if err != nil {
		return nil, nil, err
	}
	resources := make(map[string]sec.BootstrapTerminalResource, len(a.resources)+1)
	for key, value := range a.resources {
		resources[key] = value
	}
	resources["reference:kek"] = owner
	terminal, err := NewBootstrapTerminalOriginal(a.capture, a.files, resources)
	if err != nil {
		return nil, nil, err
	}
	return terminal, owner, nil
}
