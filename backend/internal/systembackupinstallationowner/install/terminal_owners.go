package install

import (
	"strings"

	sec "clawreef/internal/systembackupsecurity"
)

func (a *BootstrapTerminalOriginal) MissingTerminalResources() []string {
	missing := []string{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		if key == "reference:capture_signing" && a != nil && a.capture != nil {
			continue
		}
		if a == nil || consumerNil(a.resources[key]) {
			missing = append(missing, key)
		}
	}
	return missing
}

// Owners exposes concrete adapters for the unchanged complete-owner inventory
// gate before credentials/providers/SQL. main must install the candidate factory
// with this terminal authority and preserve its independent real KEK source.
// Do not route these adapters through legacy config-order authorization: that
// route does not establish the reviewed capture -> MinIO current-SQL prefix.
func (a *BootstrapTerminalOriginal) Owners() (sec.BootstrapOwnerAdapters, error) {
	if a == nil || a.capture == nil {
		return sec.BootstrapOwnerAdapters{}, ErrInstall
	}
	owners := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{}, References: map[string]sec.BootstrapResourceValidator{"capture_signing": a.capture}}
	for key, source := range a.resources {
		switch {
		case strings.HasPrefix(key, "registry:"):
			owners.Registries[strings.TrimPrefix(key, "registry:")] = source
		case strings.HasPrefix(key, "reference:"):
			owners.References[strings.TrimPrefix(key, "reference:")] = source
		case key == "cross_resources":
			owners.CrossResources = source
		default:
			return sec.BootstrapOwnerAdapters{}, ErrInstall
		}
	}
	return owners, nil
}
