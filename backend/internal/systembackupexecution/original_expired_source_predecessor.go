package systembackupexecution

import (
	"path/filepath"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

// These pins preserve an expired unsigned observation, not retirement evidence.
// Renewal collects new facts in a separate directory; no old file is modified,
// and the authenticated Installer separately checks that no configuration or
// task has ever consumed source authority in this installation.
type OriginalExpiredSourcePredecessor struct {
	SourceSelection, FactsReceipt install.BootstrapSourceFilePin
}

func checkOriginalExpiredSourcePredecessor(in OriginalInitialSourceAuthorInputs, directory string, now time.Time) error {
	p := in.ExpiredPredecessor
	if p == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return install.ErrInstall
	}
	read := func(pin install.BootstrapSourceFilePin) ([]byte, error) {
		// The new output directory must not contain any retained input.
		if filepath.Dir(pin.File) == directory {
			return nil, install.ErrInstall
		}
		return pinnedDeploymentFile(pin.File, pin.SHA256, 8<<20)
	}
	raw, err := read(p.SourceSelection)
	var previous install.BootstrapSourceAuthoringSelection
	if err != nil || strictBootstrapSourceJSON(raw, &previous) != nil || previous.Version != install.BootstrapSourceAuthoringSelectionVersion || previous.NotBefore.IsZero() || !previous.NotBefore.Before(previous.Until) || now.Before(previous.Until) || in.NotBefore.Before(previous.Until) || previous.ApplicationScope != in.Deployment.ApplicationScope {
		return install.ErrInstall
	}
	a, b := previous.Controller, in.Controller
	if a.Namespace != b.Namespace || a.NamespaceUID != b.NamespaceUID || a.Deployment != b.Deployment || a.DeploymentUID != b.DeploymentUID || a.ServiceAccount != b.ServiceAccount || a.ServiceAccountUID != b.ServiceAccountUID {
		return install.ErrInstall
	}
	raw, err = read(previous.Deployment)
	var core DeploymentConfig
	if err != nil || strictBootstrapSourceJSON(raw, &core) != nil || core.InstallationID != in.Deployment.InstallationID || core.ApplicationScope != in.Deployment.ApplicationScope || core.ControllerOwner != in.Deployment.ControllerOwner {
		return install.ErrInstall
	}
	raw, err = read(p.FactsReceipt)
	var facts BootstrapSourceRegistryFactsReceipt
	if err != nil || strictBootstrapSourceJSON(raw, &facts) != nil || facts.Version != "original-source-registry-facts-receipt.v1" || facts.SelectionSHA256 != p.SourceSelection.SHA256 || facts.PartsRegistry.File != previous.PartsFile || facts.SourceWritersRegistry.File != previous.SourceWritersFile || previous.RedisSourcesFile == "" || facts.NativeRegistries == nil || facts.NativeRegistries.RedisSources.File != previous.RedisSourcesFile {
		return install.ErrInstall
	}
	// Keep the entire old successful receipt chain pinned, including the exact
	// policy. These bytes are not copied into the new selection or new facts.
	for _, pin := range []install.BootstrapSourceFilePin{previous.MaterialsTemplate, previous.ExecutionProfile, facts.PartsRegistry, facts.SourceWritersRegistry, facts.NativeRegistries.RedisSources, facts.NativeRegistries.SecretAllowlist} {
		if _, err = read(pin); err != nil {
			return install.ErrInstall
		}
	}
	return nil
}
