package systembackupexecution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

type OriginalSourceAPIRefreshInputs struct {
	Version         string
	SourceSelection install.BootstrapSourceFilePin
	Connection      install.BootstrapSourceConnection
	TokenNotAfter   time.Time
}
type OriginalSourceAPISuccessorReceipt struct {
	Version                                                         string
	ParentSelection, SourceSelection, MaterialsTemplate, Deployment install.BootstrapSourceFilePin
	NativeSourceQualified, GrantsIssued, BackupReady                bool
}

// The original materials rollout has already refreshed Controller to its real
// final Pod. Replace only the expired source-API transport with a new immutable
// token at the SAME endpoint/account/CA, before any source facts or grant exist.
func ProduceOriginalSourceAPISuccessor(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, in OriginalSourceAPIRefreshInputs, directory string) (OriginalSourceAPISuccessorReceipt, error) {
	var zero OriginalSourceAPISuccessorReceipt
	if installer == nil || ctx == nil || ctx.Err() != nil || in.Version != "original-source-api-successor-inputs.v1" || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	raw, err := pinnedDeploymentFile(in.SourceSelection.File, in.SourceSelection.SHA256, 262144)
	var selected install.BootstrapSourceAuthoringSelection
	if err != nil || strictBootstrapSourceJSON(raw, &selected) != nil || len(selected.Connections) != 5 || in.TokenNotAfter.IsZero() {
		return zero, install.ErrInstall
	}
	previous, next := selected.Connections[1], in.Connection
	if previous.Purpose != "source_api" || next.Purpose != previous.Purpose || next.Endpoint != previous.Endpoint || next.Account != previous.Account || next.CA != previous.CA ||
		next.ServerUUID != previous.ServerUUID || next.Database != previous.Database || next.ScopeSHA256 != "" || next.IdentitySHA256 != "" || next.Credential.File == previous.Credential.File {
		return zero, install.ErrInstall
	}
	if _, err = pinnedDeploymentFile(next.Credential.File, next.Credential.SHA256, 16384); err != nil {
		return zero, err
	}
	for _, path := range []string{selected.PartsFile, selected.SourceWritersFile, selected.RedisSourcesFile} {
		if path == "" {
			continue
		}
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return zero, install.ErrInstall
		}
	}
	raw, err = pinnedDeploymentFile(selected.MaterialsTemplate.File, selected.MaterialsTemplate.SHA256, 8<<20)
	var material productionCaptureMaterials
	if err != nil || strictBootstrapSourceJSON(raw, &material) != nil || material.Discovery == nil || material.CaptureGrantSHA256 != "" || material.Discovery.GrantSHA256 != "" || material.Redis.GrantSHA256 != "" || material.Objects.GrantSHA256 != "" || material.DeploymentConfigSHA256 != selected.Deployment.SHA256 {
		return zero, install.ErrInstall
	}
	if material.Discovery.SourceAPI.Server != previous.Endpoint || material.Discovery.SourceAPIServiceAccountUID != previous.Account || material.Discovery.SourceAPI.CAFile != previous.CA.File || material.Discovery.SourceAPI.CASHA256 != previous.CA.SHA256 || material.Discovery.SourceAPI.TokenFile != previous.Credential.File || material.Discovery.SourceAPITokenSHA256 != previous.Credential.SHA256 {
		return zero, install.ErrInstall
	}
	material.Discovery.SourceAPI.TokenFile = next.Credential.File
	material.Discovery.SourceAPITokenSHA256 = next.Credential.SHA256
	materialRaw, err := json.Marshal(material)
	if err != nil {
		return zero, err
	}
	materialPath := filepath.Join(directory, "final-source-api.materials-template.json")
	if writeBootstrapSourceFactFile(materialPath, materialRaw) != nil {
		return zero, install.ErrInstall
	}
	selected.MaterialsTemplate = install.BootstrapSourceFilePin{File: materialPath, SHA256: hash(materialRaw)}
	selected.Connections[1] = next
	if in.TokenNotAfter.Before(selected.Until) {
		selected.Until = in.TokenNotAfter
	}
	selectionRaw, err := ce.Canonical(selected)
	if err != nil {
		return zero, err
	}
	selectionPath := filepath.Join(directory, "final-source-api.selection.json")
	if writeBootstrapSourceFactFile(selectionPath, selectionRaw) != nil {
		return zero, install.ErrInstall
	}
	selectionPin := install.BootstrapSourceFilePin{File: selectionPath, SHA256: hash(selectionRaw)}
	authority, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionPin.File, selectionPin.SHA256)
	if err != nil {
		return zero, err
	}
	defer authority.Close()
	if _, err = newBootstrapSourceAuthoringReader(ctx, authority); err != nil {
		return zero, err
	}
	if authority.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	return OriginalSourceAPISuccessorReceipt{Version: "original-source-api-successor-authored.v1", ParentSelection: in.SourceSelection, SourceSelection: selectionPin, MaterialsTemplate: selected.MaterialsTemplate, Deployment: selected.Deployment}, nil
}
