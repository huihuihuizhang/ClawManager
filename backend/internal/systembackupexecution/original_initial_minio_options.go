package systembackupexecution

import (
	"context"
	"path/filepath"
	"sort"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

type OriginalInitialMinIOOptionsReceipt struct {
	Version                                        string
	Options, NativeSetupReceipt, HistoryDefinition install.BootstrapSourceFilePin
	BackupReady                                    bool
}

// Author the operational options from the actual native account installer and
// the real original publication provider's pinned principal credentials. This
// is location data only; the later native material owner must still verify
// current source accounts. It never accepts a caller-selected output account list.
func ProduceOriginalInitialMinIOOptions(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, setup, history install.BootstrapSourceFilePin, directory string) (OriginalInitialMinIOOptionsReceipt, error) {
	var zero OriginalInitialMinIOOptionsReceipt
	if installer == nil || ctx == nil || ctx.Err() != nil || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	if installer.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, history.File, history.SHA256) != nil {
		return zero, install.ErrInstall
	}
	raw, err := pinnedDeploymentFile(setup.File, setup.SHA256, 262144)
	var receipt OriginalMinIOSourceSetupReceipt
	if err != nil || strictBootstrapSourceJSON(raw, &receipt) != nil || receipt.Version != "original-minio-source-setup-receipt.v1" || receipt.Stage != "native_installed_requires_gate_preflight" || receipt.State != "accounts_installed_not_held" || !receipt.NativeWritesAttempted {
		return zero, install.ErrInstall
	}
	materialPin := install.BootstrapSourceFilePin{File: receipt.MaterialsFile, SHA256: receipt.MaterialsSHA256}
	raw, err = pinnedDeploymentFile(materialPin.File, materialPin.SHA256, 262144)
	var material OriginalMinIOSourceReadMaterials
	if err != nil || strictBootstrapSourceJSON(raw, &material) != nil || material.Version != "original-minio-source-read-materials.v1" {
		return zero, install.ErrInstall
	}
	original, err := readMinIOPermissionProductionInputs(history.File, history.SHA256)
	if err != nil {
		return zero, err
	}
	defer original.clear()
	if material.Native.Endpoint != original.grant.Provider.Endpoint || material.Native.CASHA256 != original.grant.Provider.CASHA256 || material.Native.Namespace != original.definition.Grant.Namespace || material.Native.NamespaceUID != original.definition.Grant.NamespaceUID {
		return zero, install.ErrInstall
	}
	accounts := []string{}
	seen := map[string]bool{}
	for _, use := range original.uses {
		account := use.credential.AccessKey
		if account == "" {
			return zero, install.ErrInstall
		}
		if !seen[account] {
			accounts = append(accounts, account)
			seen[account] = true
		}
	}
	if len(accounts) == 0 {
		return zero, install.ErrInstall
	}
	sort.Strings(accounts)
	options := FormalMinIOMaterialDeliveryOptions{Version: "formal-minio-material-delivery-input.v1", Materials: materialPin, HistoryDefinition: history, OutputAccounts: accounts}
	raw, err = ce.Canonical(options)
	if err != nil {
		return zero, err
	}
	file, digest, err := nativeInstallSaveRaw(directory, "initial-minio-options.json", raw)
	if err != nil {
		return zero, err
	}
	if installer.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, history.File, history.SHA256) != nil {
		return zero, install.ErrInstall
	}
	if _, err = pinnedDeploymentFile(materialPin.File, materialPin.SHA256, 262144); err != nil {
		return zero, err
	}
	if filepath.Base(file) != "initial-minio-options.json" {
		return zero, install.ErrInstall
	}
	return OriginalInitialMinIOOptionsReceipt{Version: "original-initial-minio-options-authored.v1", Options: install.BootstrapSourceFilePin{File: file, SHA256: digest}, NativeSetupReceipt: setup, HistoryDefinition: history}, nil
}
