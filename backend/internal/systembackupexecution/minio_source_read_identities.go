package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes"
)

// RetainOriginalMinIOHistoryIdentities reobserves the fixed, already installed
// builtin accounts and captures their identity bytes. The native gate derives
// transport expiry from its own checked operation context when it uses them.
func RetainOriginalMinIOHistoryIdentities(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, kube kubernetes.Interface, setup, previousSource, provider, catalogDefinition install.BootstrapSourceFilePin, directory string, admin MinIONativeAdminFiles) (OriginalMinIOSourceSetupReceipt, error) {
	receipt := OriginalMinIOSourceSetupReceipt{Version: "original-minio-source-setup-receipt.v1", Stage: "original_builtin_history_identities", State: "failed"}
	if write == nil || read == nil || kube == nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil || nativeInstallEmptyDirectory(directory) != nil {
		return receipt, install.ErrInstall
	}
	readJSON := func(pin install.BootstrapSourceFilePin, out any) error {
		raw, e := pinnedDeploymentFile(pin.File, pin.SHA256, 262144)
		defer clear(raw)
		if e != nil || strictBootstrapSourceJSON(raw, out) != nil {
			return install.ErrInstall
		}
		return nil
	}
	var installed OriginalMinIOSourceSetupReceipt
	if readJSON(setup, &installed) != nil || installed.Version != receipt.Version || installed.State != "accounts_installed_not_held" {
		return receipt, install.ErrInstall
	}
	var mat OriginalMinIOSourceReadMaterials
	if readJSON(install.BootstrapSourceFilePin{File: installed.MaterialsFile, SHA256: installed.MaterialsSHA256}, &mat) != nil ||
		mat.Version != "original-minio-source-read-materials.v1" || installed.MaterialsFile != filepath.Join(mat.Native.CustodyDirectory, "source-read.materials.json") ||
		mat.ProviderDefinitionSHA256 != provider.SHA256 || mat.Native.MCFile != admin.MCFile || mat.Native.MCSHA256 != admin.MCSHA256 ||
		mat.Native.Operation != "" || mat.Native.InventorySHA256 != "" || len(mat.Native.OutputAccounts) != 0 || !time.Now().After(mat.Until) {
		return receipt, install.ErrInstall
	}
	var prior install.BootstrapSourceAuthoringSelection
	if readJSON(previousSource, &prior) != nil {
		return receipt, install.ErrInstall
	}
	old, e := json.Marshal(prior)
	if e != nil || hash(old) != mat.SourceSelectionSHA256 {
		return receipt, install.ErrInstall
	}
	current, target, e := read.Selection(ctx)
	newSource, encodeErr := json.Marshal(current)
	if e != nil || encodeErr != nil || current.Version != prior.Version || current.Controller != prior.Controller || current.ApplicationScope != prior.ApplicationScope ||
		current.ExecutionProfile.SHA256 != prior.ExecutionProfile.SHA256 || !reflect.DeepEqual(current.Connections, prior.Connections) ||
		target.Namespace != mat.Native.Namespace || target.NamespaceUID != mat.Native.NamespaceUID {
		return receipt, install.ErrInstall
	}
	var src OriginalMinIOSourceProviderInput
	if readJSON(provider, &src) != nil || src.Version != "original-minio-source-provider-input.v1" ||
		src.Installation != target.InstallationID || src.Namespace != target.Namespace || src.NamespaceUID != target.NamespaceUID {
		return receipt, install.ErrInstall
	}
	catalog, e := readMinIOPermissionProductionInputs(catalogDefinition.File, catalogDefinition.SHA256)
	if e != nil {
		return receipt, e
	}
	defer catalog.clear()
	if catalog.definition.Grant.Provider != src.Provider || catalog.grant.Installation != src.Installation ||
		catalog.grant.Namespace != src.Namespace || catalog.grant.NamespaceUID != src.NamespaceUID ||
		!install.ValidOriginalCatalogRoot(src.Installation, catalog.catalog.Root, catalog.definition.ConfigSHA256) ||
		mat.Native.DeploymentID != src.Provider.DeploymentID || mat.Native.CASHA256 != src.Provider.CASHA256 || mat.Native.Endpoint != src.Provider.Endpoint {
		return receipt, install.ErrInstall
	}
	if _, e = ObserveOriginalMinIOPermissions(ctx, kube, catalogDefinition.File, catalogDefinition.SHA256); e != nil {
		return receipt, e
	}
	native, e := nativeInstallAdmin(catalog.grant.Provider, ctx, admin)
	if e != nil {
		return receipt, e
	}
	defer native.close()
	names, e := collectOriginalWholeHistoryBuckets(ctx, native, mat.Native.BusinessBuckets)
	if e != nil || !reflect.DeepEqual(names, mat.Native.BusinessBuckets) {
		return receipt, install.ErrInstall
	}
	_, until, e := write.Identity(ctx)
	deadline, bounded := ctx.Deadline()
	now := time.Now().UTC()
	for _, limit := range []time.Time{deadline, current.Until, catalog.window.until} {
		if limit.Before(until) {
			until = limit
		}
	}
	if e != nil || !bounded || until.Sub(now) < 30*time.Second {
		return receipt, install.ErrInstall
	}
	previousUntil := mat.Until
	mat.Native.CustodyDirectory, mat.SourceSelectionSHA256, mat.Until = directory, hash(newSource), until
	identities := [3]sb.MinIOBuiltinIdentity{}
	pins := []*install.BootstrapSourceFilePin{&mat.RootCredential, &mat.KeeperCredential, &mat.ReaderCredential}
	for i, field := range pins {
		var credential sb.MinIOGateCredential
		if readJSON(*field, &credential) != nil || !credential.Until.Equal(previousUntil) {
			clear(credential.SecretKey)
			return receipt, install.ErrInstall
		}
		defer clear(credential.SecretKey)
		if i == 0 && (credential.AccessKey != native.credential.AccessKey || string(credential.SecretKey) != native.credential.SecretKey) {
			return receipt, install.ErrInstall
		}
		identities[i] = sb.MinIOBuiltinIdentity{Kind: "minio-builtin-static-identity.v1", AccessKey: credential.AccessKey, SecretKey: credential.SecretKey, Version: credential.Version}
		fresh, _, e := renewSourceReadCredential(*field, previousUntil, now, until, directory)
		if e != nil {
			return receipt, e
		}
		*field = fresh
	}
	check := func(current context.Context) error {
		if current != ctx {
			return install.ErrInstall
		}
		return write.CheckOriginalMinIOSourceSetup(ctx, read)
	}
	file, sha, e := nativeInstallSave(directory, "transport.observation.json", mat)
	if e != nil {
		return receipt, e
	}
	if e = sb.ObserveOriginalMinIOBuiltinIdentityMaterial(ctx, kube, file, sha, check); e != nil {
		var refused *sb.MinIOBuiltinObservationError
		if errors.As(e, &refused) {
			receipt.Stage = refused.Stage
		}
		return receipt, e
	}
	if check(ctx) != nil {
		return receipt, install.ErrInstall
	}
	mat.Version, mat.Until = "original-minio-source-read-identities.v2", time.Time{}
	for i, name := range []string{"root.identity.json", "keeper.identity.json", "reader.identity.json"} {
		file, sha, e := nativeInstallSave(directory, name, identities[i])
		if e != nil {
			return receipt, e
		}
		*pins[i] = install.BootstrapSourceFilePin{File: file, SHA256: sha}
	}
	file, sha, e = nativeInstallSave(directory, "source-read.identities.json", mat)
	if e != nil || sourceGateSyncDirectory(directory) != nil || check(ctx) != nil {
		return receipt, install.ErrInstall
	}
	receipt.MaterialsFile, receipt.MaterialsSHA256 = file, sha
	receipt.State = "original_builtin_accounts_reobserved_not_held"
	return receipt, nil
}
