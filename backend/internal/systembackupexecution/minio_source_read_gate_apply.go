package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"time"

	sb "clawreef/internal/systembackup"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes"
)

func sourceGatePolicySame(a, b []byte) bool {
	var x, y any
	if minioPermissionUniqueJSON(a) != nil || minioPermissionUniqueJSON(b) != nil || json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, e := ce.Canonical(x)
	if e != nil {
		return false
	}
	by, e := ce.Canonical(y)
	return e == nil && bytes.Equal(ax, by)
}

// Persist directory entries before native sends. File fsync alone does not
// make create-only intent/credential names survive a process or host crash.
func sourceGateSyncDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	se := f.Sync()
	ce := f.Close()
	if se != nil {
		return se
	}
	return ce
}

// Every send is journaled create-only first. If its reply was lost, a later
// caller can only query this SAME fixed target; absence remains UNKNOWN and
// never causes a second send or a newly generated credential/account.
func sourceGateSetupStep(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, dir, name string, intent any, observe func() (bool, bool, error), send func() error) (bool, error) {
	if write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return false, install.ErrInstall
	}
	path := filepath.Join(dir, "source-setup-"+name+".send-unknown.json")
	_, e := os.Lstat(path)
	pending := e == nil
	if e != nil && !os.IsNotExist(e) {
		return false, install.ErrInstall
	}
	want, e := ce.Canonical(intent)
	if e != nil {
		return false, e
	}
	if pending {
		old, e := install.ReadPrivateFile(path, 65536)
		if e != nil || !bytes.Equal(old, want) {
			return false, install.ErrInstall
		}
	}
	exists, matches, e := observe()
	if e != nil {
		return pending, e
	}
	if pending {
		if matches {
			return true, nil
		}
		return true, install.ErrCommitUnknown
	}
	if exists {
		return false, install.ErrInstall
	}
	if _, _, e = nativeInstallSaveRaw(dir, filepath.Base(path), want); e != nil {
		return false, e
	}
	if e = sourceGateSyncDirectory(dir); e != nil {
		return false, e
	}
	stored, e := install.ReadPrivateFile(path, 65536)
	if e != nil || !bytes.Equal(stored, want) || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return false, install.ErrInstall
	}
	_ = send()
	_, matches, e = observe()
	if e != nil || !matches {
		return true, install.ErrCommitUnknown
	}
	return true, nil
}

func applyOriginalMinIOSourceAccounts(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, mat OriginalMinIOSourceReadMaterials, admin MinIONativeAdminFiles, n *minioPermissionHTTP, receipt *OriginalMinIOSourceSetupReceipt) error {
	dir := mat.Native.CustodyDirectory
	for index, pin := range []install.BootstrapSourceFilePin{mat.KeeperCredential, mat.ReaderCredential} {
		raw, e := pinnedDeploymentFile(pin.File, pin.SHA256, 16384)
		if e != nil {
			return e
		}
		var c sb.MinIOGateCredential
		if strictBootstrapSourceJSON(raw, &c) != nil {
			return install.ErrInstall
		}
		clear(raw)
		defer clear(c.SecretKey)
		policy := mat.KeeperPolicy
		if index == 1 {
			policy = mat.ReaderPolicy
		}
		policyBody, e := pinnedDeploymentFile(policy.File, policy.SHA256, 16384)
		if e != nil {
			return e
		}
		name := c.AccessKey
		policyPath := "/minio/admin/v3/info-canned-policy"
		policyObserve := func() (bool, bool, error) {
			raw, status, e := n.get(ctx, policyPath, url.Values{"name": {name}, "v": {"2"}})
			if e != nil {
				return false, false, e
			}
			if nativeInstallMissing(raw, status, "XMinioAdminNoSuchPolicy", policyPath, n.provider.Region) {
				return false, false, nil
			}
			var p struct {
				PolicyName             string
				Policy                 json.RawMessage
				CreateDate, UpdateDate time.Time
			}
			if status != 200 || minioPermissionDecode(raw, &p) != nil || p.PolicyName != name {
				return true, false, install.ErrInstall
			}
			return true, sourceGatePolicySame(p.Policy, policyBody), nil
		}
		attempt, e := sourceGateSetupStep(ctx, write, read, dir, name+"-policy", policy, policyObserve, func() error {
			return nativeInstallMC(ctx, dir, n, admin, "admin", "policy", "create", "native", name, policy.File)
		})
		receipt.NativeWritesAttempted = receipt.NativeWritesAttempted || attempt
		if e != nil {
			return e
		}
		userObserve := func() (bool, bool, error) { present, e := sourceGateOwnUser(ctx, n, c); return present, present, e }
		attempt, e = sourceGateSetupStep(ctx, write, read, dir, name+"-user", pin, userObserve, func() error {
			input := append(append([]byte(name+"\n"), c.SecretKey...), '\n')
			defer clear(input)
			return nativeInstallMCInput(ctx, dir, n, admin, input, "admin", "user", "add", "native")
		})
		receipt.NativeWritesAttempted = receipt.NativeWritesAttempted || attempt
		if e != nil {
			return e
		}
		// An unbound exact newly created user is the original next-step state,
		// not an existing foreign account whose policy may be overwritten.
		attachmentObserve := func() (bool, bool, error) {
			raw, status, e := n.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {name}})
			if e != nil || status != 200 {
				return false, false, install.ErrInstall
			}
			var u struct{ PolicyName string }
			if minioPermissionUniqueJSON(raw) != nil || json.Unmarshal(raw, &u) != nil {
				return false, false, install.ErrInstall
			}
			if u.PolicyName == "" {
				return false, false, nil
			}
			return true, u.PolicyName == name, nil
		}
		attempt, e = sourceGateSetupStep(ctx, write, read, dir, name+"-attach", struct{ Account, Policy string }{name, name}, attachmentObserve, func() error {
			return nativeInstallMC(ctx, dir, n, admin, "admin", "policy", "attach", "native", name, "--user", name)
		})
		receipt.NativeWritesAttempted = receipt.NativeWritesAttempted || attempt
		if e != nil {
			return e
		}
	}
	return write.CheckOriginalMinIOSourceSetup(ctx, read)
}

// Concrete resume of C's ORIGINAL setup artifact. It never regenerates files,
// users or keys and never resends a pending native operation.
func ApplyOriginalMinIOSourceReadMaterials(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, kube kubernetes.Interface, materialsFile, materialsSHA, providerFile, providerSHA string, admin MinIONativeAdminFiles) (receipt OriginalMinIOSourceSetupReceipt, resultErr error) {
	receipt = OriginalMinIOSourceSetupReceipt{Version: "original-minio-source-setup-receipt.v1", Stage: "resume_original_materials", State: "failed", MaterialsFile: materialsFile, MaterialsSHA256: materialsSHA}
	if write == nil || read == nil || kube == nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return receipt, install.ErrInstall
	}
	raw, e := pinnedDeploymentFile(materialsFile, materialsSHA, 262144)
	var mat OriginalMinIOSourceReadMaterials
	if e != nil || strictBootstrapSourceJSON(raw, &mat) != nil || mat.Version != "original-minio-source-read-materials.v1" || mat.ProviderDefinitionSHA256 != providerSHA || filepath.Join(mat.Native.CustodyDirectory, "source-read.materials.json") != materialsFile || !time.Now().Before(mat.Until) {
		return receipt, install.ErrInstall
	}
	selection, target, e := read.Selection(ctx)
	if e != nil {
		return receipt, e
	}
	source, _ := json.Marshal(selection)
	if hash(source) != mat.SourceSelectionSHA256 || target.Namespace != mat.Native.Namespace || target.NamespaceUID != mat.Native.NamespaceUID {
		return receipt, install.ErrInstall
	}
	providerRaw, e := pinnedDeploymentFile(providerFile, providerSHA, 262144)
	var p OriginalMinIOSourceProviderInput
	if e != nil || strictBootstrapSourceJSON(providerRaw, &p) != nil || p.Version != "original-minio-source-provider-input.v1" || p.Installation != target.InstallationID || p.Namespace != target.Namespace || p.NamespaceUID != target.NamespaceUID {
		return receipt, install.ErrInstall
	}
	var provider minioPermissionProvider
	b, _ := json.Marshal(p.Provider)
	if json.Unmarshal(b, &provider) != nil || provider.Endpoint != mat.Native.Endpoint || provider.CASHA256 != mat.Native.CASHA256 || provider.DeploymentID != mat.Native.DeploymentID {
		return receipt, install.ErrInstall
	}
	cfg := minioPermissionConfiguration{Namespace: mat.Native.Namespace, NamespaceUID: mat.Native.NamespaceUID}
	first, e := minioPermissionKubernetes(ctx, kube, cfg, provider)
	if e != nil {
		return receipt, e
	}
	n, e := nativeInstallAdmin(provider, ctx, admin)
	if e != nil {
		return receipt, e
	}
	defer n.close()
	// Reuse the exact pinned executable selected by the original material.
	if admin.MCFile != mat.Native.MCFile || admin.MCSHA256 != mat.Native.MCSHA256 {
		return receipt, install.ErrInstall
	}
	st, e := os.Lstat(admin.MCFile)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 128<<20 {
		return receipt, install.ErrInstall
	}
	mc, e := os.ReadFile(admin.MCFile)
	if e != nil || hash(mc) != admin.MCSHA256 {
		return receipt, install.ErrInstall
	}
	clear(mc)
	if e = applyOriginalMinIOSourceAccounts(ctx, write, read, mat, admin, n, &receipt); e != nil {
		return receipt, e
	}
	last, e := minioPermissionKubernetes(ctx, kube, cfg, provider)
	if e != nil || last != first {
		return receipt, install.ErrInstall
	}
	receipt.State = "accounts_installed_not_held"
	return receipt, nil
}
