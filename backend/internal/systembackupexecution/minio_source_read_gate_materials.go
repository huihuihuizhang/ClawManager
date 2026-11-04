package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	"k8s.io/client-go/kubernetes"
)

// Independent source transport/actor inputs. They are checked against the
// genuine source authoring connection, actual Kube chain and authenticated
// native server; no final backup config/permission grant is a prerequisite.
type OriginalMinIOSourceProviderInput struct {
	Version, Installation, Namespace, NamespaceUID string
	Provider                                       install.MinIOPermissionProvider
}

type OriginalMinIOSourceReadMaterials struct {
	Version, SourceSelectionSHA256, ProviderDefinitionSHA256                                string
	Native                                                                                  sb.MinIOReadGateInput
	RootCredential, KeeperCredential, ReaderCredential, CaptureReaderCredential, CustodyKey install.BootstrapSourceFilePin
	KeeperPolicy, ReaderPolicy                                                              install.BootstrapSourceFilePin
	Until                                                                                   time.Time
}
type OriginalMinIOSourceSetupReceipt struct {
	Version, Stage, State, MaterialsFile, MaterialsSHA256 string
	NativeWritesAttempted                                 bool
}

// Concrete PRE-config source producer: derives source buckets/TLS/native
// coordinates from D's genuine original authoring reader, not an arbitrary
// bucket DTO. Mutations additionally require the actual maintenance owner.
// All mc operations reuse C's one pinned native installer command channel.
func ProduceOriginalMinIOSourceReadMaterials(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, kube kubernetes.Interface, providerFile, providerSHA, directory string, admin MinIONativeAdminFiles) (receipt OriginalMinIOSourceSetupReceipt, resultErr error) {
	receipt = OriginalMinIOSourceSetupReceipt{Version: "original-minio-source-setup-receipt.v1", Stage: "source_authority", State: "failed"}
	// kube is obtained from the already authenticated reader's actual client,
	// below; no replacement transport/source-observer callback is accepted.
	if write == nil || read == nil || kube == nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil || nativeInstallEmptyDirectory(directory) != nil {
		return receipt, install.ErrInstall
	}
	x, e := newBootstrapSourceAuthoringReader(ctx, read)
	if e != nil {
		return receipt, e
	}
	selection, target, e := read.Selection(ctx)
	if e != nil {
		return receipt, e
	}
	raw, e := read.Read(ctx, selection.MaterialsTemplate)
	if e != nil {
		return receipt, e
	}
	defer clear(raw)
	// The existing reader has checked the exact original source templates and
	// scopes. Run its actual finite SQL/API/native collection, not just parsing.
	if _, e = x.collectBootstrapSourceFacts(); e != nil {
		return receipt, e
	}
	var conn install.BootstrapSourceConnection
	for _, c := range selection.Connections {
		if c.Purpose == "source_objects" {
			conn = c
		}
	}
	if conn.Purpose == "" || x.materials.Objects.Objects == nil {
		return receipt, install.ErrInstall
	}
	mapping := x.materials.Objects.Objects
	if conn.Endpoint != "https://"+mapping.Address || conn.CA.File != mapping.CAFile || conn.CA.SHA256 != mapping.CASHA256 {
		return receipt, install.ErrInstall
	}
	buckets := map[string]bool{}
	if x.materials.SkillBucket != "" {
		buckets[x.materials.SkillBucket] = true
	}
	for _, p := range x.materials.Objects.ObjectPrefixes {
		buckets[p.Bucket] = true
	}
	names := []string{}
	for b := range buckets {
		if b == "" {
			return receipt, install.ErrInstall
		}
		names = append(names, b)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return receipt, install.ErrInstall
	}
	definitionRaw, e := pinnedDeploymentFile(providerFile, providerSHA, 262144)
	if e != nil {
		return receipt, e
	}
	var d OriginalMinIOSourceProviderInput
	if strictBootstrapSourceJSON(definitionRaw, &d) != nil || d.Version != "original-minio-source-provider-input.v1" || d.Namespace != target.Namespace || d.NamespaceUID != target.NamespaceUID || d.Installation != target.InstallationID || d.Provider.Endpoint != conn.Endpoint || d.Provider.CASHA256 != conn.CA.SHA256 {
		return receipt, install.ErrInstall
	}
	var provider minioPermissionProvider
	b, _ := json.Marshal(d.Provider)
	if json.Unmarshal(b, &provider) != nil {
		return receipt, install.ErrInstall
	}
	cfg := minioPermissionConfiguration{Namespace: d.Namespace, NamespaceUID: d.NamespaceUID}
	firstKube, e := minioPermissionKubernetes(ctx, kube, cfg, provider)
	if e != nil {
		return receipt, e
	}
	n, e := nativeInstallAdmin(provider, ctx, admin)
	if e != nil {
		return receipt, e
	}
	defer n.close()
	if _, e = n.collectNativeInstallServer(ctx, ma.SeptemberPermissionProfile); e != nil {
		return receipt, e
	}
	mcBytes, e := os.ReadFile(admin.MCFile)
	if e == nil && (len(mcBytes) > 128<<20 || hash(mcBytes) != admin.MCSHA256) {
		e = install.ErrInstall
	}
	clear(mcBytes)
	if e != nil {
		return receipt, e
	}
	st, e := os.Lstat(admin.MCFile)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return receipt, install.ErrInstall
	}
	version := nativeInstallVersionBuffer{}
	command := exec.CommandContext(ctx, admin.MCFile, "--version")
	command.Stdout = &version
	command.Stderr = io.Discard
	if command.Run() != nil || !bytes.Contains(version.Bytes(), []byte("mc version "+minioInstallMCRelease+" ")) {
		return receipt, install.ErrInstall
	}
	until := selection.Until
	if deadline, ok := ctx.Deadline(); !ok {
		return receipt, install.ErrInstall
	} else if deadline.Before(until) {
		until = deadline
	}
	_, writerUntil, e := write.Identity(ctx)
	if e != nil {
		return receipt, e
	}
	if writerUntil.Before(until) {
		until = writerUntil
	}
	start := time.Now().UTC()
	if !start.Before(until) {
		return receipt, install.ErrInstall
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return receipt, e
	}
	suffix := hex.EncodeToString(id[:])
	keeperPolicy, readerPolicy, e := sb.MinIOReadGatePolicies(names)
	if e != nil {
		return receipt, e
	}
	keeperName, readerName := "sbk_source_keeper_"+suffix, "sbk_source_reader_"+suffix
	makeCredential := func(account string) (sb.MinIOGateCredential, error) {
		var secret [32]byte
		if _, e := rand.Read(secret[:]); e != nil {
			return sb.MinIOGateCredential{}, e
		}
		return sb.MinIOGateCredential{AccessKey: account, SecretKey: []byte(hex.EncodeToString(secret[:])), Version: "source-" + suffix, NotBefore: start.Add(-time.Second), Until: until}, nil
	}
	kc, e := makeCredential(keeperName)
	if e != nil {
		return receipt, e
	}
	defer clear(kc.SecretKey)
	rc, e := makeCredential(readerName)
	if e != nil {
		return receipt, e
	}
	defer clear(rc.SecretKey)
	rootUser, e := install.ReadPrivateFile(admin.UserFile, 1024)
	if e != nil {
		return receipt, e
	}
	defer clear(rootUser)
	rootSecret, e := install.ReadPrivateFile(admin.PasswordFile, 4096)
	if e != nil {
		return receipt, e
	}
	defer clear(rootSecret)
	rootCred := sb.MinIOGateCredential{AccessKey: string(rootUser), SecretKey: rootSecret, Version: "original-" + hash(append(append([]byte(nil), rootUser...), rootSecret...)), NotBefore: start.Add(-time.Second), Until: until}
	selectionRaw, _ := json.Marshal(selection)
	mat := OriginalMinIOSourceReadMaterials{Version: "original-minio-source-read-materials.v1", SourceSelectionSHA256: hash(selectionRaw), ProviderDefinitionSHA256: providerSHA, Until: until}
	save := func(name string, value any) (install.BootstrapSourceFilePin, error) {
		file, sha, e := nativeInstallSave(directory, name, value)
		return install.BootstrapSourceFilePin{File: file, SHA256: sha}, e
	}
	if mat.RootCredential, e = save("root.json", rootCred); e != nil {
		return receipt, e
	}
	if mat.KeeperCredential, e = save("keeper.json", kc); e != nil {
		return receipt, e
	}
	if mat.ReaderCredential, e = save("reader.json", rc); e != nil {
		return receipt, e
	}
	if mat.CaptureReaderCredential, e = save("source-reader.json", metadataSourceCredential{AccessKey: rc.AccessKey, SecretKey: rc.SecretKey}); e != nil {
		return receipt, e
	}
	key := make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		return receipt, e
	}
	defer clear(key)
	file, sha, e := nativeInstallSaveRaw(directory, "custody.key", key)
	if e != nil {
		return receipt, e
	}
	mat.CustodyKey = install.BootstrapSourceFilePin{File: file, SHA256: sha}
	file, sha, e = nativeInstallSaveRaw(directory, "keeper-policy.json", keeperPolicy)
	if e != nil {
		return receipt, e
	}
	mat.KeeperPolicy = install.BootstrapSourceFilePin{File: file, SHA256: sha}
	file, sha, e = nativeInstallSaveRaw(directory, "reader-policy.json", readerPolicy)
	if e != nil {
		return receipt, e
	}
	mat.ReaderPolicy = install.BootstrapSourceFilePin{File: file, SHA256: sha}
	u, _ := url.Parse(provider.Endpoint)
	if u.Hostname() != mapping.ServerName {
		return receipt, install.ErrInstall
	}
	mat.Native = sb.MinIOReadGateInput{Namespace: d.Namespace, NamespaceUID: d.NamespaceUID, Pod: provider.Pod.Name, PodUID: provider.Pod.UID, Container: provider.Container, ImageID: provider.ImageID, Endpoint: provider.Endpoint, ServerName: mapping.ServerName, Region: provider.Region, CAFile: conn.CA.File, CASHA256: conn.CA.SHA256, SPKISHA256: provider.SPKISHA256, DeploymentID: provider.DeploymentID, BusinessBuckets: names, CustodyDirectory: directory, MCFile: admin.MCFile, MCSHA256: admin.MCSHA256}
	// Persist the complete fixed credentials/policies BEFORE native sends. A
	// partial failure retains these exact files; no retry generates new users.
	receipt.MaterialsFile, receipt.MaterialsSHA256, e = nativeInstallSave(directory, "source-read.materials.json", mat)
	if e != nil {
		return receipt, e
	}
	if e = os.Mkdir(filepath.Join(directory, "mc"), 0700); e != nil {
		return receipt, e
	}
	if e = os.Mkdir(filepath.Join(directory, "mc", "certs"), 0700); e != nil {
		return receipt, e
	}
	if e = os.Mkdir(filepath.Join(directory, "mc", "certs", "CAs"), 0700); e != nil {
		return receipt, e
	}
	ca, e := pinnedDeploymentFile(provider.CAFile, provider.CASHA256, 65536)
	if e != nil {
		return receipt, e
	}
	if _, _, e = nativeInstallSaveRaw(directory, "mc/certs/CAs/original-ca.crt", ca); e != nil {
		return receipt, e
	}
	for _, dir := range []string{filepath.Join(directory, "mc", "certs", "CAs"), filepath.Join(directory, "mc", "certs"), filepath.Join(directory, "mc"), directory} {
		if e = sourceGateSyncDirectory(dir); e != nil {
			return receipt, e
		}
	}
	if e = applyOriginalMinIOSourceAccounts(ctx, write, read, mat, admin, n, &receipt); e != nil {
		return receipt, e
	}
	lastKube, e := minioPermissionKubernetes(ctx, kube, cfg, provider)
	if e != nil || lastKube != firstKube || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return receipt, install.ErrInstall
	}
	receipt.Stage = "native_installed_requires_gate_preflight"
	receipt.State = "accounts_installed_not_held"
	return receipt, nil
}
