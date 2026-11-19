package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	sb "clawreef/internal/systembackup"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ContinueOriginalMinIOWholeHistoryKeeperPolicy carries forward a journal
// whose sole native send was the keeper policy. It durably retains that
// journal, and only unsent user credentials receive a fresh validity window.
func ContinueOriginalMinIOWholeHistoryKeeperPolicy(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, kube kubernetes.Interface, previous, previousSource, providerPin, catalogDefinition install.BootstrapSourceFilePin, directory string, admin MinIONativeAdminFiles) (OriginalMinIOSourceSetupReceipt, error) {
	receipt := OriginalMinIOSourceSetupReceipt{Version: "original-minio-source-setup-receipt.v1", Stage: "original_keeper_policy_recovery", State: "failed"}
	if write == nil || read == nil || kube == nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil || nativeInstallEmptyDirectory(directory) != nil {
		return receipt, install.ErrInstall
	}
	raw, e := pinnedDeploymentFile(previous.File, previous.SHA256, 262144)
	var m OriginalMinIOSourceReadMaterials
	if e != nil || strictBootstrapSourceJSON(raw, &m) != nil || m.Version != "original-minio-source-read-materials.v1" ||
		m.ProviderDefinitionSHA256 != providerPin.SHA256 || previous.File != filepath.Join(m.Native.CustodyDirectory, "source-read.materials.json") ||
		m.Native.MCFile != admin.MCFile || m.Native.MCSHA256 != admin.MCSHA256 || m.KeeperPolicyName != "" || !time.Now().After(m.Until) {
		return receipt, install.ErrInstall
	}
	selection, target, e := read.Selection(ctx)
	if e != nil {
		return receipt, e
	}
	selectionRaw, _ := json.Marshal(selection)
	var renewedAPI *install.BootstrapSourceConnection
	if selected := hash(selectionRaw); selected != m.SourceSelectionSHA256 {
		priorRaw, e := pinnedDeploymentFile(previousSource.File, previousSource.SHA256, 262144)
		var prior install.BootstrapSourceAuthoringSelection
		if e != nil || strictBootstrapSourceJSON(priorRaw, &prior) != nil {
			return receipt, install.ErrInstall
		}
		canonicalPrior, e := json.Marshal(prior)
		if e != nil || hash(canonicalPrior) != m.SourceSelectionSHA256 || prior.Version != selection.Version || prior.Controller != selection.Controller ||
			prior.ApplicationScope != selection.ApplicationScope || !time.Now().After(prior.Until) ||
			len(prior.Connections) != len(selection.Connections) {
			return receipt, install.ErrInstall
		}
		for i, old := range prior.Connections {
			next := selection.Connections[i]
			if old == next {
				continue
			}
			if renewedAPI != nil || old.Purpose != "source_api" || old.Credential.File == next.Credential.File ||
				old.Credential.SHA256 == next.Credential.SHA256 {
				return receipt, install.ErrInstall
			}
			old.Credential = next.Credential
			if old != next {
				return receipt, install.ErrInstall
			}
			renewedAPI = &selection.Connections[i]
		}
		m.SourceSelectionSHA256 = selected
	}
	sourceReader, e := newBootstrapSourceAuthoringReader(ctx, read)
	if e != nil {
		return receipt, e
	}
	if renewedAPI != nil {
		token, e := read.Read(ctx, renewedAPI.Credential)
		if e != nil {
			return receipt, e
		}
		defer clear(token)
		review, e := kube.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
			Spec: authnv1.TokenReviewSpec{Token: string(token)},
		}, metav1.CreateOptions{})
		if e != nil || review == nil || !review.Status.Authenticated || review.Status.Error != "" ||
			review.Status.User.UID != renewedAPI.Account ||
			review.Status.User.Username != "system:serviceaccount:"+target.Namespace+":"+sourceReader.materials.Discovery.SourceAPIServiceAccount {
			return receipt, install.ErrInstall
		}
	}
	if _, e = sourceReader.collectBootstrapSourceFacts(); e != nil {
		return receipt, e
	}
	raw, e = pinnedDeploymentFile(providerPin.File, providerPin.SHA256, 262144)
	var src OriginalMinIOSourceProviderInput
	if e != nil || strictBootstrapSourceJSON(raw, &src) != nil || src.Version != "original-minio-source-provider-input.v1" ||
		src.Installation != target.InstallationID || src.Namespace != target.Namespace || src.NamespaceUID != target.NamespaceUID ||
		m.Native.Namespace != target.Namespace || m.Native.NamespaceUID != target.NamespaceUID || m.Native.Endpoint != src.Provider.Endpoint ||
		m.Native.DeploymentID != src.Provider.DeploymentID || m.Native.ImageID != src.Provider.ImageID || m.Native.CASHA256 != src.Provider.CASHA256 {
		return receipt, install.ErrInstall
	}
	encoded, _ := json.Marshal(src.Provider)
	var provider minioPermissionProvider
	if json.Unmarshal(encoded, &provider) != nil {
		return receipt, install.ErrInstall
	}
	cfg := minioPermissionConfiguration{Namespace: src.Namespace, NamespaceUID: src.NamespaceUID}
	if _, e = minioPermissionKubernetes(ctx, kube, cfg, provider); e != nil {
		return receipt, e
	}
	native, e := nativeInstallAdmin(provider, ctx, admin)
	if e != nil {
		return receipt, e
	}
	defer native.close()
	profile := ma.SeptemberPermissionProfile
	if ma.MatchesDeleteCompatImageID(provider.ImageID) {
		profile = ma.DeleteCompatPermissionProfile
	}
	if _, e = native.collectNativeInstallServer(ctx, profile); e != nil {
		return receipt, e
	}
	names, e := collectOriginalWholeHistoryBuckets(ctx, native, m.Native.BusinessBuckets)
	if e != nil {
		return receipt, install.ErrInstall
	}
	scopeChanged := !reflect.DeepEqual(names, m.Native.BusinessBuckets)
	if scopeChanged {
		catalog, e := readMinIOPermissionProductionInputs(catalogDefinition.File, catalogDefinition.SHA256)
		if e != nil {
			return receipt, e
		}
		defer catalog.clear()
		if catalog.definition.Grant.Provider != src.Provider || catalog.grant.Installation != src.Installation ||
			catalog.grant.Namespace != src.Namespace || catalog.grant.NamespaceUID != src.NamespaceUID ||
			catalog.catalog.Root != src.Installation+"/catalog/" || len(names) != len(m.Native.BusinessBuckets)+1 {
			return receipt, install.ErrInstall
		}
		originalNames := make([]string, 0, len(names)-1)
		for _, name := range names {
			if name != catalog.catalog.Bucket {
				originalNames = append(originalNames, name)
			}
		}
		if !reflect.DeepEqual(originalNames, m.Native.BusinessBuckets) {
			return receipt, install.ErrInstall
		}
		if _, e = ObserveOriginalMinIOPermissions(ctx, kube, catalogDefinition.File, catalogDefinition.SHA256); e != nil {
			return receipt, e
		}
	} else if catalogDefinition != (install.BootstrapSourceFilePin{}) {
		return receipt, install.ErrInstall
	}
	deadline, hasDeadline := ctx.Deadline()
	_, ownerUntil, e := write.Identity(ctx)
	if e != nil || !hasDeadline {
		return receipt, install.ErrInstall
	}
	until := time.Now().UTC().Add(8 * time.Minute)
	for _, bound := range []time.Time{deadline, ownerUntil, selection.Until} {
		if bound.Before(until) {
			until = bound
		}
	}
	now := time.Now().UTC()
	if !now.Before(until) {
		return receipt, install.ErrInstall
	}
	var accounts [3]string
	for index, field := range []*install.BootstrapSourceFilePin{&m.RootCredential, &m.KeeperCredential, &m.ReaderCredential} {
		pin, account, e := renewSourceReadCredential(*field, m.Until, now, until, directory)
		if e != nil {
			return receipt, e
		}
		*field, accounts[index] = pin, account
	}
	if accounts[0] != native.credential.AccessKey || accounts[1] == accounts[2] || accounts[1] == accounts[0] || accounts[2] == accounts[0] ||
		!strings.HasPrefix(accounts[1], "sbk_source_keeper_") || !strings.HasPrefix(accounts[2], "sbk_source_reader_") {
		return receipt, install.ErrInstall
	}
	old := m.Native.CustodyDirectory
	journal := "source-setup-" + accounts[1] + "-policy.send-unknown.json"
	entries, e := os.ReadDir(old)
	if e != nil {
		return receipt, e
	}
	fixed := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "source-setup-") {
			if entry.Name() != journal {
				return receipt, install.ErrInstall
			}
			fixed = true
		}
	}
	if !fixed {
		return receipt, install.ErrInstall
	}
	journalRaw, e := install.ReadPrivateFile(filepath.Join(old, journal), 65536)
	var journalPolicy install.BootstrapSourceFilePin
	if e != nil || strictBootstrapSourceJSON(journalRaw, &journalPolicy) != nil || journalPolicy != m.KeeperPolicy {
		return receipt, install.ErrInstall
	}
	// Policy pins stay on their original paths so the original send journal
	// remains exact. Retained source-reader and custody pins stay immutable.
	keeper, reader, e := sb.MinIOReadGatePolicies(m.Native.BusinessBuckets)
	if e != nil {
		return receipt, e
	}
	for _, policy := range []struct {
		pin  install.BootstrapSourceFilePin
		body []byte
	}{{m.KeeperPolicy, keeper}, {m.ReaderPolicy, reader}} {
		body, e := pinnedDeploymentFile(policy.pin.File, policy.pin.SHA256, 16384)
		if e != nil || !bytes.Equal(body, policy.body) {
			return receipt, install.ErrInstall
		}
	}
	if scopeChanged {
		if _, matches, e := observeSourceReadGatePolicy(ctx, native, accounts[1], keeper); e != nil || !matches {
			return receipt, install.ErrInstall
		}
		newKeeper, newReader, e := sb.MinIOReadGatePolicies(names)
		if e != nil {
			return receipt, e
		}
		for i, item := range []struct {
			body []byte
			pin  *install.BootstrapSourceFilePin
		}{{newKeeper, &m.KeeperPolicy}, {newReader, &m.ReaderPolicy}} {
			name := []string{"keeper-catalog-policy.json", "reader-catalog-policy.json"}[i]
			file, sha, e := nativeInstallSaveRaw(directory, name, item.body)
			if e != nil {
				return receipt, e
			}
			*item.pin = install.BootstrapSourceFilePin{File: file, SHA256: sha}
		}
		m.Native.BusinessBuckets = names
		m.KeeperPolicyName = accounts[1] + "-catalog-" + m.KeeperPolicy.SHA256[:12]
		// Preserve the original send separately. The replacement policy has
		// its own name and send journal and never modifies the original.
		journal += ".predecessor"
	}
	m.Native.CustodyDirectory, m.Until = directory, until
	mc := filepath.Join(directory, "mc")
	cas := filepath.Join(mc, "certs", "CAs")
	if e = os.MkdirAll(cas, 0700); e != nil {
		return receipt, e
	}
	ca, e := pinnedDeploymentFile(m.Native.CAFile, m.Native.CASHA256, 65536)
	if e != nil {
		return receipt, e
	}
	if _, _, e = nativeInstallSaveRaw(directory, "mc/certs/CAs/original-ca.crt", ca); e != nil {
		return receipt, e
	}
	for _, dir := range []string{cas, filepath.Dir(cas), mc} {
		if e = sourceGateSyncDirectory(dir); e != nil {
			return receipt, e
		}
	}
	file, sha, e := nativeInstallSave(directory, "source-read.materials.json", m)
	if e != nil {
		return receipt, e
	}
	receipt.MaterialsFile, receipt.MaterialsSHA256 = file, sha
	if _, _, e = nativeInstallSaveRaw(directory, journal, journalRaw); e != nil || sourceGateSyncDirectory(directory) != nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return receipt, install.ErrInstall
	}
	// Create once before any new native send. The exact new artifact can be
	// queried further via Apply without creating another continuation.
	if _, _, e = nativeInstallSave(old, "source-keeper-continuation.json", install.BootstrapSourceFilePin{File: file, SHA256: sha}); e != nil || sourceGateSyncDirectory(old) != nil {
		return receipt, install.ErrCommitUnknown
	}
	return ApplyOriginalMinIOSourceReadMaterials(ctx, write, read, kube, file, sha, providerPin.File, providerPin.SHA256, admin)
}

func renewSourceReadCredential(old install.BootstrapSourceFilePin, previousUntil, now, until time.Time, directory string) (install.BootstrapSourceFilePin, string, error) {
	raw, e := pinnedDeploymentFile(old.File, old.SHA256, 16384)
	defer clear(raw)
	var c sb.MinIOGateCredential
	if e != nil || strictBootstrapSourceJSON(raw, &c) != nil || !c.Until.Equal(previousUntil) || c.AccessKey == "" || len(c.SecretKey) == 0 {
		return install.BootstrapSourceFilePin{}, "", install.ErrInstall
	}
	defer clear(c.SecretKey)
	c.NotBefore, c.Until = now.Add(-time.Second), until
	file, sha, e := nativeInstallSave(directory, filepath.Base(old.File), c)
	return install.BootstrapSourceFilePin{File: file, SHA256: sha}, c.AccessKey, e
}

// ContinueOriginalMinIOUnsentHistoryAccounts accepts a committed successor
// Keeper policy and an upper-layer user intent that never reached the native
// send guard. The original journals and account credentials stay in custody.
func ContinueOriginalMinIOUnsentHistoryAccounts(ctx context.Context, write *install.OriginalWriterMaintenance, read *install.BootstrapSourceRegistryAuthoring, kube kubernetes.Interface, previous, interrupted, providerPin, catalogDefinition install.BootstrapSourceFilePin, directory string, admin MinIONativeAdminFiles) (OriginalMinIOSourceSetupReceipt, error) {
	receipt := OriginalMinIOSourceSetupReceipt{Version: "original-minio-source-setup-receipt.v1", Stage: "continue_unsent_history_accounts", State: "failed"}
	if write == nil || read == nil || kube == nil || write.CheckOriginalMinIOSourceSetup(ctx, read) != nil || nativeInstallEmptyDirectory(directory) != nil {
		return receipt, install.ErrInstall
	}
	var old, mat OriginalMinIOSourceReadMaterials
	for _, item := range []struct {
		pin install.BootstrapSourceFilePin
		out *OriginalMinIOSourceReadMaterials
	}{{previous, &old}, {interrupted, &mat}} {
		raw, e := pinnedDeploymentFile(item.pin.File, item.pin.SHA256, 262144)
		if e != nil || strictBootstrapSourceJSON(raw, item.out) != nil || item.out.Version != "original-minio-source-read-materials.v1" ||
			item.pin.File != filepath.Join(item.out.Native.CustodyDirectory, "source-read.materials.json") ||
			item.out.ProviderDefinitionSHA256 != providerPin.SHA256 || item.out.Native.MCFile != admin.MCFile || item.out.Native.MCSHA256 != admin.MCSHA256 ||
			!time.Now().After(item.out.Until) {
			return receipt, install.ErrInstall
		}
	}
	originalDir, interruptedDir := old.Native.CustodyDirectory, mat.Native.CustodyDirectory
	pending, e := install.ReadPrivateFile(filepath.Join(originalDir, "source-keeper-continuation.json"), 65536)
	var pendingPin install.BootstrapSourceFilePin
	if e != nil || strictBootstrapSourceJSON(pending, &pendingPin) != nil || pendingPin != interrupted || old.KeeperPolicyName != "" ||
		mat.KeeperPolicyName == "" || mat.CaptureReaderCredential != old.CaptureReaderCredential || mat.CustodyKey != old.CustodyKey {
		return receipt, install.ErrInstall
	}
	if _, e = os.Lstat(filepath.Join(originalDir, "source-keeper-continuation-reconciled.json")); !os.IsNotExist(e) {
		return receipt, install.ErrCommitUnknown
	}
	selection, target, e := read.Selection(ctx)
	selected, encodeErr := json.Marshal(selection)
	if e != nil || encodeErr != nil || hash(selected) != mat.SourceSelectionSHA256 || target.Namespace != mat.Native.Namespace || target.NamespaceUID != mat.Native.NamespaceUID {
		return receipt, install.ErrInstall
	}
	catalog, e := readMinIOPermissionProductionInputs(catalogDefinition.File, catalogDefinition.SHA256)
	if e != nil {
		return receipt, e
	}
	defer catalog.clear()
	raw, e := pinnedDeploymentFile(providerPin.File, providerPin.SHA256, 262144)
	var src OriginalMinIOSourceProviderInput
	if e != nil || strictBootstrapSourceJSON(raw, &src) != nil || src.Version != "original-minio-source-provider-input.v1" ||
		src.Installation != target.InstallationID || src.Namespace != target.Namespace || src.NamespaceUID != target.NamespaceUID ||
		catalog.definition.Grant.Provider != src.Provider || catalog.grant.Installation != src.Installation ||
		catalog.grant.NamespaceUID != src.NamespaceUID || catalog.catalog.Root != src.Installation+"/catalog/" {
		return receipt, install.ErrInstall
	}
	names := make([]string, 0, len(mat.Native.BusinessBuckets))
	for _, name := range mat.Native.BusinessBuckets {
		if name != catalog.catalog.Bucket {
			names = append(names, name)
		}
	}
	normalized := mat.Native
	normalized.BusinessBuckets, normalized.CustodyDirectory = names, originalDir
	if len(mat.Native.BusinessBuckets) != len(old.Native.BusinessBuckets)+1 || !reflect.DeepEqual(normalized, old.Native) {
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
	live, e := collectOriginalWholeHistoryBuckets(ctx, native, mat.Native.BusinessBuckets)
	if e != nil || !reflect.DeepEqual(live, mat.Native.BusinessBuckets) {
		return receipt, install.ErrInstall
	}
	var identities [3]sb.MinIOGateCredential
	for i, pair := range [][2]install.BootstrapSourceFilePin{{old.RootCredential, mat.RootCredential}, {old.KeeperCredential, mat.KeeperCredential}, {old.ReaderCredential, mat.ReaderCredential}} {
		var orig sb.MinIOGateCredential
		for n, p := range pair {
			raw, e := pinnedDeploymentFile(p.File, p.SHA256, 16384)
			dest := &orig
			expiry := old.Until
			if n == 1 {
				dest, expiry = &identities[i], mat.Until
			}
			if e != nil || strictBootstrapSourceJSON(raw, dest) != nil || !dest.Until.Equal(expiry) {
				clear(raw)
				return receipt, install.ErrInstall
			}
			clear(raw)
			defer clear(dest.SecretKey)
		}
		if orig.AccessKey != identities[i].AccessKey || orig.Version != identities[i].Version || !bytes.Equal(orig.SecretKey, identities[i].SecretKey) {
			return receipt, install.ErrInstall
		}
	}
	root, keeper, reader := identities[0], identities[1], identities[2]
	if root.AccessKey != native.credential.AccessKey || string(root.SecretKey) != native.credential.SecretKey ||
		keeper.AccessKey == reader.AccessKey || keeper.AccessKey == root.AccessKey || reader.AccessKey == root.AccessKey {
		return receipt, install.ErrInstall
	}
	keeperPolicy, readerPolicy, e := sb.MinIOReadGatePolicies(live)
	if e != nil || mat.KeeperPolicyName != keeper.AccessKey+"-catalog-"+hash(keeperPolicy)[:12] {
		return receipt, install.ErrInstall
	}
	for _, body := range []struct {
		pin install.BootstrapSourceFilePin
		raw []byte
	}{{mat.KeeperPolicy, keeperPolicy}, {mat.ReaderPolicy, readerPolicy}} {
		exact, e := pinnedDeploymentFile(body.pin.File, body.pin.SHA256, 16384)
		if e != nil || !bytes.Equal(exact, body.raw) {
			return receipt, install.ErrInstall
		}
	}
	policyJournal := "source-setup-" + mat.KeeperPolicyName + "-policy.send-unknown.json"
	journal, e := reconcileUnsentHistoryAccount(interruptedDir, originalDir, policyJournal, keeper.AccessKey, root.AccessKey, mat)
	if e != nil {
		return receipt, e
	}
	if _, matches, e := observeSourceReadGatePolicy(ctx, native, mat.KeeperPolicyName, keeperPolicy); e != nil || !matches {
		return receipt, install.ErrInstall
	}
	for _, account := range []sb.MinIOGateCredential{keeper, reader} {
		if exists, e := sourceGateOwnUser(ctx, native, account, mat.KeeperPolicyName); e != nil || exists {
			return receipt, install.ErrCommitUnknown
		}
	}
	deadline, deadlineOK := ctx.Deadline()
	_, ownerUntil, e := write.Identity(ctx)
	now := time.Now().UTC()
	until := ownerUntil
	for _, limit := range []time.Time{deadline, selection.Until, catalog.window.until} {
		if limit.Before(until) {
			until = limit
		}
	}
	if e != nil || !deadlineOK || until.Sub(now) < 30*time.Second {
		return receipt, install.ErrInstall
	}
	for _, field := range []*install.BootstrapSourceFilePin{&mat.RootCredential, &mat.KeeperCredential, &mat.ReaderCredential} {
		pin, _, e := renewSourceReadCredential(*field, mat.Until, now, until, directory)
		if e != nil {
			return receipt, e
		}
		*field = pin
	}
	mat.Native.CustodyDirectory, mat.Until = directory, until
	cas := filepath.Join(directory, "mc", "certs", "CAs")
	if e = os.MkdirAll(cas, 0700); e != nil {
		return receipt, e
	}
	ca, e := pinnedDeploymentFile(mat.Native.CAFile, mat.Native.CASHA256, 65536)
	if e != nil {
		return receipt, e
	}
	if _, _, e = nativeInstallSaveRaw(directory, "mc/certs/CAs/original-ca.crt", ca); e != nil {
		return receipt, e
	}
	file, sha, e := nativeInstallSave(directory, "source-read.materials.json", mat)
	if e != nil {
		return receipt, e
	}
	receipt.MaterialsFile, receipt.MaterialsSHA256 = file, sha
	if _, _, e = nativeInstallSaveRaw(directory, policyJournal, journal); e != nil || sourceGateSyncDirectory(directory) != nil ||
		write.CheckOriginalMinIOSourceSetup(ctx, read) != nil {
		return receipt, install.ErrInstall
	}
	if _, _, e = nativeInstallSave(originalDir, "source-keeper-continuation-reconciled.json", install.BootstrapSourceFilePin{File: file, SHA256: sha}); e != nil || sourceGateSyncDirectory(originalDir) != nil {
		return receipt, install.ErrCommitUnknown
	}
	return ApplyOriginalMinIOSourceReadMaterials(ctx, write, read, kube, file, sha, providerPin.File, providerPin.SHA256, admin)
}

func reconcileUnsentHistoryAccount(interruptedDir, originalDir, policyJournal, keeper, root string, mat OriginalMinIOSourceReadMaterials) ([]byte, error) {
	pred := "source-setup-" + keeper + "-policy.send-unknown.json"
	user := "source-setup-" + keeper + "-user.send-unknown.json"
	wantNative, e := ce.Canonical(struct{ Version, ActorSHA256, Method, Path, Query, PayloadSHA256 string }{
		"original-minio-native-send-once.v1", hash([]byte(root)), "PUT", "/minio/admin/v3/add-canned-policy",
		url.Values{"name": {mat.KeeperPolicyName}}.Encode(), mat.KeeperPolicy.SHA256,
	})
	if e != nil {
		return nil, e
	}
	nativeName := "native-send-" + hash(wantNative) + ".json"
	entries, e := os.ReadDir(interruptedDir)
	if e != nil {
		return nil, e
	}
	expected := []string{pred + ".predecessor", user, policyJournal, nativeName}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "source-setup-") || strings.HasPrefix(name, "native-send-") {
			switch name {
			case expected[0], expected[1], expected[2], expected[3]:
				seen++
			default:
				return nil, install.ErrCommitUnknown
			}
		}
	}
	if seen != len(expected) {
		return nil, install.ErrCommitUnknown
	}
	original, e := install.ReadPrivateFile(filepath.Join(originalDir, pred), 65536)
	actualPred, predErr := install.ReadPrivateFile(filepath.Join(interruptedDir, pred+".predecessor"), 65536)
	actualNative, nativeErr := install.ReadPrivateFile(filepath.Join(interruptedDir, nativeName), 65536)
	if e != nil || predErr != nil || nativeErr != nil || !bytes.Equal(original, actualPred) || !bytes.Equal(actualNative, wantNative) {
		return nil, install.ErrCommitUnknown
	}
	for name, want := range map[string]install.BootstrapSourceFilePin{policyJournal: mat.KeeperPolicy, user: mat.KeeperCredential} {
		actual, e := install.ReadPrivateFile(filepath.Join(interruptedDir, name), 65536)
		encoded, encErr := ce.Canonical(want)
		if e != nil || encErr != nil || !bytes.Equal(actual, encoded) {
			return nil, install.ErrCommitUnknown
		}
	}
	return install.ReadPrivateFile(filepath.Join(interruptedDir, policyJournal), 65536)
}
