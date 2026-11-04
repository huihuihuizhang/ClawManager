package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes"
)

const minioInstallMCRelease = "RELEASE.2025-08-13T08-35-41Z"

type MinIONativeAdminFiles struct{ UserFile, PasswordFile, MCFile, MCSHA256 string }
type MinIONativeProvisionReceipt struct {
	Version, MaterialsSHA256, DefinitionSHA256, Stage, State, MCSHA256, MCVersionSHA256 string
	NativeWritesAttempted                                                               bool
}

func nativeInstallAdmin(provider minioPermissionProvider, ctx context.Context, files MinIONativeAdminFiles) (*minioPermissionHTTP, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, install.ErrInstall
	}
	user, e := install.ReadPrivateFile(files.UserFile, 1024)
	if e != nil {
		return nil, e
	}
	defer clear(user)
	password, e := install.ReadPrivateFile(files.PasswordFile, 4096)
	if e != nil {
		return nil, e
	}
	defer clear(password)
	end, ok := ctx.Deadline()
	if !ok || len(user) == 0 || len(password) == 0 || strings.ContainsAny(string(user)+string(password), "\x00\r\n") {
		return nil, install.ErrInstall
	}
	return newMinioPermissionHTTP(provider, nativePublicationCredential{AccessKey: string(user), SecretKey: string(password), NotBefore: time.Now().UTC().Add(-time.Minute), Until: end})
}

// Read-only authenticated discovery after D installs TLS. Result is original
// authoring metadata, never a permission/readiness assertion. A blank expected
// deployment ID is allowed ONLY here; actual apply requires the retained ID.
func InspectOriginalMinIONativeProvider(ctx context.Context, templateFile, templateSHA string, files MinIONativeAdminFiles) (map[string]string, error) {
	raw, e := pinnedDeploymentFile(templateFile, templateSHA, 262144)
	var d install.MinIOPermissionDefinition
	if e != nil || decodePublicationCanonical(raw, &d) != nil {
		return nil, install.ErrInstall
	}
	praw, e := json.Marshal(d.Grant.Provider)
	var provider minioPermissionProvider
	if e != nil || json.Unmarshal(praw, &provider) != nil {
		return nil, install.ErrInstall
	}
	n, e := nativeInstallAdmin(provider, ctx, files)
	if e != nil {
		return nil, e
	}
	defer n.close()
	raw, status, e := n.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	var info struct {
		DeploymentID string `json:"deploymentID"`
		Region       string `json:"region"`
		Servers      []struct {
			State, Version string
			Commit         string `json:"commitID"`
		} `json:"servers"`
	}
	profile, ok := minioNativeProfile(d.Grant.Profile)
	if !ok || profile.ServerVersion != "2025-09-07T16:13:09Z" || d.Version != profile.Definition || e != nil || status != 200 || minioPermissionUniqueJSON(raw) != nil || json.Unmarshal(raw, &info) != nil || info.DeploymentID == "" || info.Region != provider.Region || len(info.Servers) != 1 || info.Servers[0].State != "ok" || info.Servers[0].Version != profile.ServerVersion || info.Servers[0].Commit != profile.ServerCommit || provider.DeploymentID != "" && provider.DeploymentID != info.DeploymentID {
		return nil, install.ErrInstall
	}
	return map[string]string{"Version": "original-minio-authenticated-provider-observation.v1", "TemplateSHA256": templateSHA, "Endpoint": provider.Endpoint, "CASHA256": provider.CASHA256, "SPKISHA256": provider.SPKISHA256, "DeploymentID": info.DeploymentID, "ServerVersion": profile.ServerVersion, "ServerCommit": profile.ServerCommit}, nil
}

func nativeInstallMissing(raw []byte, status int, code, path, region string) bool {
	if status != 404 || len(raw) > 8192 || minioPermissionUniqueJSON(raw) != nil {
		return false
	}
	var f map[string]string
	if json.Unmarshal(raw, &f) != nil {
		return false
	}
	allowed := map[string]bool{"Code": true, "Message": true, "Key": true, "BucketName": true, "Resource": true, "Region": true, "RequestId": true, "HostId": true}
	for k := range f {
		if !allowed[k] {
			return false
		}
	}
	return f["Code"] == code && f["Message"] != "" && f["Resource"] == path && f["Key"] == "" && f["BucketName"] == "" && f["RequestId"] != "" && f["HostId"] != "" && (f["Region"] == "" || f["Region"] == region)
}

func nativeInstallOwnUser(ctx context.Context, n *minioPermissionHTTP, role MinIONativeInstallRole, credential nativePublicationCredential) (bool, error) {
	path := "/minio/admin/v3/user-info"
	raw, status, e := n.get(ctx, path, url.Values{"accessKey": {role.Account}})
	if e != nil {
		return false, e
	}
	if nativeInstallMissing(raw, status, "XMinioAdminNoSuchUser", path, n.provider.Region) {
		return false, nil
	}
	var user struct {
		AuthInfo                      *struct{ Type, AuthServer, AuthServerUserID string } `json:"userAuthInfo,omitempty"`
		SecretKey, PolicyName, Status string
		MemberOf                      []string
		UpdatedAt                     time.Time
	}
	if status != 200 || minioPermissionDecode(raw, &user) != nil || user.SecretKey != "" || user.Status != "enabled" || len(user.MemberOf) != 0 || user.UpdatedAt.IsZero() || user.PolicyName != "" && user.PolicyName != role.PolicyName || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != role.Account) {
		return false, install.ErrInstall
	}
	// A same-name record is never updated or re-keyed. Resume requires proof
	// that the retained original secret authenticates that exact independent
	// regular identity and cannot bypass owner checks.
	self, e := newMinioPermissionHTTP(n.provider, credential)
	if e != nil {
		return false, e
	}
	defer self.close()
	raw, status, e = self.get(ctx, "/minio/admin/v3/accountinfo", nil)
	var account struct {
		AccountName             string
		Server, Policy, Buckets json.RawMessage
	}
	if e != nil || status != 200 || minioPermissionDecode(raw, &account) != nil || account.AccountName != role.Account {
		return false, install.ErrInstall
	}
	raw, status, e = self.get(ctx, minioEffectiveOwnerGuardPath, url.Values{"subSys": {"policy_plugin"}, "key": {""}})
	if e != nil || status != 403 || minioEffectiveAdminAccessDenied(raw) != nil {
		return false, install.ErrInstall
	}
	return true, nil
}

type nativeInstallVersionBuffer struct{ bytes.Buffer }

func (b *nativeInstallVersionBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16384 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}
func nativeInstallMC(ctx context.Context, dir string, n *minioPermissionHTTP, files MinIONativeAdminFiles, args ...string) error {
	return nativeInstallMCInput(ctx, dir, n, files, nil, args...)
}
func nativeInstallMCCommand(ctx context.Context, dir string, n *minioPermissionHTTP, files MinIONativeAdminFiles, input []byte, args ...string) *exec.Cmd {
	u, _ := url.Parse(n.provider.Endpoint)
	u.User = url.UserPassword(n.credential.AccessKey, n.credential.SecretKey)
	cmd := exec.CommandContext(ctx, files.MCFile, append([]string{"--config-dir", filepath.Join(dir, "mc"), "--json"}, args...)...)
	cmd.Env = []string{"MC_HOST_native=" + u.String(), "MC_CONFIG_DIR=" + filepath.Join(dir, "mc"), "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd
}
func nativeInstallMCInput(ctx context.Context, dir string, n *minioPermissionHTTP, files MinIONativeAdminFiles, input []byte, args ...string) error {
	// One existing installer owns all mutations. Pinned mc remains useful for
	// read-only discovery/version checks, but its embedded madmin automatically
	// replays network failures and cannot enforce commit-unknown send-once.
	return nativeInstallWriteOnce(ctx, dir, n, input, args...)
}

// Original MinIO ADMIN installation only. The actual enrolled application
// owner authenticates before native operations; admin secrets remain operator
// files. Existing exact source observation runs again at the end and later in
// the actual issuer/probes. No provision-success bit can admit a task.
func ApplyOriginalMinIONativeMaterials(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, file, sha string, files MinIONativeAdminFiles) (receipt MinIONativeProvisionReceipt, resultErr error) {
	receipt = MinIONativeProvisionReceipt{Version: "original-minio-native-provision-receipt.v1", MaterialsSHA256: sha, Stage: "original_materials", State: "failed"}
	raw, e := pinnedDeploymentFile(file, sha, 262144)
	var m MinIONativeInstallMaterials
	if ctx == nil || ctx.Err() != nil || owner == nil || kube == nil || e != nil || decodePublicationCanonical(raw, &m) != nil || m.Version != "original-minio-native-install-materials.v1" || len(m.Roles) != 6 || filepath.Join(m.Directory, "native-install.materials.json") != file {
		return receipt, install.ErrInstall
	}
	receipt.DefinitionSHA256 = m.DefinitionSHA256
	issuer, e := owner.PrepareMinIOPermissionIssue(ctx, password, enrollment, m.DefinitionFile, m.DefinitionSHA256)
	if e != nil {
		return receipt, e
	}
	p, e := readMinIOPermissionProductionInputs(m.DefinitionFile, m.DefinitionSHA256)
	if e != nil {
		return receipt, e
	}
	defer p.clear()
	// Retain the ORIGINAL minimum grant/credential window for every mc child
	// and native request; the operator's two-minute cap never extends it.
	ctx, stop := context.WithDeadline(ctx, p.window.until)
	defer stop()
	if p.grant.Provider.DeploymentID == "" || minioPermissionKubernetesCheck(ctx, kube, p) != nil {
		return receipt, install.ErrInstall
	}
	roles := map[string]MinIONativeInstallRole{}
	for _, role := range m.Roles {
		if roles[role.Purpose].Purpose != "" {
			return receipt, install.ErrInstall
		}
		roles[role.Purpose] = role
	}
	uses := append([]minioPermissionUse(nil), p.uses...)
	uses = append(uses, minioPermissionUse{principal: minioPermissionPrincipal{Purpose: "observer", AccountSHA256: p.configuration.ObserverAccountSHA256, PolicyName: p.configuration.ObserverPolicyName, PolicySHA256: p.configuration.ObserverPolicySHA256}, credential: p.observer})
	for _, u := range uses {
		r := roles[u.principal.Purpose]
		if r.Account != u.credential.AccessKey || r.PolicyName != u.principal.PolicyName || r.PolicySHA256 != u.principal.PolicySHA256 || filepath.Join(m.Directory, "credentials", r.Purpose+".json") != r.CredentialFile || r.CredentialSHA256 == "" || filepath.Join(m.Directory, "policies", r.Purpose+".json") != r.PolicyFile {
			return receipt, install.ErrInstall
		}
		b, e := pinnedDeploymentFile(r.CredentialFile, r.CredentialSHA256, 16384)
		var c nativePublicationCredential
		if e != nil || decodePublicationCanonical(b, &c) != nil || c != u.credential {
			return receipt, install.ErrInstall
		}
		b, e = pinnedDeploymentFile(r.PolicyFile, r.PolicySHA256, 16384)
		rules := minioPermissionObserverRulesV2(p.uses)
		if r.Purpose != "observer" {
			rules, e = minioPermissionObjectRulesV2(r.Purpose, u.bucket, u.root, u.staging)
		}
		if e != nil {
			return receipt, e
		}
		if _, e = minioPermissionNormalizedPolicyV2(b, r.PolicySHA256, rules); e != nil {
			return receipt, e
		}
	}
	root, e := os.OpenRoot(m.Directory)
	if e != nil {
		return receipt, e
	}
	defer root.Close()
	lock, e := root.OpenFile("native-provision.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return receipt, install.ErrInstall
	}
	lockInfo, e := lock.Stat()
	if e != nil {
		lock.Close()
		return receipt, e
	}
	defer func() {
		lock.Close()
		if current, err := root.Lstat("native-provision.lock"); err == nil && os.SameFile(lockInfo, current) {
			root.Remove("native-provision.lock")
		}
	}()
	if _, e = lock.Write([]byte(sha)); e != nil {
		return receipt, e
	}
	if e = lock.Sync(); e != nil {
		return receipt, e
	}
	defer func() {
		if errors.Is(resultErr, install.ErrCommitUnknown) {
			receipt.State = "native_outcome_unknown_retain_same_intent"
		} else if resultErr != nil && receipt.NativeWritesAttempted {
			receipt.State = "failed_after_native_write_inspect_same_intent"
		}
		_, _, saveErr := nativeInstallSave(m.Directory, "native-provision-result-"+time.Now().UTC().Format("20060102T150405.000000000")+".json", receipt)
		if resultErr == nil && saveErr != nil {
			resultErr = install.ErrCommitUnknown
		}
	}()
	receipt.Stage = "mc_byte_version_pin"
	st, e := os.Lstat(files.MCFile)
	if e != nil || !filepath.IsAbs(files.MCFile) || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() < 1 || st.Size() > 128<<20 || st.Mode().Perm()&0022 != 0 || !formalCandidateDigest(files.MCSHA256) {
		return receipt, install.ErrInstall
	}
	mc, e := os.ReadFile(files.MCFile)
	if e != nil || hash(mc) != files.MCSHA256 {
		return receipt, install.ErrInstall
	}
	receipt.MCSHA256 = files.MCSHA256
	var version nativeInstallVersionBuffer
	cmd := exec.CommandContext(ctx, files.MCFile, "--version")
	cmd.Stdout = &version
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || !bytes.Contains(version.Bytes(), []byte("mc version "+minioInstallMCRelease+" ")) {
		return receipt, install.ErrInstall
	}
	receipt.MCVersionSHA256 = hash(version.Bytes())
	ca, e := pinnedDeploymentFile(p.grant.Provider.CAFile, p.grant.Provider.CASHA256, 65536)
	if e != nil {
		return receipt, e
	}
	caName := "mc/certs/CAs/original-ca.crt"
	caFile, e := root.OpenFile(caName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		old, re := root.ReadFile(caName)
		if re != nil || !bytes.Equal(old, ca) {
			return receipt, install.ErrInstall
		}
	} else if e != nil {
		return receipt, e
	} else {
		_, we := caFile.Write(ca)
		se := caFile.Sync()
		ce := caFile.Close()
		if we != nil || se != nil || ce != nil {
			return receipt, install.ErrInstall
		}
	}
	receipt.Stage = "strict_tls_authenticated_version"
	n, e := nativeInstallAdmin(p.grant.Provider, ctx, files)
	if e != nil {
		return receipt, e
	}
	defer n.close()
	if _, e = n.collectNativeInstallServer(ctx, p.grant.Profile); e != nil {
		return receipt, e
	}
	for _, role := range m.Roles {
		if role.Account == n.credential.AccessKey {
			return receipt, install.ErrInstall
		}
	}
	for _, bucket := range []string{p.target.Bucket, p.catalog.Bucket} {
		receipt.Stage = "versioned_bucket_" + bucket
		raw, status, e := n.get(ctx, "/"+bucket, url.Values{"versioning": {""}})
		if e != nil {
			return receipt, e
		}
		if minioTerminalError(minioTerminalReply{status: status, body: raw}, 404, "NoSuchBucket", "", p.grant.Provider.Region) {
			receipt.NativeWritesAttempted = true
			if e = nativeInstallMC(ctx, m.Directory, n, files, "mb", "native/"+bucket); e != nil {
				return receipt, e
			}
		} else {
			var v struct {
				XMLName xml.Name `xml:"VersioningConfiguration"`
				Status  string   `xml:"Status"`
			}
			if status != 200 || xml.Unmarshal(raw, &v) != nil || v.Status != "" && v.Status != "Enabled" && v.Status != "Suspended" {
				return receipt, install.ErrInstall
			}
		}
		// Refuse an existing bucket policy; never delete or replace one.
		raw, status, e = n.get(ctx, "/"+bucket, url.Values{"policy": {""}})
		if e != nil || !minioTerminalError(minioTerminalReply{status: status, body: raw}, 404, "NoSuchBucketPolicy", "", p.grant.Provider.Region) {
			return receipt, install.ErrInstall
		}
		receipt.NativeWritesAttempted = true
		if e = nativeInstallMC(ctx, m.Directory, n, files, "version", "enable", "native/"+bucket); e != nil {
			return receipt, e
		}
		if _, e = n.bucket(ctx, bucket); e != nil {
			return receipt, e
		}
		if issuer.Recheck(ctx) != nil {
			return receipt, install.ErrInstall
		}
	}
	for _, u := range uses {
		r := roles[u.principal.Purpose]
		receipt.Stage = "principal_" + r.Purpose
		if r.Account == n.credential.AccessKey {
			return receipt, install.ErrInstall
		}
		path := "/minio/admin/v3/info-canned-policy"
		raw, status, e := n.get(ctx, path, url.Values{"name": {r.PolicyName}, "v": {"2"}})
		if e != nil {
			return receipt, e
		}
		rules := minioPermissionObserverRulesV2(p.uses)
		if r.Purpose != "observer" {
			rules, e = minioPermissionObjectRulesV2(r.Purpose, u.bucket, u.root, u.staging)
		}
		if e != nil {
			return receipt, e
		}
		if nativeInstallMissing(raw, status, "XMinioAdminNoSuchPolicy", path, n.provider.Region) {
			receipt.NativeWritesAttempted = true
			if e = nativeInstallMC(ctx, m.Directory, n, files, "admin", "policy", "create", "native", r.PolicyName, r.PolicyFile); e != nil {
				return receipt, e
			}
		} else {
			var policy struct {
				PolicyName             string
				Policy                 json.RawMessage
				CreateDate, UpdateDate time.Time
			}
			if status != 200 || minioPermissionDecode(raw, &policy) != nil || policy.PolicyName != r.PolicyName {
				return receipt, install.ErrInstall
			}
			if _, e = minioPermissionNormalizedPolicyV2(policy.Policy, r.PolicySHA256, rules); e != nil {
				return receipt, e
			}
		}
		exists, e := nativeInstallOwnUser(ctx, n, r, u.credential)
		if e != nil {
			return receipt, e
		}
		if !exists {
			receipt.NativeWritesAttempted = true
			// Pinned mc's documented non-TTY two-line input path. Neither new
			// access key nor secret key enters process arguments or diagnostics.
			input := []byte(r.Account + "\n" + u.credential.SecretKey + "\n")
			e = nativeInstallMCInput(ctx, m.Directory, n, files, input, "admin", "user", "add", "native")
			clear(input)
			if e != nil {
				return receipt, e
			}
			if exists, e = nativeInstallOwnUser(ctx, n, r, u.credential); e != nil || !exists {
				return receipt, install.ErrInstall
			}
		}
		// Same original plan may resume a partial policy attachment. No password
		// update is issued for an existing user, and foreign mappings refuse.
		receipt.NativeWritesAttempted = true
		if e = nativeInstallMC(ctx, m.Directory, n, files, "admin", "policy", "attach", "native", r.PolicyName, "--user", r.Account); e != nil {
			return receipt, e
		}
		if _, e = n.userAndPolicyV2(ctx, r.Account, r.PolicyName, r.PolicySHA256, rules); e != nil || issuer.Recheck(ctx) != nil {
			return receipt, install.ErrInstall
		}
	}
	receipt.Stage = "actual_source_reobservation"
	if _, e = ObserveOriginalMinIOPermissions(ctx, kube, m.DefinitionFile, m.DefinitionSHA256); e != nil {
		return receipt, e
	}
	if issuer.Recheck(ctx) != nil {
		return receipt, install.ErrInstall
	}
	receipt.Stage, receipt.State = "complete", "native_materials_installed_source_reobserved_not_issued"
	return receipt, nil
}

func (n *minioPermissionHTTP) collectNativeInstallServer(ctx context.Context, profile string) (string, error) {
	p, ok := minioNativeProfile(profile)
	if !ok || p.ServerVersion != "2025-09-07T16:13:09Z" {
		return "", install.ErrInstall
	}
	return n.serverSeptember(ctx)
}
func minioPermissionKubernetesCheck(ctx context.Context, kube kubernetes.Interface, p *minioPermissionProductionInputs) error {
	_, e := minioPermissionKubernetes(ctx, kube, p.configuration, p.grant.Provider)
	return e
}
