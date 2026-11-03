package systembackupexecution

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
)

type MinIONativeInstallRole struct{ Purpose, Account, PolicyName, CredentialFile, CredentialSHA256, PolicyFile, PolicySHA256 string }
type MinIONativeInstallMaterials struct {
	Version, OriginalTemplateSHA256, DefinitionFile, DefinitionSHA256 string
	Directory                                                         string
	Roles                                                             []MinIONativeInstallRole
}
type MinIONativeInstallOutput struct{ File, SHA256, DefinitionFile, DefinitionSHA256 string }

func nativeInstallEmptyDirectory(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return install.ErrInstall
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return install.ErrInstall
	}
	return nil
}
func nativeInstallSave(dir, name string, value any) (string, string, error) {
	raw, e := ce.Canonical(value)
	if e != nil {
		return "", "", e
	}
	return nativeInstallSaveRaw(dir, name, raw)
}
func nativeInstallSaveRaw(dir, name string, raw []byte) (string, string, error) {
	root, e := os.OpenRoot(dir)
	if e != nil {
		return "", "", e
	}
	defer root.Close()
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", "", e
	}
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return "", "", install.ErrInstall
	}
	return filepath.Join(dir, name), hash(raw), nil
}
func nativeInstallRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return b, e
}
func nativeInstallPolicy(rules []minioPermissionRule) ([]byte, string, error) {
	statements := []json.RawMessage{}
	for _, r := range rules {
		a, s := append([]string(nil), r.Actions...), append([]string(nil), r.Resources...)
		sort.Strings(a)
		sort.Strings(s)
		raw, e := ce.Canonical(map[string]any{"Effect": "Allow", "Action": a, "Resource": s})
		if e != nil {
			return nil, "", e
		}
		statements = append(statements, raw)
	}
	sort.Slice(statements, func(i, j int) bool { return bytes.Compare(statements[i], statements[j]) < 0 })
	raw, e := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if e != nil {
		return nil, "", e
	}
	sha := hash(raw)
	if _, e = minioPermissionNormalizedPolicyV2(raw, sha, rules); e != nil {
		return nil, "", e
	}
	return raw, sha, nil
}

// Original authoring only: creates SIX new private files and exact finite
// policies from the existing original definition/target/catalog templates.
// It neither contacts a provider nor signs a permission or writes SQL.
func GenerateOriginalMinIONativeMaterials(templateFile, templateSHA, directory string) (MinIONativeInstallOutput, error) {
	return generateOriginalMinIONativeMaterials(templateFile, templateSHA, directory, nil, nil)
}

// D prepare is the UNIQUE six-credential generator in the field sequence.
// This entry copies its exact pinned bytes/identities; it generates NO account
// credential. It only joins them to the original C definition and finite plan.
func BindDPreparedMinIONativeMaterials(templateFile, templateSHA, receiptFile, receiptSHA, directory string) (MinIONativeInstallOutput, error) {
	var receipt struct {
		Status         string `json:"status"`
		NamespaceUID   string `json:"namespace_uid"`
		CA             string `json:"ca_sha256"`
		SPKI           string `json:"server_spki_sha256"`
		Leaf           string `json:"server_leaf_sha256"`
		AppImage       string `json:"app_image"`
		Bundle         string `json:"bundle_sha256"`
		NativeObserved bool   `json:"native_permission_observed"`
		MySQLRotated   bool   `json:"mysql_rotated"`
		ClusterMutated bool   `json:"cluster_mutated"`
		Accounts       []struct {
			Purpose     string `json:"purpose"`
			Account     string `json:"account_sha256"`
			Credential  string `json:"credential_file_sha256"`
			Provisioned bool   `json:"provisioned"`
		} `json:"accounts"`
	}
	raw, e := pinnedDeploymentFile(receiptFile, receiptSHA, 65536)
	if e != nil || filepath.Base(receiptFile) != "receipt.json" || decodePublicationCanonical(raw, &receipt) != nil || receipt.Status != "prepared_local_only" || receipt.NativeObserved || receipt.MySQLRotated || receipt.ClusterMutated || len(receipt.Accounts) != 6 {
		return MinIONativeInstallOutput{}, install.ErrInstall
	}
	if _, e = pinnedDeploymentFile(filepath.Join(filepath.Dir(receiptFile), "bundle.json"), receipt.Bundle, 262144); e != nil {
		return MinIONativeInstallOutput{}, e
	}
	raw, e = pinnedDeploymentFile(templateFile, templateSHA, 262144)
	var definition install.MinIOPermissionDefinition
	if e != nil || decodePublicationCanonical(raw, &definition) != nil || definition.Grant.NamespaceUID != receipt.NamespaceUID || definition.Grant.Provider.CASHA256 != receipt.CA || definition.Grant.Provider.SPKISHA256 != receipt.SPKI {
		return MinIONativeInstallOutput{}, install.ErrInstall
	}
	credentials := map[string]nativePublicationCredential{}
	credentialBytes := map[string][]byte{}
	for _, account := range receipt.Accounts {
		switch account.Purpose {
		case "artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append", "observer":
		default:
			return MinIONativeInstallOutput{}, install.ErrInstall
		}
		if account.Provisioned || credentials[account.Purpose].AccessKey != "" {
			return MinIONativeInstallOutput{}, install.ErrInstall
		}
		credential, e := loadNativePublicationCredential(filepath.Join(filepath.Dir(receiptFile), account.Purpose+".credential.json"), account.Credential)
		if e != nil || hash([]byte(credential.AccessKey)) != account.Account || credential.SessionToken != "" || credential.NotBefore.After(definition.Grant.NotBefore) || credential.Until.Before(definition.Grant.Until) {
			return MinIONativeInstallOutput{}, install.ErrInstall
		}
		credentials[account.Purpose] = credential
		raw, e := pinnedDeploymentFile(filepath.Join(filepath.Dir(receiptFile), account.Purpose+".credential.json"), account.Credential, 16384)
		if e != nil {
			return MinIONativeInstallOutput{}, e
		}
		credentialBytes[account.Purpose] = raw
	}
	defer func() {
		for _, raw := range credentialBytes {
			clear(raw)
		}
	}()
	return generateOriginalMinIONativeMaterials(templateFile, templateSHA, directory, credentials, credentialBytes)
}

func generateOriginalMinIONativeMaterials(templateFile, templateSHA, directory string, prepared map[string]nativePublicationCredential, preparedBytes map[string][]byte) (MinIONativeInstallOutput, error) {
	zero := MinIONativeInstallOutput{}
	if nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	raw, e := pinnedDeploymentFile(templateFile, templateSHA, 262144)
	var d install.MinIOPermissionDefinition
	if e != nil || decodePublicationCanonical(raw, &d) != nil || d.Grant.Profile != ma.SeptemberPermissionProfile {
		return zero, install.ErrInstall
	}
	profile, _ := ma.NativeProfile(d.Grant.Profile)
	if d.Version != profile.Definition || d.Grant.Version != "minio-permission-grant.v1" || d.Grant.Epoch != 1 || len(d.Grant.Principals) != 5 || d.Grant.NotBefore.IsZero() || !d.Grant.NotBefore.Before(d.Grant.Until) || d.Grant.Until.Sub(d.Grant.NotBefore) > 24*time.Hour {
		return zero, install.ErrInstall
	}
	raw, e = pinnedDeploymentFile(d.TargetFile, d.TargetSHA256, 65536)
	var target PublicationTargetMaterials
	if e != nil || decodeProviderDeploymentJSON(raw, &target) != nil {
		return zero, install.ErrInstall
	}
	raw, e = pinnedDeploymentFile(target.CatalogMaterialsFile, target.CatalogMaterialsSHA256, 65536)
	var catalog PublicationCatalogMaterials
	if e != nil || decodeProviderDeploymentJSON(raw, &catalog) != nil || target.Bucket == catalog.Bucket || target.InstallationID != d.Grant.Installation || target.Root != d.Grant.Installation+"/" || target.RemoteStagingRoot == "" || catalog.InstallationID != target.InstallationID || target.Endpoint != d.Grant.Provider.Endpoint || catalog.Endpoint != target.Endpoint || target.Region != d.Grant.Provider.Region || catalog.Region != target.Region || target.CASHA256 != d.Grant.Provider.CASHA256 || catalog.CASHA256 != target.CASHA256 {
		return zero, install.ErrInstall
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return zero, e
	}
	defer root.Close()
	for _, name := range []string{"credentials", "policies", "mc", "mc/certs", "mc/certs/CAs"} {
		if root.Mkdir(name, 0700) != nil {
			return zero, install.ErrInstall
		}
	}
	nonce, e := nativeInstallRandom(12)
	if e != nil {
		return zero, e
	}
	prefix := "cm-" + hex.EncodeToString(nonce) + "-"
	materials := MinIONativeInstallMaterials{Version: "original-minio-native-install-materials.v1", OriginalTemplateSHA256: templateSHA, Directory: directory, Roles: []MinIONativeInstallRole{}}
	uses := []minioPermissionUse{}
	byPurpose := map[string]int{}
	for i, p := range d.Grant.Principals {
		if byPurpose[p.Purpose] != 0 {
			return zero, install.ErrInstall
		}
		byPurpose[p.Purpose] = i + 1
	}
	for _, purpose := range []string{"artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read", "observer"} {
		credential := prepared[purpose]
		if prepared == nil {
			key, e := nativeInstallRandom(12)
			if e != nil {
				return zero, e
			}
			secret, e := nativeInstallRandom(20)
			if e != nil {
				return zero, e
			}
			credential = nativePublicationCredential{AccessKey: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key), SecretKey: hex.EncodeToString(secret), NotBefore: d.Grant.NotBefore, Until: d.Grant.Until}
			clear(key)
			clear(secret)
		} else if credential.AccessKey == "" {
			return zero, install.ErrInstall
		}
		var file, sha string
		if prepared == nil {
			file, sha, e = nativeInstallSave(directory, "credentials/"+purpose+".json", credential)
		} else {
			// Preserve D's exact original timestamp spelling and byte pin.
			file, sha, e = nativeInstallSaveRaw(directory, "credentials/"+purpose+".json", preparedBytes[purpose])
		}
		if e != nil {
			return zero, e
		}
		role := MinIONativeInstallRole{Purpose: purpose, Account: credential.AccessKey, PolicyName: prefix + purpose, CredentialFile: file, CredentialSHA256: sha}
		if purpose == "observer" {
			d.ObserverCredentialFile, d.ObserverCredentialSHA256, d.ObserverAccountSHA256, d.ObserverPolicyName = file, sha, hash([]byte(role.Account)), role.PolicyName
		} else {
			i := byPurpose[purpose] - 1
			if i < 0 {
				return zero, install.ErrInstall
			}
			d.Grant.Principals[i].AccountSHA256, d.Grant.Principals[i].PolicyName = hash([]byte(role.Account)), role.PolicyName
			bucket, path, staging := target.Bucket, target.Root, target.RemoteStagingRoot
			if purpose == "catalog_read" || purpose == "catalog_append" {
				bucket, path, staging = catalog.Bucket, catalog.Root, ""
			}
			uses = append(uses, minioPermissionUse{principal: minioPermissionPrincipal{Purpose: purpose}, bucket: bucket, root: path, staging: staging})
		}
		switch purpose {
		case "artifact_read":
			target.ReadCredentialFile, target.ReadCredentialSHA256 = file, sha
		case "artifact_write":
			target.WriteCredentialFile, target.WriteCredentialSHA256 = file, sha
		case "artifact_delete":
			target.DeleteCredentialFile, target.DeleteCredentialSHA256 = file, sha
		case "catalog_read":
			catalog.ReadCredentialFile, catalog.ReadCredentialSHA256 = file, sha
		case "catalog_append":
			catalog.AppendCredentialFile, catalog.AppendCredentialSHA256 = file, sha
		}
		materials.Roles = append(materials.Roles, role)
	}
	for i := range materials.Roles {
		r := &materials.Roles[i]
		var rules []minioPermissionRule
		if r.Purpose == "observer" {
			rules = minioPermissionObserverRulesV2(uses)
		} else {
			for _, u := range uses {
				if u.principal.Purpose == r.Purpose {
					rules, e = minioPermissionObjectRulesV2(r.Purpose, u.bucket, u.root, u.staging)
				}
			}
		}
		if e != nil {
			return zero, e
		}
		policy, sha, e := nativeInstallPolicy(rules)
		if e != nil {
			return zero, e
		}
		var value any
		if json.Unmarshal(policy, &value) != nil {
			return zero, install.ErrInstall
		}
		r.PolicyFile, _, e = nativeInstallSave(directory, "policies/"+r.Purpose+".json", value)
		if e != nil {
			return zero, e
		}
		r.PolicySHA256 = sha
		if r.Purpose == "observer" {
			d.ObserverPolicySHA256 = sha
		} else {
			d.Grant.Principals[byPurpose[r.Purpose]-1].PolicySHA256 = sha
		}
	}
	target.CatalogMaterialsFile, target.CatalogMaterialsSHA256, e = nativeInstallSave(directory, "catalog.materials.json", catalog)
	if e != nil {
		return zero, e
	}
	if target.validate() != nil || catalog.validate(target) != nil {
		return zero, install.ErrInstall
	}
	d.TargetFile, d.TargetSHA256, e = nativeInstallSave(directory, "target.materials.json", target)
	if e != nil {
		return zero, e
	}
	definition, e := ce.Canonical(d)
	if e != nil {
		return zero, e
	}
	if _, e = install.DecodeMinIOPermissionDefinition(definition, hash(definition)); e != nil {
		return zero, e
	}
	materials.DefinitionFile, materials.DefinitionSHA256, e = nativeInstallSave(directory, "permission.definition.json", d)
	if e != nil {
		return zero, e
	}
	// Existing concrete loader validates all generated credential/target joins.
	p, e := readMinIOPermissionProductionInputs(materials.DefinitionFile, materials.DefinitionSHA256)
	if e != nil {
		return zero, e
	}
	p.clear()
	file, sha, e := nativeInstallSave(directory, "native-install.materials.json", materials)
	if e != nil {
		return zero, e
	}
	return MinIONativeInstallOutput{file, sha, materials.DefinitionFile, materials.DefinitionSHA256}, nil
}
