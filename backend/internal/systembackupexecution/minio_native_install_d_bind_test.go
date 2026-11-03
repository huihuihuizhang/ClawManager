package systembackupexecution

import (
	ce "clawreef/internal/systembackupcontrolevidence"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMinIONativeInstallBindDUsesExactSameSixCredentialBytes(t *testing.T) {
	f := newMinioSeptemberTerminalComponent(t, "")
	p, e := readMinIOPermissionProductionInputs(f.input.DefinitionFile, f.input.DefinitionSHA256)
	if e != nil {
		t.Fatal(e)
	}
	defer p.clear()
	source := firstInstallPrivateDirectory(t)
	output := firstInstallPrivateDirectory(t)
	write := func(name string, value any) (string, string) {
		raw, e := ce.Canonical(value)
		if e != nil {
			t.Fatal(e)
		}
		file := filepath.Join(source, name)
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return file, hash(raw)
	}
	_, bundleSHA := write("bundle.json", map[string]string{"version": "first-page-minio-tls.v1"})
	accounts := []map[string]any{}
	expected := map[string]string{}
	uses := append([]minioPermissionUse(nil), p.uses...)
	uses = append(uses, minioPermissionUse{principal: minioPermissionPrincipal{Purpose: "observer"}, credential: p.observer})
	for _, use := range uses {
		purpose := use.principal.Purpose
		_, sha := write(purpose+".credential.json", map[string]string{"access_key": use.credential.AccessKey, "secret_key": use.credential.SecretKey, "session_token": "", "not_before": p.grant.NotBefore.Add(-time.Second).Format("2006-01-02T15:04:05.000000Z"), "until": p.grant.Until.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")})
		expected[purpose] = sha
		accounts = append(accounts, map[string]any{"purpose": purpose, "account_sha256": hash([]byte(use.credential.AccessKey)), "credential_file_sha256": sha, "provisioned": false})
	}
	receiptFile, receiptSHA := write("receipt.json", map[string]any{"status": "prepared_local_only", "namespace_uid": p.grant.NamespaceUID, "ca_sha256": p.grant.Provider.CASHA256, "server_spki_sha256": p.grant.Provider.SPKISHA256, "server_leaf_sha256": hash([]byte("fixture-leaf")), "app_image": "fixture@sha256:" + hash([]byte("fixture-image")), "bundle_sha256": bundleSHA, "accounts": accounts, "native_permission_observed": false, "mysql_rotated": false, "cluster_mutated": false})
	before := f.requests.Load()
	result, e := BindDPreparedMinIONativeMaterials(f.input.DefinitionFile, f.input.DefinitionSHA256, receiptFile, receiptSHA, output)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := pinnedDeploymentFile(result.File, result.SHA256, 262144)
	var materials MinIONativeInstallMaterials
	if e != nil || decodePublicationCanonical(raw, &materials) != nil || len(materials.Roles) != 6 || f.requests.Load() != before {
		t.Fatal("D binding lost six roles or performed native I/O", e)
	}
	for _, role := range materials.Roles {
		if role.CredentialSHA256 != expected[role.Purpose] {
			t.Fatal("D credential bytes were changed/regenerated")
		}
	}
}
