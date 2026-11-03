package systembackupexecution

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestMinIONativeInstallMissingRequiresExactOriginalAdminError(t *testing.T) {
	path := "/minio/admin/v3/user-info"
	base := map[string]string{"Code": "XMinioAdminNoSuchUser", "Message": "The specified user does not exist", "Resource": path, "Region": "us-east-1", "RequestId": "original-request", "HostId": "original-server"}
	encode := func(value map[string]string) []byte { raw, _ := json.Marshal(value); return raw }
	if !nativeInstallMissing(encode(base), 404, base["Code"], path, "us-east-1") {
		t.Fatal("exact original missing response refused")
	}
	for key, value := range map[string]string{"Code": "AccessDenied", "Resource": "/foreign", "Region": "foreign", "RequestId": "", "HostId": "", "Key": "foreign", "BucketName": "foreign", "NextToken": "foreign"} {
		copy := map[string]string{}
		for k, v := range base {
			copy[k] = v
		}
		copy[key] = value
		if nativeInstallMissing(encode(copy), 404, base["Code"], path, "us-east-1") {
			t.Fatal("ambiguous response admitted creation", key)
		}
	}
	if nativeInstallMissing(encode(base), 403, base["Code"], path, "us-east-1") || nativeInstallMissing(append(encode(base), []byte(" {}")...), 404, base["Code"], path, "us-east-1") {
		t.Fatal("nonmissing or trailing response admitted creation")
	}
}

func TestMinIONativeInstallGeneratesSixPrivateFiniteOriginalMaterials(t *testing.T) {
	f := newMinioSeptemberTerminalComponent(t, "")
	directory := firstInstallPrivateDirectory(t)
	before := f.requests.Load()
	result, e := GenerateOriginalMinIONativeMaterials(f.input.DefinitionFile, f.input.DefinitionSHA256, directory)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := pinnedDeploymentFile(result.File, result.SHA256, 262144)
	var m MinIONativeInstallMaterials
	if e != nil || decodePublicationCanonical(raw, &m) != nil || len(m.Roles) != 6 || f.requests.Load() != before {
		t.Fatal("generation performed native I/O or lost roles", e)
	}
	accounts, policies := map[string]bool{}, map[string]bool{}
	for _, role := range m.Roles {
		if accounts[role.Account] || policies[role.PolicyName] {
			t.Fatal("aliased native principal")
		}
		accounts[role.Account], policies[role.PolicyName] = true, true
		st, e := os.Lstat(role.CredentialFile)
		if e != nil || !st.Mode().IsRegular() {
			t.Fatal("private credential missing", e)
		}
	}
	p, e := readMinIOPermissionProductionInputs(result.DefinitionFile, result.DefinitionSHA256)
	if e != nil {
		t.Fatal(e)
	}
	p.clear()
	if _, e = GenerateOriginalMinIONativeMaterials(f.input.DefinitionFile, f.input.DefinitionSHA256, directory); e == nil {
		t.Fatal("original generated credentials overwritten")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if receipt, e := ApplyOriginalMinIONativeMaterials(ctx, nil, f.kube, nil, install.EnrollmentPin{}, result.File, result.SHA256, MinIONativeAdminFiles{}); e == nil || receipt.NativeWritesAttempted || f.requests.Load() != before {
		t.Fatal("native setup bypassed actual original owner authentication")
	}
}
