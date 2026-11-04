package systembackupexecution

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Maintenance has admin permissions but is still a genuine independent
// builtin user. Its legitimate ConfigUpdate permission is not a root bypass.
func sourceGateOwnUser(ctx context.Context, n *minioPermissionHTTP, c sb.MinIOGateCredential) (bool, error) {
	path := "/minio/admin/v3/user-info"
	raw, status, e := n.get(ctx, path, url.Values{"accessKey": {c.AccessKey}})
	if e != nil {
		return false, e
	}
	if nativeInstallMissing(raw, status, "XMinioAdminNoSuchUser", path, n.provider.Region) {
		return false, nil
	}
	var user struct {
		SecretKey, PolicyName, Status string
		MemberOf                      []string
		UpdatedAt                     time.Time
		AuthInfo                      *struct{ Type, AuthServer, AuthServerUserID string } `json:"userAuthInfo,omitempty"`
	}
	if status != 200 || minioPermissionDecode(raw, &user) != nil || user.SecretKey != "" || user.Status != "enabled" || len(user.MemberOf) != 0 || user.PolicyName != "" && user.PolicyName != c.AccessKey || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != c.AccessKey) || c.AccessKey == n.credential.AccessKey {
		return false, install.ErrInstall
	}
	self, e := newMinioPermissionHTTP(n.provider, nativePublicationCredential{AccessKey: c.AccessKey, SecretKey: string(c.SecretKey), NotBefore: c.NotBefore, Until: c.Until})
	if e != nil {
		return false, e
	}
	defer self.close()
	raw, status, e = self.get(ctx, "/minio/admin/v3/accountinfo", nil)
	if e != nil {
		return false, e
	}
	if status == 200 {
		var a struct {
			AccountName             string
			Server, Policy, Buckets json.RawMessage
		}
		if minioPermissionDecode(raw, &a) != nil || a.AccountName != c.AccessKey {
			return false, install.ErrInstall
		}
		return true, nil
	}
	// An unbound new user can lack accountinfo permission. Native IAM denial
	// after signature validation differs from bad signature/disabled/missing.
	var denied map[string]json.RawMessage
	if status != 403 || minioPermissionUniqueJSON(raw) != nil || json.Unmarshal(raw, &denied) != nil {
		return false, install.ErrInstall
	}
	var code, resource, id string
	_ = json.Unmarshal(denied["Code"], &code)
	_ = json.Unmarshal(denied["Resource"], &resource)
	_ = json.Unmarshal(denied["RequestId"], &id)
	if code != "AccessDenied" || resource != "/minio/admin/v3/accountinfo" || id == "" {
		return false, install.ErrInstall
	}
	return true, nil
}
