package systembackupreferenceprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	mn "clawreef/internal/systembackup/minionative"
	"github.com/minio/minio-go/v7/pkg/signer"
	"k8s.io/client-go/kubernetes"
)

// CreateOriginalS3Principal is restricted to this installer's fresh random
// accounts and the existing native encrypted add-user operation. Secrets stay
// in private pinned material and encrypted HTTP bodies, never process argv.
// The enclosing installer establishes original enrollment and retains intent;
// this transport requires native root and exact absence and never resends.
func CreateOriginalS3Principal(ctx context.Context, kube kubernetes.Interface, namespace, namespaceUID string, provider MinIOProvider, rootPin FilePin, p Principal) error {
	if ObserveOriginalS3OwnerTarget(ctx, kube, namespace, namespaceUID, provider, rootPin) != nil {
		return ErrObservation
	}
	key, e := credential(p.Credential)
	if e != nil || !regexp.MustCompile(`^c1_[0-9a-f]{32}_[a-f]$`).MatchString(key.AccessKey) || hash([]byte(key.AccessKey)) != p.AccountSHA256 || time.Now().Before(key.NotBefore) || !time.Now().Before(key.Until) {
		return ErrObservation
	}
	raw, e := ReadPinned(rootPin, 16384)
	if e != nil {
		return ErrObservation
	}
	defer clear(raw)
	var root OriginalS3OwnerCredential
	if minioPermissionDecode(raw, &root) != nil || root.AccessKey == key.AccessKey {
		return ErrObservation
	}
	defer clear(root.SecretKey)
	until := key.Until
	if root.Until.Before(until) {
		until = root.Until
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	native, e := newMinioPermissionHTTP(provider, nativePublicationCredential{AccessKey: root.AccessKey, SecretKey: string(root.SecretKey), NotBefore: root.NotBefore, Until: root.Until})
	if e != nil {
		return e
	}
	defer native.close()
	const userPath = "/minio/admin/v3/user-info"
	query := url.Values{"accessKey": {key.AccessKey}}
	missing, status, e := native.get(ctx, userPath, query)
	if e != nil || status != 404 || len(missing) > 8192 || minioPermissionUniqueJSON(missing) != nil {
		return ErrObservation
	}
	var fields map[string]string
	if json.Unmarshal(missing, &fields) != nil {
		return ErrObservation
	}
	allowed := map[string]bool{"Code": true, "Message": true, "Key": true, "BucketName": true, "Resource": true, "Region": true, "RequestId": true, "HostId": true}
	for name := range fields {
		if !allowed[name] {
			return ErrObservation
		}
	}
	if fields["Code"] != "XMinioAdminNoSuchUser" || fields["Message"] == "" || fields["Resource"] != userPath || fields["Key"] != "" || fields["BucketName"] != "" || fields["RequestId"] == "" || fields["HostId"] == "" || fields["Region"] != "" && fields["Region"] != provider.Region {
		return ErrObservation
	}
	plain, e := json.Marshal(struct {
		SecretKey string `json:"secretKey"`
		Status    string `json:"status"`
	}{key.SecretKey, "enabled"})
	if e != nil {
		return ErrObservation
	}
	defer clear(plain)
	body, e := mn.EncryptAdminData(root.SecretKey, plain)
	if e != nil {
		return ErrObservation
	}
	defer clear(body)
	u, e := url.Parse(provider.Endpoint)
	if e != nil {
		return ErrObservation
	}
	u.Path = "/minio/admin/v3/add-user"
	u.RawQuery = query.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if e != nil {
		return ErrObservation
	}
	req.Header.Set("X-Amz-Content-Sha256", hash(body))
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/octet-stream")
	req = signer.SignV4(*req, root.AccessKey, string(root.SecretKey), "", provider.Region)
	// Exactly one write attempt, using the already supported MinIO protocol.
	// A lost reply is checked against this exact account, never sent again.
	response, sendErr := mn.SendOnce(native.client, req)
	if response != nil {
		reply, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		response.Body.Close()
		clear(reply)
		if readErr != nil || len(reply) > 8192 {
			return ErrObservation
		}
	}
	actual, status, e := native.get(ctx, userPath, query)
	var user struct {
		SecretKey  string    `json:"secretKey,omitempty"`
		PolicyName string    `json:"policyName,omitempty"`
		Status     string    `json:"status"`
		MemberOf   []string  `json:"memberOf,omitempty"`
		UpdatedAt  time.Time `json:"updatedAt,omitempty"`
		AuthInfo   *struct {
			Type             string `json:"type"`
			AuthServer       string `json:"authServer"`
			AuthServerUserID string `json:"authServerUserID"`
		} `json:"userAuthInfo,omitempty"`
	}
	if e != nil || status != 200 || minioPermissionDecode(actual, &user) != nil || user.SecretKey != "" || user.PolicyName != "" || user.Status != "enabled" || len(user.MemberOf) != 0 || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != key.AccessKey) {
		return ErrObservation
	}
	self, e := newMinioPermissionHTTP(provider, key)
	if e != nil {
		return e
	}
	defer self.close()
	actual, status, e = self.get(ctx, "/minio/admin/v3/accountinfo", nil)
	if e != nil {
		return ErrObservation
	}
	if status == 200 {
		var account struct {
			AccountName             string
			Server, Policy, Buckets json.RawMessage
		}
		if minioPermissionDecode(actual, &account) != nil || account.AccountName != key.AccessKey {
			return ErrObservation
		}
	} else {
		var denied struct {
			Code, Message, Resource string
			RequestID               string `json:"RequestId"`
			HostID                  string `json:"HostId"`
			Region                  string
		}
		if status != 403 || minioPermissionDecode(actual, &denied) != nil || denied.Code != "AccessDenied" || denied.Resource != "/minio/admin/v3/accountinfo" || denied.RequestID == "" {
			return ErrObservation
		}
	}
	if sendErr != nil && ctx.Err() != nil {
		return ErrObservation
	}
	return nil
}
