package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	mn "clawreef/internal/systembackup/minionative"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/minio/minio-go/v7/pkg/signer"
)

type nativeInstallOnceOperation struct {
	method, path string
	query        url.Values
	plain        []byte
	encrypted    bool
	observe      func(context.Context) (bool, error)
}

// This is the SAME existing native installer entry, restricted to its five
// exact original commands. No generic path/method operation is exported.
func nativeInstallWriteOnce(ctx context.Context, dir string, n *minioPermissionHTTP, input []byte, args ...string) error {
	if ctx == nil || n == nil || ctx.Err() != nil || time.Now().Before(n.credential.NotBefore) || !time.Now().Before(n.credential.Until) {
		return install.ErrInstall
	}
	ctx, stop := context.WithDeadline(ctx, n.credential.Until)
	defer stop()
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	op, e := nativeInstallOncePlan(n, input, args)
	if e != nil {
		return e
	}
	defer clear(op.plain)
	intent, e := ce.Canonical(struct{ Version, ActorSHA256, Method, Path, Query, PayloadSHA256 string }{"original-minio-native-send-once.v1", hash([]byte(n.credential.AccessKey)), op.method, op.path, op.query.Encode(), hash(op.plain)})
	if e != nil {
		return e
	}
	name := "native-send-" + hash(intent) + ".json"
	path := filepath.Join(dir, name)
	_, e = os.Lstat(path)
	pending := e == nil
	if e != nil && !os.IsNotExist(e) {
		return install.ErrInstall
	}
	if pending {
		old, e := install.ReadPrivateFile(path, 65536)
		if e != nil || !bytes.Equal(old, intent) {
			return install.ErrInstall
		}
	}
	matched, e := op.observe(ctx)
	if e != nil {
		return e
	}
	if matched {
		return nil
	}
	if pending {
		return install.ErrCommitUnknown
	}
	if _, _, e = nativeInstallSaveRaw(dir, name, intent); e != nil {
		return e
	}
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	se, ce := f.Sync(), f.Close()
	if se != nil || ce != nil {
		return install.ErrInstall
	}
	old, e := install.ReadPrivateFile(path, 65536)
	current, identityErr := os.Lstat(dir)
	if e != nil || !bytes.Equal(old, intent) || ctx.Err() != nil || identityErr != nil || !os.SameFile(st, current) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	body := op.plain
	if op.encrypted {
		body, e = mn.EncryptAdminData([]byte(n.credential.SecretKey), op.plain)
		if e != nil {
			return e
		}
		defer clear(body)
	}
	_ = nativeInstallSignedOnce(ctx, n, op.method, op.path, op.query, body)
	// A lost response is resolved ONLY from this exact target. A later call
	// with the same immutable intent can query, but never send a second time.
	matched, e = op.observe(ctx)
	if e != nil || !matched {
		return install.ErrCommitUnknown
	}
	return nil
}

func nativeInstallSignedOnce(ctx context.Context, n *minioPermissionHTTP, method, path string, query url.Values, body []byte) error {
	u, _ := url.Parse(n.provider.Endpoint)
	u.Path, u.RawQuery = path, query.Encode()
	r, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("X-Amz-Content-Sha256", hash(body))
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("Content-Type", "application/octet-stream")
	r = signer.SignV4(*r, n.credential.AccessKey, n.credential.SecretKey, "", n.provider.Region)
	response, e := mn.SendOnce(n.client, r)
	if e != nil {
		return install.ErrCommitUnknown
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	defer clear(raw)
	if e != nil || len(raw) > 1<<20 || response.ContentLength >= 0 && int64(len(raw)) != response.ContentLength || response.StatusCode < 200 || response.StatusCode >= 300 {
		return install.ErrCommitUnknown
	}
	return nil
}

func nativeInstallOncePlan(n *minioPermissionHTTP, input []byte, args []string) (nativeInstallOnceOperation, error) {
	zero := nativeInstallOnceOperation{}
	// Each exact operation has its own finite read budget; this does not reset
	// or broaden the publication observer's independent global observation.
	read := *n
	read.requests = 0
	get := read.get
	op := nativeInstallOnceOperation{method: "PUT", query: url.Values{}}
	if len(args) == 2 && args[0] == "mb" && strings.HasPrefix(args[1], "native/") || len(args) == 3 && args[0] == "version" && args[1] == "enable" && strings.HasPrefix(args[2], "native/") {
		bucket := strings.TrimPrefix(args[len(args)-1], "native/")
		if !minioPermissionName(bucket) || strings.ContainsAny(bucket, "/\\*?:") {
			return zero, install.ErrInstall
		}
		op.path = "/" + bucket
		version := args[0] == "version"
		if version {
			op.query.Set("versioning", "")
			op.plain = []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
		} else if n.provider.Region != "us-east-1" {
			op.plain, _ = xml.Marshal(struct {
				XMLName  xml.Name `xml:"CreateBucketConfiguration"`
				XMLNS    string   `xml:"xmlns,attr"`
				Location string   `xml:"LocationConstraint"`
			}{XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/", Location: n.provider.Region})
		}
		op.observe = func(ctx context.Context) (bool, error) {
			raw, status, e := get(ctx, "/"+bucket, url.Values{"versioning": {""}})
			if e != nil {
				return false, e
			}
			if minioTerminalError(minioTerminalReply{status: status, body: raw}, 404, "NoSuchBucket", "", n.provider.Region) {
				return false, nil
			}
			var v struct {
				XMLName xml.Name `xml:"VersioningConfiguration"`
				Status  string   `xml:"Status"`
			}
			if status != 200 || xml.Unmarshal(raw, &v) != nil || v.Status != "" && v.Status != "Enabled" && v.Status != "Suspended" {
				return false, install.ErrInstall
			}
			return !version || v.Status == "Enabled", nil
		}
		return op, nil
	}
	if len(args) == 6 && strings.Join(args[:4], " ") == "admin policy create native" {
		name := args[4]
		if !minioPermissionName(name) {
			return zero, install.ErrInstall
		}
		plain, e := install.ReadPrivateFile(args[5], 65536)
		if e != nil || minioPermissionUniqueJSON(plain) != nil {
			return zero, install.ErrInstall
		}
		op.path = "/minio/admin/v3/add-canned-policy"
		op.query.Set("name", name)
		op.plain = plain
		op.observe = func(ctx context.Context) (bool, error) {
			path := "/minio/admin/v3/info-canned-policy"
			raw, status, e := get(ctx, path, url.Values{"name": {name}, "v": {"2"}})
			if e != nil {
				return false, e
			}
			if nativeInstallMissing(raw, status, "XMinioAdminNoSuchPolicy", path, n.provider.Region) {
				return false, nil
			}
			var p struct {
				PolicyName             string
				Policy                 json.RawMessage
				CreateDate, UpdateDate time.Time
			}
			if status != 200 || minioPermissionDecode(raw, &p) != nil || p.PolicyName != name || !sourceGatePolicySame(p.Policy, plain) {
				return false, install.ErrInstall
			}
			return true, nil
		}
		return op, nil
	}
	if len(args) == 4 && strings.Join(args, " ") == "admin user add native" {
		pieces := bytes.Split(input, []byte{'\n'})
		if len(pieces) != 3 || len(pieces[2]) != 0 || !minioPermissionName(string(pieces[0])) || len(pieces[1]) < 8 || bytes.ContainsAny(pieces[1], "\x00\r") {
			return zero, install.ErrInstall
		}
		name, secret := string(pieces[0]), string(pieces[1])
		op.path = "/minio/admin/v3/add-user"
		op.query.Set("accessKey", name)
		op.encrypted = true
		op.plain, _ = json.Marshal(struct {
			SecretKey string `json:"secretKey"`
			Status    string `json:"status"`
		}{secret, "enabled"})
		op.observe = func(ctx context.Context) (bool, error) { return nativeInstallOnceOwnUser(ctx, &read, name, secret) }
		return op, nil
	}
	if len(args) == 7 && strings.Join(args[:4], " ") == "admin policy attach native" && args[5] == "--user" {
		policy, user := args[4], args[6]
		if !minioPermissionName(policy) || !minioPermissionName(user) {
			return zero, install.ErrInstall
		}
		op.method = "POST"
		op.path = "/minio/admin/v3/idp/builtin/policy/attach"
		op.encrypted = true
		op.plain, _ = json.Marshal(struct {
			Policies []string `json:"policies"`
			User     string   `json:"user"`
		}{[]string{policy}, user})
		op.observe = func(ctx context.Context) (bool, error) {
			raw, status, e := get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {user}})
			var u struct {
				PolicyName, Status string
				MemberOf           []string
			}
			if e != nil || status != 200 || minioPermissionUniqueJSON(raw) != nil || json.Unmarshal(raw, &u) != nil || u.Status != "enabled" || len(u.MemberOf) != 0 || u.PolicyName != "" && u.PolicyName != policy {
				return false, install.ErrInstall
			}
			return u.PolicyName == policy, nil
		}
		return op, nil
	}
	return zero, install.ErrInstall
}

func nativeInstallOnceOwnUser(ctx context.Context, n *minioPermissionHTTP, name, secret string) (bool, error) {
	path := "/minio/admin/v3/user-info"
	raw, status, e := n.get(ctx, path, url.Values{"accessKey": {name}})
	if e != nil {
		return false, e
	}
	if nativeInstallMissing(raw, status, "XMinioAdminNoSuchUser", path, n.provider.Region) {
		return false, nil
	}
	var u struct {
		SecretKey, PolicyName, Status string
		MemberOf                      []string
		UpdatedAt                     time.Time
		AuthInfo                      *struct{ Type, AuthServer, AuthServerUserID string } `json:"userAuthInfo,omitempty"`
	}
	if status != 200 || minioPermissionDecode(raw, &u) != nil || u.SecretKey != "" || u.Status != "enabled" || len(u.MemberOf) != 0 || u.AuthInfo != nil && (u.AuthInfo.Type != "builtin" || u.AuthInfo.AuthServer != "" || u.AuthInfo.AuthServerUserID != name) || name == n.credential.AccessKey {
		return false, install.ErrInstall
	}
	self, e := newMinioPermissionHTTP(n.provider, nativePublicationCredential{AccessKey: name, SecretKey: secret, NotBefore: n.credential.NotBefore, Until: n.credential.Until})
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
		if minioPermissionDecode(raw, &a) != nil || a.AccountName != name {
			return false, install.ErrInstall
		}
		return true, nil
	}
	var denied struct {
		Code, Message, Resource string
		RequestID               string `json:"RequestId"`
		HostID                  string `json:"HostId"`
		Region                  string
	}
	if status != 403 || minioPermissionDecode(raw, &denied) != nil || denied.Code != "AccessDenied" || denied.Resource != "/minio/admin/v3/accountinfo" || denied.RequestID == "" {
		return false, install.ErrInstall
	}
	return true, nil
}
