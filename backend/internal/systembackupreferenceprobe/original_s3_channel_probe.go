package systembackupreferenceprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// OriginalS3ChannelPolicy describes a separate installation-only upstream.
// Generic evidence_write stays PutObject-only. ListVersions is constrained to
// the same installation prefix, HEAD uses GetObjectVersion on that prefix.
func OriginalS3ChannelPolicy(c S3Profile) ([]byte, error) {
	if ValidateS3Profile(c) != nil {
		return nil, ErrObservation
	}
	root := c.Evidence.Root + "/" + c.Installation + "/"
	statements := []map[string]any{
		{"Action": []string{"s3:GetBucketVersioning"}, "Effect": "Allow", "Resource": []string{"arn:aws:s3:::" + c.Evidence.Bucket}},
		{"Action": []string{"s3:ListBucketVersions"}, "Effect": "Allow", "Resource": []string{"arn:aws:s3:::" + c.Evidence.Bucket}, "Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": []string{root + "*"}}}},
		{"Action": []string{"s3:GetObjectVersion", "s3:PutObject"}, "Effect": "Allow", "Resource": []string{"arn:aws:s3:::" + c.Evidence.Bucket + "/" + root + "*"}},
	}
	sort.Slice(statements, func(i, j int) bool {
		a, _ := ce.Canonical(statements[i])
		b, _ := ce.Canonical(statements[j])
		return bytes.Compare(a, b) < 0
	})
	return ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
}

func originalChannelNormalized(raw []byte) ([]byte, error) {
	if minioPermissionUniqueJSON(raw) != nil {
		return nil, ErrObservation
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || len(doc) != 2 || doc["Version"] == nil || doc["Statement"] == nil {
		return nil, ErrObservation
	}
	var statements []map[string]json.RawMessage
	if json.Unmarshal(doc["Statement"], &statements) != nil || len(statements) != 3 {
		return nil, ErrObservation
	}
	stable := []json.RawMessage{}
	for _, st := range statements {
		for _, key := range []string{"Action", "Resource"} {
			v, e := minioPermissionStrings(st[key])
			if e != nil {
				return nil, e
			}
			sort.Strings(v)
			st[key], e = ce.Canonical(v)
			if e != nil {
				return nil, e
			}
		}
		if condition, ok := st["Condition"]; ok {
			var m map[string]map[string]json.RawMessage
			if json.Unmarshal(condition, &m) != nil || len(m) != 1 || len(m["StringLike"]) != 1 {
				return nil, ErrObservation
			}
			v, e := minioPermissionStrings(m["StringLike"]["s3:prefix"])
			if e != nil {
				return nil, e
			}
			sort.Strings(v)
			st["Condition"], e = ce.Canonical(map[string]any{"StringLike": map[string]any{"s3:prefix": v}})
			if e != nil {
				return nil, e
			}
		}
		b, e := ce.Canonical(st)
		if e != nil {
			return nil, e
		}
		stable = append(stable, b)
	}
	sort.Slice(stable, func(i, j int) bool { return bytes.Compare(stable[i], stable[j]) < 0 })
	doc["Statement"], _ = ce.Canonical(stable)
	return ce.Canonical(doc)
}

// ObserveOriginalS3Channel checks actual named user/policy AND effective-self
// policy, including the exact prefix condition, plus a real admin denial.
func ObserveOriginalS3Channel(ctx context.Context, c S3Profile, p Principal) error {
	if p.Purpose != "c1_channel_upstream" || ValidateS3Profile(c) != nil || !name.MatchString(p.PolicyName) {
		return ErrObservation
	}
	want, e := OriginalS3ChannelPolicy(c)
	if e != nil || hash(want) != p.PolicySHA256 {
		return ErrObservation
	}
	for _, other := range append([]Principal{c.Observer}, c.Principals...) {
		if other.AccountSHA256 == p.AccountSHA256 || other.Credential.File == p.Credential.File {
			return ErrObservation
		}
	}
	observer, e := credential(c.Observer.Credential)
	if e != nil {
		return e
	}
	key, e := credential(p.Credential)
	if e != nil || hash([]byte(key.AccessKey)) != p.AccountSHA256 || time.Now().Before(key.NotBefore) || !time.Now().Before(key.Until) {
		return ErrObservation
	}
	r, e := newMinioPermissionHTTP(c.Provider, observer)
	if e != nil {
		return e
	}
	defer r.close()
	raw, status, e := r.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {key.AccessKey}})
	var user struct {
		AuthInfo *struct {
			Type             string `json:"type"`
			AuthServer       string `json:"authServer"`
			AuthServerUserID string `json:"authServerUserID"`
		} `json:"userAuthInfo,omitempty"`
		SecretKey  string    `json:"secretKey,omitempty"`
		PolicyName string    `json:"policyName,omitempty"`
		Status     string    `json:"status"`
		MemberOf   []string  `json:"memberOf,omitempty"`
		UpdatedAt  time.Time `json:"updatedAt,omitempty"`
	}
	if e != nil || status != 200 || minioPermissionDecode(raw, &user) != nil || user.SecretKey != "" || user.Status != "enabled" || user.PolicyName != p.PolicyName || len(user.MemberOf) != 0 || user.UpdatedAt.IsZero() || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != key.AccessKey) {
		return ErrObservation
	}
	raw, status, e = r.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {p.PolicyName}, "v": {"2"}})
	var policy struct {
		PolicyName             string
		Policy                 json.RawMessage
		CreateDate, UpdateDate time.Time
	}
	if e != nil || status != 200 || minioPermissionDecode(raw, &policy) != nil || policy.PolicyName != p.PolicyName || policy.UpdateDate.IsZero() {
		return ErrObservation
	}
	normal, e := originalChannelNormalized(policy.Policy)
	if e != nil || !bytes.Equal(normal, want) {
		return ErrObservation
	}
	self, e := newMinioPermissionHTTP(c.Provider, key)
	if e != nil {
		return e
	}
	defer self.close()
	raw, status, e = self.get(ctx, "/minio/admin/v3/accountinfo", nil)
	var account struct {
		AccountName             string
		Server, Policy, Buckets json.RawMessage
	}
	if e != nil || status != 200 || minioPermissionDecode(raw, &account) != nil || account.AccountName != key.AccessKey || len(account.Server) == 0 {
		return ErrObservation
	}
	normal, e = originalChannelNormalized(account.Policy)
	if e != nil || !bytes.Equal(normal, want) {
		return ErrObservation
	}
	raw, status, e = self.get(ctx, minioEffectiveOwnerGuardPath, url.Values{"subSys": {"policy_plugin"}, "key": {""}})
	if e != nil || status != 403 || minioEffectiveAdminAccessDenied(raw) != nil {
		return ErrObservation
	}
	return nil
}

type originalS3Reply struct {
	body    []byte
	status  int
	version string
}

func originalS3Request(ctx context.Context, r *minioPermissionHTTP, method, path string, q url.Values, body []byte, headers http.Header) (originalS3Reply, error) {
	if ctx == nil || ctx.Err() != nil || time.Now().Before(r.credential.NotBefore) || !time.Now().Before(r.credential.Until) {
		return originalS3Reply{}, ErrObservation
	}
	ctx, cancel := context.WithDeadline(ctx, r.credential.Until)
	defer cancel()
	u, e := url.Parse(r.provider.Endpoint)
	if e != nil {
		return originalS3Reply{}, ErrObservation
	}
	u.Path = path
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return originalS3Reply{}, e
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	req.Header.Set("X-Amz-Content-Sha256", hash(body))
	req = signer.SignV4(*req, r.credential.AccessKey, r.credential.SecretKey, "", r.provider.Region)
	response, e := r.client.Do(req)
	if e != nil {
		return originalS3Reply{}, ErrObservation
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return originalS3Reply{}, ErrObservation
	}
	return originalS3Reply{raw, response.StatusCode, response.Header.Get("X-Amz-Version-Id")}, nil
}
func originalS3Denied(r originalS3Reply) bool {
	var problem struct {
		XMLName xml.Name
		Code    string
	}
	return r.status == 403 && xml.Unmarshal(r.body, &problem) == nil && problem.XMLName.Local == "Error" && problem.Code == "AccessDenied"
}

// VerifyOriginalS3NativeOperations exercises actual PUT, versioned GET/HEAD,
// version DELETE, ListVersions and versioning, and wrong-role/outside-prefix
// denials. Cleanup deletes only exact random keys/versions created here. Root
// is used only to clean these exact probe versions, never as an evidence principal.
func VerifyOriginalS3NativeOperations(ctx context.Context, c S3Profile, channel Principal, rootPin FilePin) (resultErr error) {
	if ObserveOriginalS3Channel(ctx, c, channel) != nil {
		return ErrObservation
	}
	clients := map[string]*minioPermissionHTTP{}
	defer func() {
		for _, r := range clients {
			r.close()
		}
	}()
	for _, p := range append(append([]Principal{c.Observer}, c.Principals...), channel) {
		key, e := credential(p.Credential)
		if e != nil {
			return e
		}
		r, e := newMinioPermissionHTTP(c.Provider, key)
		if e != nil {
			return e
		}
		clients[p.Purpose] = r
	}
	defer func() {
		for _, r := range clients {
			r.close()
		}
	}()
	raw, e := ReadPinned(rootPin, 16384)
	if e != nil {
		return e
	}
	defer clear(raw)
	var root OriginalS3OwnerCredential
	if minioPermissionDecode(raw, &root) != nil {
		return ErrObservation
	}
	defer clear(root.SecretKey)
	owner, e := newMinioPermissionHTTP(c.Provider, nativePublicationCredential{AccessKey: root.AccessKey, SecretKey: string(root.SecretKey), NotBefore: root.NotBefore, Until: root.Until})
	if e != nil {
		return e
	}
	defer owner.close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	suffix := ".original-c1-probe-" + hex.EncodeToString(nonce[:])
	type cleanupObject struct{ bucket, key, version string }
	created := []cleanupObject{}
	defer func() {
		for _, o := range created {
			r, e := originalS3Request(ctx, owner, http.MethodDelete, "/"+o.bucket+"/"+o.key, url.Values{"versionId": {o.version}}, nil, nil)
			if e != nil || r.status != 204 {
				resultErr = ErrObservation
			}
		}
	}()
	deniedPut := func(purpose, bucket, key string) error {
		r, e := originalS3Request(ctx, clients[purpose], http.MethodPut, "/"+bucket+"/"+key, nil, []byte("original-c1-forbidden-probe"), http.Header{"If-None-Match": {"*"}})
		if e == nil && r.status == 200 && r.version != "" && r.version != "null" {
			created = append(created, cleanupObject{bucket, key, r.version})
		}
		if e != nil || !originalS3Denied(r) {
			return ErrObservation
		}
		return nil
	}
	payload := []byte("original-c1-native-permission-probe.v1")
	put := func(purpose, bucket, key string) (string, error) {
		r, e := originalS3Request(ctx, clients[purpose], http.MethodPut, "/"+bucket+"/"+key, nil, payload, http.Header{"If-None-Match": {"*"}})
		if e != nil || r.status != 200 || r.version == "" || r.version == "null" {
			return "", ErrObservation
		}
		created = append(created, cleanupObject{bucket, key, r.version})
		return r.version, nil
	}
	evidenceKey := c.Evidence.Root + "/" + c.Installation + "/" + suffix
	version, e := put("evidence_write", c.Evidence.Bucket, evidenceKey)
	if e != nil {
		return e
	}
	r, e := originalS3Request(ctx, clients["evidence_read"], http.MethodGet, "/"+c.Evidence.Bucket+"/"+evidenceKey, url.Values{"versionId": {version}}, nil, nil)
	if e != nil || r.status != 200 || !bytes.Equal(r.body, payload) {
		return ErrObservation
	}
	for _, purpose := range []string{"artifact_upload_issuer", "evidence_write", "evidence_delete", "metadata_observer"} {
		r, e := originalS3Request(ctx, clients[purpose], http.MethodGet, "/"+c.Evidence.Bucket+"/"+evidenceKey, url.Values{"versionId": {version}}, nil, nil)
		if e != nil || !originalS3Denied(r) {
			return ErrObservation
		}
	}
	for _, purpose := range []string{"evidence_read", "evidence_delete", "metadata_observer"} {
		if deniedPut(purpose, c.Evidence.Bucket, evidenceKey+"-forbidden") != nil {
			return ErrObservation
		}
	}
	if _, e = put("artifact_upload_issuer", c.UploadBucket, c.UploadRoot+suffix); e != nil {
		return e
	}
	if _, e = put("artifact_upload_issuer", c.UploadBucket, c.UploadStagingRoot+suffix); e != nil {
		return e
	}
	channelKey := evidenceKey + "-channel"
	r, e = originalS3Request(ctx, clients["c1_channel_upstream"], http.MethodGet, "/"+c.Evidence.Bucket, url.Values{"versioning": {""}}, nil, nil)
	var vc struct {
		XMLName xml.Name
		Status  string
	}
	if e != nil || r.status != 200 || xml.Unmarshal(r.body, &vc) != nil || vc.XMLName.Local != "VersioningConfiguration" || vc.Status != "Enabled" {
		return ErrObservation
	}
	r, e = originalS3Request(ctx, clients["c1_channel_upstream"], http.MethodGet, "/"+c.Evidence.Bucket, url.Values{"versions": {""}, "prefix": {channelKey}, "max-keys": {"1"}}, nil, nil)
	var listing struct {
		XMLName      xml.Name
		Name, Prefix string
		IsTruncated  *bool
		Versions     []struct{ Key string } `xml:"Version"`
		Markers      []struct{ Key string } `xml:"DeleteMarker"`
	}
	if e != nil || r.status != 200 || xml.Unmarshal(r.body, &listing) != nil || listing.XMLName.Local != "ListVersionsResult" || listing.Name != c.Evidence.Bucket || listing.Prefix != channelKey || listing.IsTruncated == nil || *listing.IsTruncated || len(listing.Versions) != 0 || len(listing.Markers) != 0 {
		return ErrObservation
	}
	channelVersion, e := put("c1_channel_upstream", c.Evidence.Bucket, channelKey)
	if e != nil {
		return e
	}
	r, e = originalS3Request(ctx, clients["c1_channel_upstream"], http.MethodHead, "/"+c.Evidence.Bucket+"/"+channelKey, url.Values{"versionId": {channelVersion}}, nil, nil)
	if e != nil || r.status != 200 || r.version != channelVersion {
		return ErrObservation
	}
	for _, purpose := range []string{"artifact_upload_issuer", "evidence_read", "evidence_write", "evidence_delete"} {
		r, e = originalS3Request(ctx, clients[purpose], http.MethodGet, "/"+c.Evidence.Bucket, url.Values{"versioning": {""}}, nil, nil)
		if e != nil || !originalS3Denied(r) {
			return ErrObservation
		}
	}
	r, e = originalS3Request(ctx, clients["c1_channel_upstream"], http.MethodGet, "/"+c.Evidence.Bucket, url.Values{"versions": {""}, "prefix": {"outside-" + suffix}, "max-keys": {"1"}}, nil, nil)
	if e != nil || !originalS3Denied(r) {
		return ErrObservation
	}
	if deniedPut("c1_channel_upstream", c.Evidence.Bucket, "outside-"+suffix) != nil {
		return ErrObservation
	}
	r, e = originalS3Request(ctx, clients["evidence_delete"], http.MethodDelete, "/"+c.Evidence.Bucket+"/"+evidenceKey, url.Values{"versionId": {version}}, nil, nil)
	if e != nil || r.status != 204 {
		return ErrObservation
	}
	// Remove this exact version from root cleanup after the real delete passes.
	for n, o := range created {
		if o.bucket == c.Evidence.Bucket && o.key == evidenceKey && o.version == version {
			created = append(created[:n], created[n+1:]...)
			break
		}
	}
	return nil
}

// Uppercase transport used by the existing OriginalC1ChannelInputs consumer.
func OriginalS3ChannelCredentials(raw []byte) ([]byte, error) {
	var c nativePublicationCredential
	if minioPermissionDecode(raw, &c) != nil || c.SessionToken != "" || strings.TrimSpace(c.AccessKey) != c.AccessKey || len(c.SecretKey) < 16 {
		return nil, ErrObservation
	}
	return ce.Canonical(struct{ AccessKey, SecretKey string }{c.AccessKey, c.SecretKey})
}
