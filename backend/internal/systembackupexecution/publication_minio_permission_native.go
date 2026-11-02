package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

type minioPermissionHTTP struct {
	client     *http.Client
	provider   minioPermissionProvider
	credential nativePublicationCredential
	requests   int
}

func newMinioPermissionHTTP(p minioPermissionProvider, credential nativePublicationCredential) (*minioPermissionHTTP, error) {
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !formalCandidateDigest(p.SPKISHA256) || p.Region == "" || credential.SessionToken != "" {
		return nil, minioPermissionFailure("native-transport-profile")
	}
	ca, err := pinnedDeploymentFile(p.CAFile, p.CASHA256, 65536)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return nil, minioPermissionFailure("native-ca")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || hash(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != p.SPKISHA256 {
			return minioPermissionFailure("native-tls-identity")
		}
		return nil
	}}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	return &minioPermissionHTTP{provider: p, credential: credential, client: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (r *minioPermissionHTTP) close() {
	r.client.CloseIdleConnections()
	r.credential = nativePublicationCredential{}
}

// No caller-supplied path/method: all invocations below are exact named GETs.
// Named admin v3 APIs are complete single replies, not list/pagination APIs.
// Unknown truncation/pagination headers are refused rather than guessed away.
func (r *minioPermissionHTTP) get(ctx context.Context, path string, query url.Values) ([]byte, int, error) {
	if ctx == nil || ctx.Err() != nil || time.Now().Before(r.credential.NotBefore) || !time.Now().Before(r.credential.Until) {
		return nil, 0, minioPermissionFailure("native-credential-window")
	}
	r.requests++
	if r.requests > 64 {
		return nil, 0, minioPermissionFailure("native-request-budget")
	}
	u, _ := url.Parse(r.provider.Endpoint)
	u.Path = path
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, minioPermissionFailure("native-request")
	}
	request.Header.Set("X-Amz-Content-Sha256", hash(nil))
	request = signer.SignV4(*request, r.credential.AccessKey, r.credential.SecretKey, "", r.provider.Region)
	response, err := r.client.Do(request)
	if err != nil {
		return nil, 0, minioPermissionFailure("native-get")
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" || response.Header.Get("X-Amz-Is-Truncated") != "" || response.Header.Get("X-Next-Token") != "" || response.Header.Get("Link") != "" {
		return nil, 0, minioPermissionFailure("native-response-profile")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.ContentLength >= 0 && int64(len(raw)) != response.ContentLength {
		return nil, 0, minioPermissionFailure("native-response-limit")
	}
	return raw, response.StatusCode, nil
}

func minioPermissionDecode(raw []byte, out any) error {
	if minioPermissionUniqueJSON(raw) != nil || decodeProviderDeploymentJSON(raw, out) != nil {
		return minioPermissionFailure("native-json")
	}
	return nil
}

func (r *minioPermissionHTTP) server(ctx context.Context) (string, error) {
	raw, status, err := r.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	if err != nil || status != http.StatusOK || minioPermissionUniqueJSON(raw) != nil {
		return "", minioPermissionFailure("native-server-info")
	}
	// Additional InfoMessage statistics are ignored, never approval inputs.
	var info struct {
		DeploymentID string `json:"deploymentID"`
		Region       string `json:"region"`
		Servers      []struct {
			State   string `json:"state"`
			Version string `json:"version"`
			Commit  string `json:"commitID"`
		} `json:"servers"`
	}
	if json.Unmarshal(raw, &info) != nil || info.DeploymentID != r.provider.DeploymentID || info.Region != r.provider.Region || len(info.Servers) != 1 {
		return "", minioPermissionFailure("native-server-identity")
	}
	for _, server := range info.Servers {
		if server.State != "ok" || server.Version != minioPermissionVersion || server.Commit != minioPermissionCommit {
			return "", minioPermissionFailure("native-version-profile")
		}
	}
	stable, _ := ce.Canonical(info)
	return hash(stable), nil
}

func (r *minioPermissionHTTP) userAndPolicy(ctx context.Context, account, policyName, policySHA string, rules []minioPermissionRule) (string, error) {
	raw, status, err := r.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {account}})
	if err != nil || status != http.StatusOK {
		return "", minioPermissionFailure("native-user-info")
	}
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
	if minioPermissionDecode(raw, &user) != nil || user.SecretKey != "" || user.Status != "enabled" || user.PolicyName != policyName || len(user.MemberOf) != 0 || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != account) || user.UpdatedAt.IsZero() {
		return "", minioPermissionFailure("native-builtin-flat-user")
	}
	// Only one exact named policy is supported; commas/extra policies refuse.
	if !minioPermissionName(policyName) {
		return "", minioPermissionFailure("native-policy-name")
	}
	policyRaw, status, err := r.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {policyName}, "v": {"2"}})
	if err != nil || status != http.StatusOK {
		return "", minioPermissionFailure("native-policy-info")
	}
	var policy struct {
		PolicyName             string
		Policy                 json.RawMessage
		CreateDate, UpdateDate time.Time
	}
	if minioPermissionDecode(policyRaw, &policy) != nil || policy.PolicyName != policyName || policy.UpdateDate.IsZero() || minioPermissionPolicy(policy.Policy, policySHA, rules) != nil {
		return "", minioPermissionFailure("native-exact-policy")
	}
	stable, _ := ce.Canonical(struct {
		User   any
		Policy any
	}{user, policy})
	return hash(stable), nil
}

func (r *minioPermissionHTTP) bucket(ctx context.Context, bucket string) (string, error) {
	if bucket == "" || strings.ContainsAny(bucket, "/\\?#\r\n") {
		return "", minioPermissionFailure("original-bucket")
	}
	raw, status, err := r.get(ctx, "/"+bucket, url.Values{"policy": {""}})
	var missing struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Bucket  string   `xml:"BucketName"`
	}
	if err != nil || status != http.StatusNotFound || len(raw) > 8192 || xml.Unmarshal(raw, &missing) != nil || missing.Code != "NoSuchBucketPolicy" || missing.Bucket != "" && missing.Bucket != bucket {
		return "", minioPermissionFailure("native-bucket-policy-profile")
	}
	raw, status, err = r.get(ctx, "/"+bucket, url.Values{"versioning": {""}})
	var version struct {
		XMLName xml.Name `xml:"VersioningConfiguration"`
		Status  string   `xml:"Status"`
		MFA     string   `xml:"MfaDelete"`
	}
	if err != nil || status != http.StatusOK || len(raw) > 8192 || xml.Unmarshal(raw, &version) != nil || version.Status != "Enabled" || version.MFA != "" && version.MFA != "Disabled" {
		return "", minioPermissionFailure("native-bucket-versioning")
	}
	return hash([]byte(bucket + "/NoSuchBucketPolicy/Enabled/" + version.MFA)), nil
}

type minioPermissionUse struct {
	principal             minioPermissionPrincipal
	credential            nativePublicationCredential
	bucket, root, staging string
}

func (r *minioPermissionHTTP) collect(ctx context.Context, cfg minioPermissionConfiguration, uses []minioPermissionUse) (string, error) {
	stamps := []string{}
	server, err := r.server(ctx)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, server)
	buckets := map[string]bool{}
	for _, use := range uses {
		buckets[use.bucket] = true
	}
	names := []string{}
	for bucket := range buckets {
		names = append(names, bucket)
	}
	sort.Strings(names)
	arns := []string{}
	for _, bucket := range names {
		arns = append(arns, "arn:aws:s3:::"+bucket)
	}
	observerRules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, arns}}
	observer, err := r.userAndPolicy(ctx, r.credential.AccessKey, cfg.ObserverPolicyName, cfg.ObserverPolicySHA256, observerRules)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, observer)
	for _, use := range uses {
		if hash([]byte(use.credential.AccessKey)) != use.principal.AccountSHA256 || use.credential.SessionToken != "" || use.credential.AccessKey == r.credential.AccessKey {
			return "", minioPermissionFailure("original-principal-account")
		}
		rules, err := minioPermissionObjectRules(use.principal.Purpose, use.bucket, use.root, use.staging)
		if err != nil {
			return "", err
		}
		stamp, err := r.userAndPolicy(ctx, use.credential.AccessKey, use.principal.PolicyName, use.principal.PolicySHA256, rules)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	for _, bucket := range names {
		stamp, err := r.bucket(ctx, bucket)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	raw, _ := ce.Canonical(stamps)
	return hash(raw), nil
}
