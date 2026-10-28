package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// S3WebIdentityAuthority authenticates the current task, GC worker or download
// session and resolves the registered evidence/claim/config on EVERY call.
// It supplies an owned OIDC token, not static S3 keys. Echoing the input Scope
// is not authorization. SQLTaskAuthority implements the job-log publish path;
// download and GC require separate session/worker authorities.
type S3WebIdentityAuthority interface {
	AuthorizeS3(context.Context, S3Scope) (S3WebIdentityGrant, error)
}

type S3Authorization struct {
	Scope                             S3Scope
	Evidence                          Identity
	ConfigVersion                     int64
	AccessKind                        string // task, download, gc, recovery
	AttemptNumber                     int64  // positive for task; zero for other kinds
	PrincipalHash, LeaseHash, Subject string
	ExpiresAt                         time.Time // current task/claim/session/revocation deadline
}

type S3WebIdentityGrant struct {
	Authorization  S3Authorization
	Token          []byte // owned copy, erased even on denial
	TokenExpiresAt time.Time
}

// S3STSConfig pins an AWS-query-compatible STS/OIDC profile. Store is the SAME
// admitted mapping used by S3Store; arbitrary caller endpoints/policies are not
// accepted. Providers must enforce the generated IAM policy (including dates,
// version IDs, explicit denies and conditional writes) before deployment.
type S3STSConfig struct {
	Store                               S3Config
	Endpoint, RoleARN, Issuer, Audience string
	CAPEM                               []byte
	CASHA256                            string
}

type S3STSCredentials struct {
	config                       S3STSConfig
	client                       *http.Client
	authority                    S3WebIdentityAuthority
	partition, account, roleName string
}

var _ S3Credentials = (*S3STSCredentials)(nil)
var stsRole = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@/-]{1,512})$`)

const stsNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"

func stsEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.Opaque == "" && !strings.ContainsAny(raw, "?#\r\n")
}

func NewS3STSCredentials(c S3STSConfig, a S3WebIdentityAuthority) (*S3STSCredentials, error) {
	if nilSystemAdapter(a) {
		return nil, ErrInvalid
	}
	s, err := newS3STSTransport(c)
	if err != nil {
		return nil, err
	}
	s.authority = a
	return s, nil
}

// Shared wire transport, never an authorization bypass exposed to callers.
// Task and system adapters each validate their own complete authorization.
func newS3STSTransport(c S3STSConfig) (*S3STSCredentials, error) {
	s := c.Store
	role := stsRole.FindStringSubmatch(c.RoleARN)
	issuer, err := url.Parse(c.Issuer)
	if !stsEndpoint(c.Endpoint) || !stsEndpoint(s.Endpoint) || len(role) != 4 ||
		err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.Opaque != "" || strings.ContainsAny(c.Issuer, "?#\r\n") || len(c.Issuer) > 2048 ||
		!s3Token([]byte(c.Audience), 1, 255) ||
		!installationPattern.MatchString(s.Installation) || !digestPattern.MatchString(s.Identity) || !versionPattern.MatchString(s.Version) || !safeKey(s.Root) ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(s.Bucket) || strings.Contains(s.Bucket, "..") ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(s.Region) ||
		len(c.CAPEM) > 65536 || !digestPattern.MatchString(c.CASHA256) || hash(c.CAPEM) != c.CASHA256 ||
		len(s.CAPEM) > 65536 || !digestPattern.MatchString(s.CASHA256) || hash(s.CAPEM) != s.CASHA256 {
		return nil, ErrInvalid
	}
	roots, dataRoots := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) || !dataRoots.AppendCertsFromPEM(s.CAPEM) {
		return nil, ErrInvalid
	}
	roleParts := strings.Split(role[3], "/")
	for _, part := range roleParts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrInvalid
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384,
		DisableCompression: true, DisableKeepAlives: true}
	c.CAPEM = nil
	c.Store.CAPEM = nil
	return &S3STSCredentials{config: c, partition: role[1], account: role[2], roleName: roleParts[len(roleParts)-1],
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (s *S3STSCredentials) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}

func (s *S3STSCredentials) validScope(v S3Scope) bool {
	c := s.config.Store
	if !v.Ref.valid(false) || v.Ref.Identity != c.Identity || v.Ref.Version != c.Version ||
		!strings.HasPrefix(v.Ref.RelativeKey, c.Root+"/"+c.Installation+"/") || v.Ref.ImmutableVersion != "" && !s3Version(v.Ref.ImmutableVersion) || strings.Contains(v.Ref.ImmutableVersion, "${") {
		return false
	}
	empty := ObjectInfo{}
	switch v.Operation {
	case S3Stat:
		return v.Object == empty && v.Offset == 0 && v.Length == 0 && v.Deadline.IsZero()
	case S3Range:
		return v.Ref.ImmutableVersion != "" && v.Object == empty && v.Offset >= 0 && v.Length > 0 && v.Length <= ChunkSize+28 && v.Offset <= maxS3EvidenceObject-v.Length && v.Deadline.IsZero()
	case S3Put, S3Delete:
		return v.Offset == 0 && v.Length == 0 && digestPattern.MatchString(v.Object.SHA256) && v.Object.Size > 0 && v.Object.Size <= maxS3EvidenceObject &&
			(v.Operation == S3Put && v.Ref.ImmutableVersion == "" && v.Object.Version == "" && time.Now().Before(v.Deadline) ||
				v.Operation == S3Delete && v.Ref.ImmutableVersion != "" && v.Object.Version == v.Ref.ImmutableVersion && v.Deadline.IsZero())
	default:
		return false
	}
}

func (s *S3STSCredentials) validGrant(g S3WebIdentityGrant, scope S3Scope) bool {
	a := g.Authorization
	now := time.Now()
	key, err := keyFor(s.config.Store.Root, a.Evidence)
	return err == nil && key == scope.Ref.RelativeKey && a.Evidence.Installation == s.config.Store.Installation && a.Scope == scope &&
		a.ConfigVersion > 0 && oneOf(a.AccessKind, "task", "download", "gc", "recovery") &&
		(a.AccessKind == "task" && a.AttemptNumber > 0 || a.AccessKind != "task" && a.AttemptNumber == 0) &&
		(a.AccessKind != "download" || oneOf(string(scope.Operation), string(S3Stat), string(S3Range))) &&
		(a.AccessKind != "gc" || oneOf(string(scope.Operation), string(S3Stat), string(S3Delete))) &&
		(a.AccessKind != "recovery" || scope.Operation == S3Stat && scope.Ref.ImmutableVersion == "") &&
		(a.AccessKind != "task" || scope.Operation != S3Delete) &&
		digestPattern.MatchString(a.PrincipalHash) && digestPattern.MatchString(a.LeaseHash) && s3Token([]byte(a.Subject), 6, 255) &&
		now.Before(a.ExpiresAt) && now.Before(g.TokenExpiresAt) && s3Token(g.Token, 4, 20000)
}

// Session credentials last 900s (the STS minimum), but provider access is
// explicitly denied after a <=60s authorization window. Credential expiration
// is NOT shortened fictionally: returned ExpiresAt is the policy deadline.
// Range/checksum/length remain signed client constraints, not IAM constraints.
func (s *S3STSCredentials) policy(v S3Scope, until time.Time) ([]byte, error) {
	resource := "arn:" + s.partition + ":s3:::" + s.config.Store.Bucket + "/" + v.Ref.RelativeKey
	action := "s3:GetObject"
	if v.Ref.ImmutableVersion != "" {
		action = "s3:GetObjectVersion"
	}
	if v.Operation == S3Put {
		action = "s3:PutObject"
	}
	if v.Operation == S3Delete {
		action = "s3:DeleteObjectVersion"
	}
	statements := []map[string]any{
		{"Effect": "Allow", "Action": action, "Resource": resource},
		{"Effect": "Deny", "NotAction": action, "Resource": "*"},
		{"Effect": "Deny", "Action": "*", "NotResource": resource},
		{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"DateGreaterThanEquals": map[string]string{"aws:CurrentTime": until.Format(time.RFC3339)}}},
		{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"BoolIfExists": map[string]string{"aws:SecureTransport": "false"}}},
	}
	if v.Ref.ImmutableVersion != "" {
		statements = append(statements, map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"StringNotEquals": map[string]string{"s3:VersionId": v.Ref.ImmutableVersion}}})
	}
	if v.Operation == S3Put {
		statements = append(statements, map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"StringNotEquals": map[string]string{"s3:if-none-match": "*"}}})
	}
	raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil || len(raw) > 2048 {
		return nil, ErrDenied
	}
	return raw, nil
}

func (s *S3STSCredentials) Resolve(ctx context.Context, scope S3Scope) (S3Credential, error) {
	if s == nil || nilSystemAdapter(s.authority) {
		return S3Credential{}, ErrDenied
	}
	return s.exchange(ctx, scope, func(ctx context.Context, scope S3Scope) (stsExchangeGrant, error) {
		g, err := s.authority.AuthorizeS3(ctx, scope)
		x := stsExchangeGrant{Token: g.Token, TokenExpiresAt: g.TokenExpiresAt}
		if err != nil || !s.validGrant(g, scope) {
			return x, ErrDenied
		}
		x.Authorization = stsExchangeAuthorization{Legacy: g.Authorization, Subject: g.Authorization.Subject, ExpiresAt: g.Authorization.ExpiresAt}
		return x, nil
	})
}

type stsExchangeAuthorization struct {
	Legacy               S3Authorization // retains the legacy path's exact comparable value
	BindingHash, Subject string
	ExpiresAt            time.Time
}
type stsExchangeGrant struct {
	Authorization  stsExchangeAuthorization
	Token          []byte
	TokenExpiresAt time.Time
}

func (s *S3STSCredentials) exchange(ctx context.Context, scope S3Scope, authorize func(context.Context, S3Scope) (stsExchangeGrant, error)) (S3Credential, error) {
	deny := func() (S3Credential, error) { return S3Credential{}, ErrDenied }
	if s == nil || s.client == nil || authorize == nil || ctx == nil || ctx.Err() != nil || !s.validScope(scope) {
		return deny()
	}
	first, err := authorize(ctx, scope)
	defer wipe(first.Token)
	if err != nil {
		return deny()
	}
	now := time.Now().UTC()
	until := now.Add(60 * time.Second)
	for _, limit := range []time.Time{first.Authorization.ExpiresAt, first.TokenExpiresAt, scope.Deadline} {
		if !limit.IsZero() && limit.Before(until) {
			until = limit
		}
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	until = until.Truncate(time.Second)
	if !until.After(now.Add(time.Second)) {
		return deny()
	}
	policy, err := s.policy(scope, until)
	if err != nil {
		return deny()
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return deny()
	}
	session := "evidence-" + hex.EncodeToString(nonce)
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {s.config.RoleARN}, "RoleSessionName": {session}, "DurationSeconds": {"900"}, "Policy": {string(policy)}, "WebIdentityToken": {string(first.Token)}}
	body := []byte(form.Encode())
	defer wipe(body)
	requestCtx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, s.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return deny()
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.client.Do(req)
	if err != nil {
		return deny()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || len(res.Header.Values("Content-Encoding")) != 0 {
		return deny()
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer wipe(raw)
	if err != nil || len(raw) > 65536 || requestCtx.Err() != nil {
		return deny()
	}
	fields, err := decodeSTS(raw)
	if err != nil {
		return deny()
	}
	cred := S3Credential{Scope: scope, AccessKey: []byte(fields["Credentials/AccessKeyId"]), SecretKey: []byte(fields["Credentials/SecretAccessKey"]), SessionToken: []byte(fields["Credentials/SessionToken"]), ExpiresAt: until}
	success := false
	defer func() {
		if !success {
			wipe(cred.AccessKey)
			wipe(cred.SecretKey)
			wipe(cred.SessionToken)
		}
	}()
	expiry, err := time.Parse(time.RFC3339Nano, fields["Credentials/Expiration"])
	if err != nil || !expiry.After(until) || expiry.After(time.Now().Add(900*time.Second)) ||
		fields["Audience"] != s.config.Audience || fields["Provider"] != s.config.Issuer || fields["SubjectFromWebIdentityToken"] != first.Authorization.Subject ||
		fields["AssumedRoleUser/Arn"] != "arn:"+s.partition+":sts::"+s.account+":assumed-role/"+s.roleName+"/"+session ||
		!strings.HasSuffix(fields["AssumedRoleUser/AssumedRoleId"], ":"+session) ||
		!s3Token([]byte(strings.TrimSuffix(fields["AssumedRoleUser/AssumedRoleId"], ":"+session)), 1, 128) ||
		!s3Token(cred.AccessKey, 3, 256) || !s3Token(cred.SecretKey, 16, 4096) || !s3Token(cred.SessionToken, 16, 16384) {
		return deny()
	}
	second, err := authorize(requestCtx, scope)
	defer wipe(second.Token)
	if err != nil || second.Authorization != first.Authorization || second.TokenExpiresAt.Before(until) || requestCtx.Err() != nil || !time.Now().Before(until) {
		return deny()
	}
	success = true
	return cred, nil
}

// Parse a bounded, closed XML tree. Reject duplicates, unknown nodes/namespaces,
// attributes, directives, comments, mixed content and trailing documents.
// Internal XML strings cannot be guaranteed erased; never include them in errors.
func decodeSTS(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrDenied
	}
	containers := map[string]bool{"AssumeRoleWithWebIdentityResponse": true, "AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult": true,
		"AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/Credentials":     true,
		"AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/AssumedRoleUser": true,
		"AssumeRoleWithWebIdentityResponse/ResponseMetadata":                                true}
	required := []string{"Credentials/AccessKeyId", "Credentials/SecretAccessKey", "Credentials/SessionToken", "Credentials/Expiration", "Audience", "Provider", "SubjectFromWebIdentityToken", "AssumedRoleUser/Arn", "AssumedRoleUser/AssumedRoleId"}
	base := "AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/"
	leaves := map[string]bool{base + "PackedPolicySize": true, base + "SourceIdentity": true, "AssumeRoleWithWebIdentityResponse/ResponseMetadata/RequestId": true}
	for _, key := range required {
		leaves[base+key] = true
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	stack := []string{}
	seen := map[string]bool{}
	values := map[string]string{}
	declaration := false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrDenied
		}
		switch v := token.(type) {
		case xml.StartElement:
			stack = append(stack, v.Name.Local)
			path := strings.Join(stack, "/")
			if v.Name.Space != stsNamespace || seen[path] || !containers[path] && !leaves[path] {
				return nil, ErrDenied
			}
			if len(v.Attr) > 1 || len(stack) != 1 && len(v.Attr) != 0 {
				return nil, ErrDenied
			}
			for _, attr := range v.Attr {
				if len(stack) != 1 || attr.Name.Space != "" || attr.Name.Local != "xmlns" || attr.Value != stsNamespace {
					return nil, ErrDenied
				}
			}
			seen[path] = true
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, ErrDenied
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			path := strings.Join(stack, "/")
			if leaves[path] {
				values[path] += string(v)
			} else if len(bytes.TrimSpace(v)) != 0 {
				return nil, ErrDenied
			}
		case xml.ProcInst:
			if declaration || len(seen) != 0 || v.Target != "xml" {
				return nil, ErrDenied
			}
			declaration = true
		default:
			return nil, ErrDenied
		}
	}
	if len(stack) != 0 {
		return nil, ErrDenied
	}
	result := map[string]string{}
	for _, key := range required {
		if values[base+key] == "" {
			return nil, ErrDenied
		}
		result[key] = values[base+key]
	}
	if seen[base+"PackedPolicySize"] {
		n, err := strconv.ParseUint(values[base+"PackedPolicySize"], 10, 8)
		if err != nil || n > 100 {
			return nil, ErrDenied
		}
	}
	return result, nil
}
