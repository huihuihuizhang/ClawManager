package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7/pkg/s3utils"
	"github.com/minio/minio-go/v7/pkg/signer"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// OriginalC1ChannelOwner is trusted installation-process composition. Its
// upstream owner credentials NEVER leave this process or enter producer STS
// responses. The actual installer authenticates its original owner first.
// New registrations additionally require the real opaque D handle/claim.
type OriginalC1ChannelOwner struct {
	Upstream                                                                    S3Config
	AccessKey, SecretKey                                                        []byte
	Kubernetes                                                                  kubernetes.Interface
	Namespace, NamespaceUID, PodName, PodUID, ServiceAccount, ServiceAccountUID string
	Issuer, Audience, RoleARN                                                   string
}

type OriginalC1OwnerChannel struct {
	mu           sync.Mutex
	ctx          context.Context
	owner        OriginalC1ChannelOwner
	config       S3STSConfig
	providerHash string
	upstream     *http.Client
	server       *http.Server
	listener     net.Listener
	profiles     map[string]*originalC1ChannelProfile
	sessions     map[string]*originalC1ChannelCredential
	backing      *OriginalC1BackingStoreSource
	closed       bool
}

type originalC1ChannelCredential struct {
	profile       *originalC1ChannelProfile
	scope         S3Scope
	access, token string
	secret        []byte
	until, expiry time.Time
	putUsed       bool
}

func c1Random(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}

// NewOriginalC1OwnerChannel starts a REAL TLS endpoint on an exclusively owned
// loopback socket. It has no HTTP registration/approval API. Without a real
// opaque D publication claim, its STS endpoint cannot issue any credential.
// A fresh real CA/leaf is generated for this bounded owner invocation; the
// installer retains its public CA/endpoint in the signed original source.
func NewOriginalC1OwnerChannel(ctx context.Context, c OriginalC1ChannelOwner) (*OriginalC1OwnerChannel, error) {
	if ctx == nil {
		return nil, ErrDenied
	}
	until, bounded := ctx.Deadline()
	if ctx == nil || !bounded || ctx.Err() != nil || !time.Now().Before(until) || nilSystemAdapter(c.Kubernetes) || len(c.AccessKey) < 3 || len(c.SecretKey) < 16 || !stsEndpoint(c.Upstream.Endpoint) || !digestPattern.MatchString(c.Upstream.Identity) || !versionPattern.MatchString(c.Upstream.Version) || hash(c.Upstream.CAPEM) != c.Upstream.CASHA256 || !safeKey(c.Upstream.Root) || !installationPattern.MatchString(c.Upstream.Installation) || len(stsRole.FindStringSubmatch(c.RoleARN)) != 4 || c.Issuer == "" || c.Audience == "" {
		return nil, ErrDenied
	}
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(c.Upstream.CAPEM) {
		return nil, ErrDenied
	}
	c.AccessKey, c.SecretKey = bytes.Clone(c.AccessKey), bytes.Clone(c.SecretKey)
	c.Upstream.CAPEM = bytes.Clone(c.Upstream.CAPEM)
	g := &OriginalC1OwnerChannel{ctx: ctx, owner: c, profiles: map[string]*originalC1ChannelProfile{}, sessions: map[string]*originalC1ChannelCredential{}}
	g.upstream = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: root}, DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if g.currentWorkload(ctx) != nil {
		g.Close()
		return nil, ErrDenied
	}
	// Actual upstream authenticated native versioning discovery. No local
	// "versioned" or provider-healthy flag substitutes for this request.
	response, e := g.ownerRequest(ctx, http.MethodGet, "/"+c.Upstream.Bucket, url.Values{"versioning": {""}}, nil, nil)
	if e != nil {
		g.Close()
		return nil, ErrDenied
	}
	var versioning struct{ Status string }
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || readErr != nil || len(body) > 65536 || xml.Unmarshal(body, &versioning) != nil || versioning.Status != "Enabled" {
		g.Close()
		return nil, ErrDenied
	}
	backing := &OriginalC1BackingStoreSource{channel: g, store: c.Upstream, observedAt: time.Now().UTC().Truncate(time.Microsecond)}
	backing.store.CAPEM = bytes.Clone(c.Upstream.CAPEM)
	backing.origin = backing
	g.backing = backing
	certificate, ca, e := c1ChannelCertificate(until)
	if e != nil {
		g.Close()
		return nil, ErrDenied
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		g.Close()
		return nil, e
	}
	g.listener = listener
	endpoint := "https://" + listener.Addr().String()
	store := c.Upstream
	store.Endpoint = endpoint
	store.CAPEM = bytes.Clone(ca)
	store.CASHA256 = hash(ca)
	g.config = S3STSConfig{Endpoint: endpoint, CAPEM: bytes.Clone(ca), CASHA256: hash(ca), Issuer: c.Issuer, Audience: c.Audience, RoleARN: c.RoleARN, Store: store}
	g.providerHash = hash(canonical(struct {
		Version                string
		Store                  S3Config
		Issuer, Audience, Role string
		PodUID, SAUID          string
	}{"original-c1-owner-method-channel.v1", store, c.Issuer, c.Audience, c.RoleARN, c.PodUID, c.ServiceAccountUID}))
	g.server = &http.Server{Handler: g, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16384, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = g.server.Serve(tls.NewListener(listener, g.server.TLSConfig)) }()
	return g, nil
}

func c1ChannelCertificate(until time.Time) (tls.Certificate, []byte, error) {
	var zero tls.Certificate
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return zero, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if e != nil {
		return zero, nil, e
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "original-c1-installation-process-channel"}, NotBefore: now.Add(-time.Second), NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if e != nil {
		return zero, nil, e
	}
	leafPublic, leafKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return zero, nil, e
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "127.0.0.1"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, key)
	wipe(key)
	if e != nil {
		return zero, nil, e
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	wipe(leafKey)
	if e != nil {
		return zero, nil, e
	}
	defer wipe(keyDER)
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer wipe(keyPEM)
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	return cert, root, e
}

func (g *OriginalC1OwnerChannel) Config() (S3STSConfig, string) {
	c := g.config
	c.CAPEM = bytes.Clone(c.CAPEM)
	c.Store.CAPEM = bytes.Clone(c.Store.CAPEM)
	return c, g.providerHash
}
func (g *OriginalC1OwnerChannel) currentWorkload(ctx context.Context) error {
	c := g.owner
	ns, e := c.Kubernetes.CoreV1().Namespaces().Get(ctx, c.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != c.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrDenied
	}
	pod, e := c.Kubernetes.CoreV1().Pods(c.Namespace).Get(ctx, c.PodName, metav1.GetOptions{})
	if e != nil || string(pod.UID) != c.PodUID || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != c.ServiceAccount || pod.Spec.NodeName == "" || pod.Status.Phase != "Running" {
		return ErrDenied
	}
	sa, e := c.Kubernetes.CoreV1().ServiceAccounts(c.Namespace).Get(ctx, c.ServiceAccount, metav1.GetOptions{})
	if e != nil || string(sa.UID) != c.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return ErrDenied
	}
	return nil
}
func (g *OriginalC1OwnerChannel) review(ctx context.Context, token string) error {
	if g.ctx.Err() != nil || g.currentWorkload(ctx) != nil {
		return ErrDenied
	}
	c := g.owner
	review, e := c.Kubernetes.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{c.Audience}}}, metav1.CreateOptions{})
	if e != nil || !review.Status.Authenticated || review.Status.Error != "" || review.Status.User.Username != "system:serviceaccount:"+c.Namespace+":"+c.ServiceAccount || review.Status.User.UID != c.ServiceAccountUID {
		return ErrDenied
	}
	audience := false
	for _, v := range review.Status.Audiences {
		if v == c.Audience {
			audience = true
		}
	}
	uid := review.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
	name := review.Status.User.Extra["authentication.kubernetes.io/pod-name"]
	if !audience || len(uid) != 1 || uid[0] != c.PodUID || len(name) != 1 || name[0] != c.PodName {
		return ErrDenied
	}
	return nil
}

func (g *OriginalC1OwnerChannel) ownerRequest(ctx context.Context, method, path string, q url.Values, body []byte, headers http.Header) (*http.Response, error) {
	if g.ctx.Err() != nil || ctx.Err() != nil {
		return nil, ErrDenied
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, ErrDenied
	}
	access, secret := bytes.Clone(g.owner.AccessKey), bytes.Clone(g.owner.SecretKey)
	g.mu.Unlock()
	defer wipe(access)
	defer wipe(secret)

	u, e := url.Parse(g.owner.Upstream.Endpoint)
	if e != nil {
		return nil, e
	}
	u.Path = path
	u.RawQuery = q.Encode()
	request, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("X-Amz-Content-Sha256", hash(body))
	request.GetBody = nil
	request = signer.SignV4(*request, string(access), string(secret), "", g.owner.Upstream.Region)
	return g.upstream.Do(request)
}

func (g *OriginalC1OwnerChannel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.listener == nil || r.Host != g.listener.Addr().String() {
		http.Error(w, "denied", 403)
		return
	}

	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || g.ctx.Err() != nil {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/" && r.URL.RawQuery == "" {
		g.sts(w, r)
		return
	}
	g.object(w, r)
}

func (g *OriginalC1OwnerChannel) sts(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if r.ParseForm() != nil || len(r.PostForm) != 7 {
		http.Error(w, "denied", 403)
		return
	}
	for _, name := range []string{"Action", "Version", "RoleArn", "RoleSessionName", "DurationSeconds", "Policy", "WebIdentityToken"} {
		if len(r.PostForm[name]) != 1 {
			http.Error(w, "denied", 403)
			return
		}
	}
	f := r.PostForm
	if f.Get("Action") != "AssumeRoleWithWebIdentity" || f.Get("Version") != "2011-06-15" || f.Get("RoleArn") != g.config.RoleARN || f.Get("DurationSeconds") != "900" || !strings.HasPrefix(f.Get("RoleSessionName"), "evidence-") || len(f.Get("RoleSessionName")) != 41 || g.review(r.Context(), f.Get("WebIdentityToken")) != nil {
		http.Error(w, "denied", 403)
		return
	}
	if decoded, err := hex.DecodeString(strings.TrimPrefix(f.Get("RoleSessionName"), "evidence-")); err != nil || len(decoded) != 16 {
		http.Error(w, "denied", 403)
		return
	}
	profile, scope, until := g.findPolicy([]byte(f.Get("Policy")))
	if profile == nil || profile.check() != nil {
		http.Error(w, "denied", 403)
		return
	}
	credential, e := g.issue(profile, scope, until)
	if e != nil {
		http.Error(w, "denied", 403)
		return
	}
	defer wipe(credential.secret)
	role := stsRole.FindStringSubmatch(g.config.RoleARN)
	session := f.Get("RoleSessionName")
	escape := func(v string) string { var b bytes.Buffer; _ = xml.EscapeText(&b, []byte(v)); return b.String() }
	data := fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:%s:sts::%s:assumed-role/%s/%s</Arn><AssumedRoleId>native-c1:%s</AssumedRoleId></AssumedRoleUser><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>%s</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`, stsNamespace, escape(g.config.Audience), escape(g.config.Issuer), escape(profile.policy.Subject), role[1], role[2], role[3], session, session, credential.access, string(credential.secret), credential.token, credential.expiry.Format(time.RFC3339Nano), session)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, data)
}

func (g *OriginalC1OwnerChannel) findPolicy(raw []byte) (*originalC1ChannelProfile, S3Scope, time.Time) {
	// Only the exact existing SDK policy is understood, not arbitrary IAM.
	var deadline time.Time
	var data struct {
		Statement []struct{ Condition map[string]map[string]string }
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &data) != nil {
		return nil, S3Scope{}, deadline
	}
	for _, s := range data.Statement {
		if v := s.Condition["DateGreaterThanEquals"]["aws:CurrentTime"]; v != "" {
			if !deadline.IsZero() {
				return nil, S3Scope{}, time.Time{}
			}
			deadline, _ = time.Parse(time.RFC3339, v)
		}
	}
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return nil, S3Scope{}, time.Time{}
	}
	g.mu.Lock()
	profiles := make([]*originalC1ChannelProfile, 0, len(g.profiles))
	for _, p := range g.profiles {
		profiles = append(profiles, p)
	}
	g.mu.Unlock()
	for _, p := range profiles {
		p.mu.Lock()
		scopes := append([]originalC1ChannelScope(nil), p.scopes...)
		p.mu.Unlock()
		for _, registered := range scopes {
			s := registered.scope
			if deadline.After(registered.until) {
				continue
			}
			want, e := p.transport.policy(s, deadline)
			if e == nil && bytes.Equal(want, raw) {
				return p, s, deadline
			}
		}
	}
	return nil, S3Scope{}, time.Time{}
}

func (g *OriginalC1OwnerChannel) issue(p *originalC1ChannelProfile, scope S3Scope, until time.Time) (*originalC1ChannelCredential, error) {
	if !time.Now().Before(until) || until.After(p.until) || p.check() != nil {
		return nil, ErrDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.sessions) >= 4096 {
		return nil, ErrDenied
	}
	// Reuse the VERY SAME scoped credential exercised by the private native
	// probes; do not issue a broader/different capability after those probes.
	for _, c := range g.sessions {
		if c.profile == p && c.scope == scope && c.until.Equal(until) {
			clone := *c
			clone.secret = bytes.Clone(c.secret)
			return &clone, nil
		}
	}
	access, e := c1Random(16)
	if e != nil {
		return nil, e
	}
	secret, e := c1Random(32)
	if e != nil {
		return nil, e
	}
	token, e := c1Random(32)
	if e != nil {
		return nil, e
	}
	expiry := time.Now().Add(899 * time.Second)
	if d, ok := g.ctx.Deadline(); ok && d.Before(expiry) {
		expiry = d
	}
	if !expiry.After(until) {
		return nil, ErrDenied
	}
	c := &originalC1ChannelCredential{profile: p, scope: scope, access: access, secret: []byte(secret), token: token, until: until, expiry: expiry}
	g.sessions[access] = c
	clone := *c
	clone.secret = bytes.Clone(c.secret)
	return &clone, nil
}

func (g *OriginalC1OwnerChannel) object(w http.ResponseWriter, r *http.Request) {
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		http.Error(w, "denied", 403)
		return
	}
	parts := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(parts) != 5 {
		http.Error(w, "denied", 403)
		return
	}
	g.mu.Lock()
	c := g.sessions[parts[0]]
	var secret []byte
	if c != nil {
		secret = bytes.Clone(c.secret)
	}
	g.mu.Unlock()
	defer wipe(secret)
	if c == nil || !c1VerifyPresign(r, c.access, secret, c.token, g.owner.Upstream.Region, c.until, time.Now().UTC()) || c.profile.check() != nil || g.currentWorkload(r.Context()) != nil {
		http.Error(w, "denied", 403)
		return
	}
	wantPath := "/" + g.owner.Upstream.Bucket + "/" + c.scope.Ref.RelativeKey
	if r.URL.Path != wantPath || r.URL.RawPath != "" && r.URL.EscapedPath() != s3utils.EncodePath(wantPath) || q.Get("versionId") != c.scope.Ref.ImmutableVersion || len(r.Header.Values("Range")) != 0 {
		http.Error(w, "denied", 403)
		return
	}
	var body []byte
	if c.scope.Operation == S3Stat {
		if r.Method != http.MethodHead || r.ContentLength > 0 {
			http.Error(w, "denied", 403)
			return
		}
	} else if c.scope.Operation == S3Put {
		if r.Method != http.MethodPut || c.scope.Ref.ImmutableVersion != "" || r.Header.Get("If-None-Match") != "*" || r.ContentLength != c.scope.Object.Size || r.ContentLength < 1 || r.ContentLength > 8<<20 {
			http.Error(w, "denied", 403)
			return
		}
		body, e = io.ReadAll(io.LimitReader(r.Body, c.scope.Object.Size+1))
		defer wipe(body)
		digest, decodeErr := hex.DecodeString(c.scope.Object.SHA256)
		if e != nil || decodeErr != nil || int64(len(body)) != c.scope.Object.Size || hash(body) != c.scope.Object.SHA256 || r.Header.Get("X-Amz-Content-Sha256") != c.scope.Object.SHA256 || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest) {
			http.Error(w, "denied", 403)
			return
		}
		g.mu.Lock()
		used := c.putUsed
		if !used {
			c.putUsed = true
		}
		g.mu.Unlock()
		if used {
			http.Error(w, "denied", 403)
			return
		}
	} else {
		http.Error(w, "denied", 403)
		return
	}
	if c.profile.check() != nil || !time.Now().Before(c.until) {
		http.Error(w, "denied", 403)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), c.until)
	defer cancel()
	headers := make(http.Header)
	for _, name := range []string{"If-None-Match", "X-Amz-Checksum-Sha256", "X-Amz-Checksum-Mode", "Content-Type"} {
		if value := r.Header.Get(name); value != "" {
			headers.Set(name, value)
		}
	}
	query := url.Values{}
	if c.scope.Ref.ImmutableVersion != "" {
		query.Set("versionId", c.scope.Ref.ImmutableVersion)
	}
	response, e := g.ownerRequest(ctx, r.Method, wantPath, query, body, headers)
	if e != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer response.Body.Close()
	if c.profile.check() != nil || !time.Now().Before(c.until) {
		http.Error(w, "unconfirmed", 502)
		return
	}
	if response.StatusCode == http.StatusOK {
		version := response.Header.Get("X-Amz-Version-Id")
		if s3Version(version) {
			c.profile.mu.Lock()
			c.profile.version = version
			c.profile.mu.Unlock()
		}
	}
	for _, name := range []string{"X-Amz-Version-Id", "X-Amz-Checksum-Sha256", "X-Amz-Checksum-Type", "X-Amz-Delete-Marker", "ETag", "Content-Length"} {
		if values := response.Header.Values(name); len(values) == 1 {
			w.Header().Set(name, values[0])
		}
	}
	if r.Method != http.MethodHead {
		w.Header().Set("Content-Length", "0")
	}
	w.Header().Set("X-Claw-C1-Scope", hash(canonical(c.scope)))
	w.WriteHeader(response.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	}
}

func (g *OriginalC1OwnerChannel) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	for _, c := range g.sessions {
		wipe(c.secret)
	}
	wipe(g.owner.AccessKey)
	wipe(g.owner.SecretKey)
	g.mu.Unlock()
	if g.server != nil {
		_ = g.server.Close()
	}
	if g.listener != nil {
		_ = g.listener.Close()
	}
	if g.upstream != nil {
		g.upstream.CloseIdleConnections()
	}
}
