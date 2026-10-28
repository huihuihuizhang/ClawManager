package systembackupevidence

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// TaskAuthorityConfig is deployment-owned admission, NEVER request JSON. One
// authority binds one reviewed Job producer, controller lease and config. A new
// Job/config/identity needs new admission; no wildcard or latest fallback exists.
// TokenFile is an already provisioned, rotating projected OIDC token, not S3 keys.
type TaskAuthorityConfig struct {
	DB                                   *sql.DB
	Installation, ServerUUID, Database   string
	ConfigVersion                        int64
	ConfigSHA256                         string
	Root                                 string
	Store, Write                         KeyRef
	ClientCAPEM                          []byte
	ClientCASHA256, CertificateSHA256    string
	OwnerType, OwnerID, ControllerOwner  string
	Attempt                              int64
	Phase, JobUnit, JobUID               string
	JobGeneration                        int64
	RelayIdentity, RelayVersion          string
	Issuer, Audience, Subject, TokenFile string
	ExpiresAt                            time.Time
	Classification                       string
	LogPolicy                            JobLogPolicy
}

// SQLTaskAuthority implements the task job-log producer/publisher path. It does
// not grant system capability, administrator download or GC access. Those need
// their own authenticated principals, references and retention authorization.
type SQLTaskAuthority struct {
	c         TaskAuthorityConfig
	roots     *x509.CertPool
	principal string
}

var _ ContentAuthority = (*SQLTaskAuthority)(nil)
var _ S3WebIdentityAuthority = (*SQLTaskAuthority)(nil)
var taskJobUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NewSQLTaskAuthority(c TaskAuthorityConfig) (*SQLTaskAuthority, error) {
	p := ownerPatterns[c.OwnerType]
	issuer, issuerErr := url.Parse(c.Issuer)
	if c.DB == nil || !installationPattern.MatchString(c.Installation) || c.ServerUUID == "" || c.Database == "" ||
		c.ConfigVersion < 1 || !digestPattern.MatchString(c.ConfigSHA256) || !safeKey(c.Root) || !c.Store.valid() || !c.Write.valid() ||
		!digestPattern.MatchString(c.CertificateSHA256) || !digestPattern.MatchString(c.ClientCASHA256) ||
		len(c.ClientCAPEM) == 0 || len(c.ClientCAPEM) > 65536 || hash(c.ClientCAPEM) != c.ClientCASHA256 ||
		p == nil || !p.MatchString(c.OwnerID) || taskTable(c.OwnerType) == "" || !taskPhase(c.OwnerType, c.Phase) ||
		!s3Token([]byte(c.ControllerOwner), 1, 128) || c.Attempt < 1 || c.JobGeneration < 1 || !taskJobUID.MatchString(c.JobUID) ||
		!versionPattern.MatchString(c.JobUnit) || !s3Token([]byte(c.RelayIdentity), 1, 256) || !versionPattern.MatchString(c.RelayVersion) ||
		!s3Token([]byte(c.Subject), 6, 255) || !s3Token([]byte(c.Audience), 1, 255) ||
		issuerErr != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.Opaque != "" || strings.ContainsAny(c.Issuer, "?#") || !s3Token([]byte(c.Issuer), 9, 2048) ||
		!filepath.IsAbs(c.TokenFile) || !time.Now().Before(c.ExpiresAt) ||
		!oneOf(c.Classification, "internal", "confidential", "sensitive") {
		return nil, ErrInvalid
	}
	policy, err := freezeLogPolicy(c.LogPolicy)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(c.ClientCAPEM) {
		return nil, ErrInvalid
	}
	c.LogPolicy, c.ClientCAPEM = policy, nil
	// Public binding digest changes when any admitted identity or policy changes.
	principal := hash(canonical(struct {
		Installation, Certificate, Task, Owner, Controller, Phase, Unit, Job, Relay, RelayVersion, ConfigHash, Policy string
		Attempt, Generation, ConfigVersion                                                                            int64
	}{c.Installation, c.CertificateSHA256, c.OwnerType, c.OwnerID, c.ControllerOwner, c.Phase, c.JobUnit, c.JobUID, c.RelayIdentity, c.RelayVersion, c.ConfigSHA256, logPolicyHash(policy), c.Attempt, c.JobGeneration, c.ConfigVersion}))
	return &SQLTaskAuthority{c: c, roots: roots, principal: principal}, nil
}

type taskPeer struct{ certificates [][]byte }

// AuthenticateRequest requires a completed mTLS handshake, then verifies its
// peer again against the authority's own pinned CA and exact certificate. The
// opaque context is tied to this authority; headers and caller IDs are ignored.
func (a *SQLTaskAuthority) AuthenticateRequest(r *http.Request) (context.Context, error) {
	if a == nil {
		return nil, ErrAuth
	}
	return authenticatePinnedPeer(r, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
}

func authenticatePinnedPeer(r *http.Request, key any, roots *x509.CertPool, certificate string, expires time.Time) (context.Context, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 ||
		len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates) > 8 || len(r.TLS.VerifiedChains[0]) == 0 ||
		r.TLS.PeerCertificates[0] == nil || r.TLS.VerifiedChains[0][0] == nil ||
		!r.TLS.PeerCertificates[0].Equal(r.TLS.VerifiedChains[0][0]) {
		return nil, ErrAuth
	}
	p := taskPeer{}
	for _, cert := range r.TLS.PeerCertificates {
		if cert == nil || len(cert.Raw) > 16384 {
			return nil, ErrAuth
		}
		p.certificates = append(p.certificates, append([]byte(nil), cert.Raw...))
	}
	ctx := context.WithValue(r.Context(), key, p)
	if _, err := pinnedPeerExpiry(ctx, key, roots, certificate, expires); err != nil {
		return nil, ErrAuth
	}
	return ctx, nil
}

func (a *SQLTaskAuthority) peerExpiry(ctx context.Context) (time.Time, error) {
	if a == nil {
		return time.Time{}, ErrDenied
	}
	return pinnedPeerExpiry(ctx, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
}

func pinnedPeerExpiry(ctx context.Context, key any, roots *x509.CertPool, certificate string, expires time.Time) (time.Time, error) {
	return pinnedPeerExpiryAt(ctx, key, roots, certificate, expires, time.Now())
}

func pinnedPeerExpiryAt(ctx context.Context, key any, roots *x509.CertPool, certificate string, expires, now time.Time) (time.Time, error) {
	if roots == nil || ctx.Err() != nil {
		return time.Time{}, ErrDenied
	}
	p, ok := ctx.Value(key).(taskPeer)
	if !ok || len(p.certificates) == 0 || hash(p.certificates[0]) != certificate {
		return time.Time{}, ErrDenied
	}
	leaf, err := x509.ParseCertificate(p.certificates[0])
	if err != nil {
		return time.Time{}, ErrDenied
	}
	intermediates := x509.NewCertPool()
	for _, raw := range p.certificates[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return time.Time{}, ErrDenied
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || !now.Before(expires) {
		return time.Time{}, ErrDenied
	}
	until := expires
	for _, cert := range chains[0] {
		until = earlier(until, cert.NotAfter)
	}
	return until, nil
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (a *SQLTaskAuthority) accepts(i Identity) bool {
	return i.valid() && i.Installation == a.c.Installation && i.OwnerType == a.c.OwnerType && i.OwnerID == a.c.OwnerID &&
		i.Type == "job_log_chunk" && i.Media == "text/plain" && i.Classification == a.c.Classification && i.ContentSize <= MaxLogChunkBytes
}

func (a *SQLTaskAuthority) AuthorizeContent(ctx context.Context, i Identity) (ContentAuthorization, error) {
	if a == nil || !a.accepts(i) {
		return ContentAuthorization{}, ErrDenied
	}
	grant, err := a.authorize(ctx, nil)
	if err != nil {
		return ContentAuthorization{}, ErrDenied
	}
	policy, err := freezeLogPolicy(a.c.LogPolicy)
	if err != nil {
		return ContentAuthorization{}, ErrDenied
	}
	return ContentAuthorization{Identity: i, ProducerIdentityHash: grant.leaseHash, ValidUntil: grant.until, JobLog: &policy}, nil
}

func (a *SQLTaskAuthority) AuthorizeS3(ctx context.Context, scope S3Scope) (S3WebIdentityGrant, error) {
	if a == nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	grant, err := a.authorize(ctx, &scope)
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	// No filesystem/provider operation occurs while SQL locks are held.
	token, expires, err := a.readToken()
	if err != nil {
		return S3WebIdentityGrant{}, ErrDenied
	}
	if ctx.Err() != nil || !time.Now().Before(grant.until) {
		wipe(token)
		return S3WebIdentityGrant{}, ErrDenied
	}
	return S3WebIdentityGrant{Authorization: S3Authorization{
		Scope: scope, Evidence: grant.identity, ConfigVersion: a.c.ConfigVersion, AccessKind: "task", AttemptNumber: a.c.Attempt,
		PrincipalHash: a.principal, LeaseHash: grant.leaseHash, Subject: a.c.Subject, ExpiresAt: grant.until,
	}, Token: token, TokenExpiresAt: expires}, nil
}

// This is a bounded claim precheck, NOT JWT authentication. The pinned STS
// endpoint must verify signature/trust and its response must match these claims.
// The token is never used to authenticate the producer or to authorize SQL.
func (a *SQLTaskAuthority) readToken() ([]byte, time.Time, error) {
	return readProjectedToken(a.c.TokenFile, a.c.Issuer, a.c.Audience, a.c.Subject)
}

func readProjectedToken(path, expectedIssuer, expectedAudience, expectedSubject string) ([]byte, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, ErrDenied
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 20000 {
		return nil, time.Time{}, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(f, 20001))
	ok := false
	defer func() {
		if !ok {
			wipe(raw)
		}
	}()
	if err != nil || !s3Token(raw, 4, 20000) {
		return nil, time.Time{}, ErrDenied
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return nil, time.Time{}, ErrDenied
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	defer wipe(payload)
	if err != nil || !utf8.Valid(payload) {
		return nil, time.Time{}, ErrDenied
	}
	fields, err := transitObject(payload)
	defer wipeTransitFields(fields)
	if err != nil {
		return nil, time.Time{}, ErrDenied
	}
	var issuer, subject string
	var exp, nbf, iat int64
	if json.Unmarshal(fields["iss"], &issuer) != nil || issuer != expectedIssuer || json.Unmarshal(fields["sub"], &subject) != nil || subject != expectedSubject ||
		json.Unmarshal(fields["exp"], &exp) != nil || exp <= 0 {
		return nil, time.Time{}, ErrDenied
	}
	var audiences []string
	var audience string
	if json.Unmarshal(fields["aud"], &audience) == nil {
		audiences = []string{audience}
	} else if json.Unmarshal(fields["aud"], &audiences) != nil {
		return nil, time.Time{}, ErrDenied
	}
	// Exactly one admitted audience; ambiguous/multi-recipient tokens rejected.
	if len(audiences) != 1 || audiences[0] != expectedAudience {
		return nil, time.Time{}, ErrDenied
	}
	now := time.Now().Unix()
	for name, dest := range map[string]*int64{"nbf": &nbf, "iat": &iat} {
		if value, exists := fields[name]; exists && (string(value) == "null" || json.Unmarshal(value, dest) != nil || *dest < 0 || *dest > now) {
			return nil, time.Time{}, ErrDenied
		}
	}
	if exp <= now || exp <= nbf || exp <= iat {
		return nil, time.Time{}, ErrDenied
	}
	ok = true
	return raw, time.Unix(exp, 0).UTC(), nil
}
