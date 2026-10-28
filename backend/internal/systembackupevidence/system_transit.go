package systembackupevidence

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// SystemPreparationAuthority authenticates the live producer and authorizes BOTH
// its body and the exact encrypt-only profile. ProfileHash is a lookup input,
// never proof. Implementations must use D's fixed call snapshot, check current
// deployment/grant/run/ref/revocation facts, and verify that the channel does not
// depend on the provider being tested. There is no production implementation or
// success fallback here. Returned data cannot independently authorize anything.
type SystemPreparationAuthority interface {
	AuthorizeSystemPreparation(context.Context, Identity, string) (SystemPreparationAuthorization, error)
}

type SystemPreparationAuthorization struct {
	Content     ContentAuthorization
	Key         KeyRef
	ProfileHash string
	// Trusted workload authentication projection, distinct from the Wrap JWT.
	// The adapter also verifies profile issuer/subject match that workload.
	AuthenticationAudience, AuthenticationTokenFile string
}

// SystemWrapProfileHash binds every local JWT/Transit setting except the CA
// bytes, which are bound by CASHA256 and checked by NewTransitKeys. The digest
// is an internal adapter profile, not the C1 channel_profile_hash or authority.
// It is deterministic JSON of this closed structure; no secret token is read.
func SystemWrapProfileHash(c TransitJWTConfig) string {
	raw, err := json.Marshal(struct {
		Domain                                                              string
		Endpoint, Installation, KeyName                                     string
		Key                                                                 KeyRef
		KeyVersion                                                          uint32
		CASHA256, Mount, Role, Policy, Issuer, Audience, Subject, TokenFile string
	}{"system-backup-system-wrap-profile.v1", c.Transit.Endpoint, c.Transit.Installation, c.Transit.KeyName, c.Transit.Key, c.Transit.KeyVersion,
		c.Transit.CASHA256, c.Mount, c.Role, c.Policy, c.Issuer, c.Audience, c.Subject, c.TokenFile})
	if err != nil {
		return ""
	}
	return hash(raw)
}

// SystemTransitPreparer exposes only preparation, never raw keys or credentials.
// The host supplies encrypted staging. SQL admission/publish follow separately.
// A real authority, reviewed remote ACL and production host are still required.
type SystemTransitPreparer struct {
	authority SystemPreparationAuthority
	c         TransitJWTConfig
	profile   string
	keys      *TransitKeys
	closed    atomic.Bool
}

func NewSystemTransitPreparer(a SystemPreparationAuthority, c TransitJWTConfig) (*SystemTransitPreparer, error) {
	u, err := url.Parse(c.Issuer)
	if nilSystemAdapter(a) || !transitSegment(c.Mount) || !transitSegment(c.Role) || !transitSegment(c.Policy) ||
		oneOf(strings.ToLower(c.Policy), "root", "default") || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(c.Issuer, "?#\r\n") ||
		!s3Token([]byte(c.Audience), 1, 255) || !s3Token([]byte(c.Subject), 1, 1024) || !filepath.IsAbs(c.TokenFile) || !digestPattern.MatchString(SystemWrapProfileHash(c)) {
		return nil, ErrKey
	}
	p := &SystemTransitPreparer{authority: a, c: c, profile: SystemWrapProfileHash(c)}
	p.keys, err = NewTransitKeys(c.Transit, systemTransitCredentials{p})
	if err != nil {
		return nil, err
	}
	p.c.Transit.CAPEM = nil
	return p, nil
}

type systemTransitCall struct {
	p         *SystemTransitPreparer
	identity  Identity
	grantHash string
	until     time.Time
}

func (p *SystemTransitPreparer) authorize(ctx context.Context, i Identity) (SystemPreparationAuthorization, error) {
	if p == nil || p.closed.Load() || ctx.Err() != nil {
		return SystemPreparationAuthorization{}, ErrDenied
	}
	g, err := p.authority.AuthorizeSystemPreparation(ctx, i, p.profile)
	if err != nil || g.ProfileHash != p.profile || g.Key != p.c.Transit.Key || g.Content.Identity != i || i.Installation != p.c.Transit.Installation ||
		!s3Token([]byte(g.AuthenticationAudience), 1, 255) || g.AuthenticationAudience == p.c.Audience || !filepath.IsAbs(g.AuthenticationTokenFile) ||
		strings.EqualFold(filepath.Clean(g.AuthenticationTokenFile), filepath.Clean(p.c.TokenFile)) || ctx.Err() != nil {
		return SystemPreparationAuthorization{}, ErrDenied
	}
	if _, _, err := contentValidator(g.Content, i); err != nil {
		return SystemPreparationAuthorization{}, ErrDenied
	}
	return g, nil
}

func (c *systemTransitCall) AuthorizeContent(ctx context.Context, i Identity) (ContentAuthorization, error) {
	if c == nil || i != c.identity || ctx.Err() != nil || !time.Now().Before(c.until) {
		return ContentAuthorization{}, ErrDenied
	}
	g, err := c.p.authorize(ctx, i)
	if err != nil || systemPreparationHash(g) != c.grantHash || ctx.Err() != nil || !time.Now().Before(c.until) {
		return ContentAuthorization{}, ErrDenied
	}
	return g.Content, nil
}

func systemPreparationHash(g SystemPreparationAuthorization) string {
	raw, err := json.Marshal(g)
	if err != nil {
		return ""
	}
	return hash(raw)
}

func (p *SystemTransitPreparer) Prepare(ctx context.Context, i Identity, src Source, dst io.Writer) (Prepared, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.closed.Load() || !i.validExternal() || i.OwnerType != "system" || i.Type != "capability_snapshot" || i.Media != "application/json" || i.ContentSize > MaxCapabilityContent || src == nil || nilSystemAdapter(dst) {
		return Prepared{}, ErrDenied
	}
	g, err := p.authorize(ctx, i)
	if err != nil {
		return Prepared{}, ErrDenied
	}
	until := earlier(time.Now().Add(20*time.Second), g.Content.ValidUntil.Add(-transitClockMargin))
	if deadline, ok := ctx.Deadline(); ok {
		until = earlier(until, deadline)
	}
	call := &systemTransitCall{p, i, systemPreparationHash(g), until}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	// Pointer identity is local to this preparer and call; external request
	// fields/context strings cannot mint or reuse a Wrap capability.
	ctx = context.WithValue(ctx, p, call)
	return PrepareSystemCapability(ctx, i, p.c.Transit.Key, src, call, systemTransitKeys{call}, dst)
}

// Close after the host drains in-flight preparations. Repeated Close is safe.
func (p *SystemTransitPreparer) Close() {
	if p != nil && !p.closed.Swap(true) {
		p.keys.Close()
	}
}

type systemTransitKeys struct{ call *systemTransitCall }

func (systemTransitKeys) Unwrap(context.Context, KeyRef, []byte) ([]byte, error) { return nil, ErrKey }
func (k systemTransitKeys) Wrap(ctx context.Context, key KeyRef, dek []byte) ([]byte, error) {
	c := k.call
	if c == nil || c.p == nil || key != c.p.c.Transit.Key {
		return nil, ErrKey
	}
	if _, err := c.AuthorizeContent(ctx, c.identity); err != nil {
		return nil, ErrKey
	}
	wrapped, err := c.p.keys.Wrap(ctx, key, dek)
	if err != nil {
		wipe(wrapped)
		return nil, ErrKey
	}
	if _, err := c.AuthorizeContent(ctx, c.identity); err != nil {
		wipe(wrapped)
		return nil, ErrKey
	}
	return wrapped, nil
}

type systemTransitCredentials struct{ p *SystemTransitPreparer }

func (r systemTransitCredentials) Resolve(ctx context.Context, key KeyRef, op TransitOperation) (TransitCredential, error) {
	deny := func() (TransitCredential, error) { return TransitCredential{}, ErrKey }
	p := r.p
	if p == nil || p.closed.Load() || op != TransitWrap || key != p.c.Transit.Key {
		return deny()
	}
	c, ok := ctx.Value(p).(*systemTransitCall)
	if !ok || c == nil || c.p != p {
		return deny()
	}
	if _, err := c.AuthorizeContent(ctx, c.identity); err != nil {
		return deny()
	}
	jwt, jwtExpiry, err := readProjectedToken(p.c.TokenFile, p.c.Issuer, p.c.Audience, p.c.Subject)
	defer wipe(jwt)
	if err != nil {
		return deny()
	}
	until := earlier(c.until, jwtExpiry.Add(-transitClockMargin))
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	secret, expiry, err := transitJWTExchange(ctx, p.keys.client, p.c, jwt, until)
	if err != nil {
		wipe(secret)
		return deny()
	}
	if _, err := c.AuthorizeContent(ctx, c.identity); err != nil || ctx.Err() != nil || !time.Now().Before(expiry) {
		wipe(secret)
		return deny()
	}
	return TransitCredential{Key: key, Installation: p.c.Transit.Installation, Operation: op, Secret: secret, ExpiresAt: earlier(expiry, c.until)}, nil
}
