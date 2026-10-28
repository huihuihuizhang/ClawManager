package systembackupevidence

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// TransitJWTConfig is a reviewed operation-specific KEK mapping, never request
// input. The JWT role must issue nonrenewable batch tokens with <=20s TTL and
// exactly Policy: the admitted operation on this pre-existing key/context.
// Separate audience/projected file prevent reusing the S3 workload credential.
type TransitJWTConfig struct {
	Transit                              TransitConfig
	Mount, Role, Policy                  string
	Issuer, Audience, Subject, TokenFile string
}

// DownloadTransitConfig preserves the download mapping API. Its policy must permit decrypt only.
type DownloadTransitConfig = TransitJWTConfig

// DownloadTransit connects live SQL download authorization, JWT token exchange,
// historical key routing and envelope-bound unwrap. It exposes neither tokens
// nor wrap privileges. Close only after in-flight users have finished.
type DownloadTransit struct {
	keys DownloadKeys
	ring *TransitKeyring
}

var _ Keys = (*DownloadTransit)(nil)

func NewDownloadTransit(a *SQLDownloadAuthority, configs []DownloadTransitConfig) (*DownloadTransit, error) {
	if a == nil || len(configs) == 0 || len(configs) > 128 {
		return nil, ErrKey
	}
	ring := &TransitKeyring{keys: make(map[KeyRef]*TransitKeys)}
	roles, policies := map[string]bool{}, map[string]bool{}
	fail := func() (*DownloadTransit, error) { ring.Close(); return nil, ErrKey }
	for _, c := range configs {
		u, err := url.Parse(c.Issuer)
		roleID := c.Transit.Endpoint + "/" + c.Mount + "/" + c.Role
		policyID := c.Transit.Endpoint + "/" + c.Policy
		if c.Transit.Installation != a.c.Registry.Installation || ring.keys[c.Transit.Key] != nil || roles[roleID] || policies[policyID] ||
			!transitSegment(c.Mount) || !transitSegment(c.Role) || !transitSegment(c.Policy) || oneOf(strings.ToLower(c.Policy), "root", "default") ||
			err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(c.Issuer, "?#\r\n") ||
			c.Issuer != a.c.Issuer || c.Subject != a.c.Subject || !s3Token([]byte(c.Audience), 1, 255) || c.Audience == a.c.Audience ||
			!filepath.IsAbs(c.TokenFile) || filepath.Clean(c.TokenFile) == filepath.Clean(a.c.TokenFile) {
			return fail()
		}
		resolver := &downloadTransitCredentials{c: c, authority: a}
		key, err := NewTransitKeys(c.Transit, resolver)
		if err != nil {
			return fail()
		}
		resolver.client = key.client // same pinned origin/CA/redirect policy
		resolver.c.Transit.CAPEM = nil
		ring.keys[c.Transit.Key] = key
		roles[roleID], policies[policyID] = true, true
	}
	return &DownloadTransit{keys: DownloadKeys{Authority: a, Keys: ring}, ring: ring}, nil
}

func transitSegment(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}
func (d *DownloadTransit) Wrap(ctx context.Context, key KeyRef, plain []byte) ([]byte, error) {
	return (DownloadKeys{}).Wrap(ctx, key, plain)
}
func (d *DownloadTransit) Unwrap(ctx context.Context, key KeyRef, wrapped []byte) ([]byte, error) {
	if d == nil {
		return nil, ErrKey
	}
	return d.keys.Unwrap(ctx, key, wrapped)
}
func (d *DownloadTransit) Close() {
	if d != nil {
		d.ring.Close()
	}
}

type downloadTransitCredentials struct {
	c         DownloadTransitConfig
	authority *SQLDownloadAuthority
	client    *http.Client
}

func (d *downloadTransitCredentials) Resolve(ctx context.Context, key KeyRef, op TransitOperation) (TransitCredential, error) {
	deny := func() (TransitCredential, error) {
		if c := committedDownloadFrom(ctx); c != nil {
			c.fail()
		}
		return TransitCredential{}, ErrKey
	}
	if d == nil || d.client == nil || op != TransitUnwrap || key != d.c.Transit.Key {
		return deny()
	}
	before, err := d.authority.authorize(ctx)
	if err != nil || before.record.Manifest.Key != key {
		return deny()
	}
	jwt, jwtExpiry, err := readProjectedToken(d.c.TokenFile, d.c.Issuer, d.c.Audience, d.c.Subject)
	defer wipe(jwt)
	if err != nil {
		return deny()
	}
	until := earlier(before.until, jwtExpiry).Add(-transitClockMargin)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	secret, expiry, err := transitJWTExchange(ctx, d.client, d.c, jwt, until)
	ok := false
	defer func() {
		if !ok {
			wipe(secret)
		}
	}()
	if err != nil {
		return deny()
	}
	after, err := d.authority.authorize(ctx)
	if err != nil || before.principal != after.principal || before.lease != after.lease || after.record.Manifest.Key != key ||
		ctx.Err() != nil || !time.Now().Before(expiry) || !time.Now().Before(after.until.Add(-transitClockMargin)) {
		return deny()
	}
	ok = true
	return TransitCredential{Key: key, Installation: d.c.Transit.Installation, Operation: TransitUnwrap, Secret: secret, ExpiresAt: earlier(expiry, after.until.Add(-transitClockMargin))}, nil
}
