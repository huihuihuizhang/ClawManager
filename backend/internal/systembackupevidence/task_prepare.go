package systembackupevidence

import (
	"context"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// TaskPreparer binds real task authorization, job-log validation and a reviewed
// encrypt-only Transit role. It exposes neither raw keys nor provider tokens.
// The caller supplies an authenticated SQLTaskAuthority context and task-owned
// encrypted staging. Registry admission and conditional Publish follow later.
type TaskPreparer struct {
	authority *SQLTaskAuthority
	keys      *TransitKeys
	c         TransitJWTConfig
	closed    atomic.Bool
}

func NewTaskPreparer(a *SQLTaskAuthority, c TransitJWTConfig) (*TaskPreparer, error) {
	if a == nil {
		return nil, ErrKey
	}
	u, err := url.Parse(c.Issuer)
	if c.Transit.Installation != a.c.Installation || !transitSegment(c.Mount) || !transitSegment(c.Role) || !transitSegment(c.Policy) ||
		oneOf(strings.ToLower(c.Policy), "root", "default") || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(c.Issuer, "?#\r\n") ||
		c.Issuer != a.c.Issuer || c.Subject != a.c.Subject || !s3Token([]byte(c.Audience), 1, 255) || c.Audience == a.c.Audience ||
		!filepath.IsAbs(c.TokenFile) || filepath.Clean(c.TokenFile) == filepath.Clean(a.c.TokenFile) {
		return nil, ErrKey
	}
	p := &TaskPreparer{authority: a, c: c}
	p.keys, err = NewTransitKeys(c.Transit, taskTransitCredentials{p})
	if err != nil {
		return nil, err
	}
	p.c.Transit.CAPEM = nil
	return p, nil
}

type taskPreparation struct {
	identity Identity
	lease    string
	until    time.Time
}

// Prepare fails closed if task/config/attempt/Job authorization changes during
// validation, JWT exchange, encryption or staging. On any error discard dst:
// it may contain ciphertext, but no usable Prepared is returned.
func (p *TaskPreparer) Prepare(ctx context.Context, i Identity, src Source, dst io.Writer) (Prepared, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.closed.Load() || !p.authority.accepts(i) || src == nil || nilSystemAdapter(dst) {
		return Prepared{}, ErrDenied
	}
	grant, err := p.authority.authorizeKey(ctx, nil, &p.c.Transit.Key)
	if err != nil {
		return Prepared{}, ErrDenied
	}
	until := grant.until.Add(-transitClockMargin)
	ctx, cancel := context.WithDeadline(ctx, earlier(time.Now().Add(20*time.Second), until))
	defer cancel()
	ctx = context.WithValue(ctx, p, taskPreparation{i, grant.leaseHash, until})
	dispatcher, err := NewContentDispatcher(p.authority)
	if err != nil {
		return Prepared{}, err
	}
	prepared, err := Prepare(ctx, i, p.c.Transit.Key, src, dispatcher, taskPrepareKeys{p}, dst)
	if err != nil {
		return Prepared{}, err
	}
	if _, err = p.authorize(ctx); err != nil {
		return Prepared{}, ErrDenied
	}
	return prepared, nil
}

func (p *TaskPreparer) authorize(ctx context.Context) (taskGrant, error) {
	if p == nil || p.closed.Load() || ctx.Err() != nil {
		return taskGrant{}, ErrDenied
	}
	binding, ok := ctx.Value(p).(taskPreparation)
	if !ok || !p.authority.accepts(binding.identity) || !time.Now().Before(binding.until) {
		return taskGrant{}, ErrDenied
	}
	grant, err := p.authority.authorizeKey(ctx, nil, &p.c.Transit.Key)
	if err != nil || grant.leaseHash != binding.lease || !time.Now().Before(grant.until.Add(-transitClockMargin)) || !time.Now().Before(binding.until) || ctx.Err() != nil {
		return taskGrant{}, ErrDenied
	}
	return grant, nil
}

// Close after the host drains in-flight preparation calls.
func (p *TaskPreparer) Close() {
	if p != nil && !p.closed.Swap(true) {
		p.keys.Close()
	}
}

type taskPrepareKeys struct{ p *TaskPreparer }

func (k taskPrepareKeys) Unwrap(context.Context, KeyRef, []byte) ([]byte, error) { return nil, ErrKey }
func (k taskPrepareKeys) Wrap(ctx context.Context, key KeyRef, dek []byte) ([]byte, error) {
	wrapped, err := k.p.keys.Wrap(ctx, key, dek)
	if err != nil {
		return nil, ErrKey
	}
	if _, err := k.p.authorize(ctx); err != nil {
		wipe(wrapped)
		return nil, ErrKey
	}
	return wrapped, nil
}

type taskTransitCredentials struct{ p *TaskPreparer }

func (r taskTransitCredentials) Resolve(ctx context.Context, key KeyRef, op TransitOperation) (TransitCredential, error) {
	deny := func() (TransitCredential, error) { return TransitCredential{}, ErrKey }
	p := r.p
	if p == nil || op != TransitWrap || key != p.c.Transit.Key {
		return deny()
	}
	before, err := p.authorize(ctx)
	if err != nil {
		return deny()
	}
	jwt, jwtExpiry, err := readProjectedToken(p.c.TokenFile, p.c.Issuer, p.c.Audience, p.c.Subject)
	defer wipe(jwt)
	if err != nil {
		return deny()
	}
	until := earlier(before.until, jwtExpiry).Add(-transitClockMargin)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	secret, expiry, err := transitJWTExchange(ctx, p.keys.client, p.c, jwt, until)
	ok := false
	defer func() {
		if !ok {
			wipe(secret)
		}
	}()
	if err != nil {
		return deny()
	}
	after, err := p.authorize(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(expiry) {
		return deny()
	}
	ok = true
	return TransitCredential{Key: key, Installation: p.c.Transit.Installation, Operation: op, Secret: secret, ExpiresAt: earlier(expiry, after.until.Add(-transitClockMargin))}, nil
}
