package systembackupevidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync/atomic"
	"time"
	"unicode/utf8"

	pd "clawreef/internal/systembackupproducer"
)

// RecoveryManagerPeerConfig is an independently provisioned management mTLS
// mapping. SQL grants and current deployment admission are checked separately.
// It must not be populated from an ordinary administrator session or HTTP body.
type RecoveryManagerPeerConfig struct {
	Scope                             pd.Scope
	IssuerIdentityHash, Subject       string
	ClientCAPEM                       []byte
	ClientCASHA256, CertificateSHA256 string
	ExpiresAt                         time.Time
}

// RecoveryManagerPeerAuthenticator proves possession of one specifically
// admitted management certificate. It does not grant read_fence, write_fence
// or manage_deployment permission.
type RecoveryManagerPeerAuthenticator struct {
	c                           RecoveryManagerPeerConfig
	roots                       *x509.CertPool
	identity, credentialBinding string
	closed                      atomic.Bool
}

type RecoveryManagerPeer struct {
	owner   *RecoveryManagerPeerAuthenticator
	request context.Context
}

func (RecoveryManagerPeer) MarshalJSON() ([]byte, error) { return nil, ErrAuth }
func (*RecoveryManagerPeer) UnmarshalJSON([]byte) error  { return ErrAuth }

// RecoveryManagerPeerFacts are comparison inputs for the current, locked
// management row. They are not a recovery workload identity or a SQL grant.
type RecoveryManagerPeerFacts struct {
	Scope                 pd.Scope
	IdentityHash          string
	IssuerIdentityHash    string
	CredentialBindingHash string
	ExpiresAt             time.Time
}

func NewRecoveryManagerPeerAuthenticator(c RecoveryManagerPeerConfig) (*RecoveryManagerPeerAuthenticator, error) {
	db := string(c.Scope.Database)
	if !taskJobUID.MatchString(string(c.Scope.ServerUUID)) || !installationPattern.MatchString(string(c.Scope.Installation)) ||
		!utf8.ValidString(db) || utf8.RuneCountInString(db) < 1 || utf8.RuneCountInString(db) > 64 || len(db) > 256 ||
		!digestPattern.MatchString(c.IssuerIdentityHash) || !s3Token([]byte(c.Subject), 6, 255) ||
		!digestPattern.MatchString(c.CertificateSHA256) || !digestPattern.MatchString(c.ClientCASHA256) ||
		len(c.ClientCAPEM) == 0 || len(c.ClientCAPEM) > 65536 || hash(c.ClientCAPEM) != c.ClientCASHA256 ||
		!systemPeerTime(c.ExpiresAt) || !time.Now().Before(c.ExpiresAt) {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.ClientCAPEM) {
		return nil, ErrInvalid
	}
	identity := systemPeerHash(struct {
		Domain          string
		Scope           pd.Scope
		Issuer, Subject string
	}{"system-backup-recovery-manager.v1", c.Scope, c.IssuerIdentityHash, c.Subject})
	credential := systemPeerHash(struct {
		Domain, Identity, CA, Certificate string
		ExpiresAt                         time.Time
	}{"system-backup-recovery-manager-credential.v1", identity, c.ClientCASHA256, c.CertificateSHA256, c.ExpiresAt})
	c.ClientCAPEM = nil
	return &RecoveryManagerPeerAuthenticator{c: c, roots: roots, identity: identity, credentialBinding: credential}, nil
}

func (a *RecoveryManagerPeerAuthenticator) AuthenticateRequest(r *http.Request) (*RecoveryManagerPeer, error) {
	if a == nil || a.closed.Load() || r == nil || r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
		return nil, ErrAuth
	}
	ctx, err := authenticatePinnedPeer(r, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return nil, ErrAuth
	}
	p := &RecoveryManagerPeer{owner: a, request: ctx}
	if _, err := a.Check(r.Context(), p, a.c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return nil, ErrAuth
	}
	return p, nil
}

// Check must be repeated with D's locked scope and database time in each
// management transaction and its final Guard. It never queries SQL itself.
func (a *RecoveryManagerPeerAuthenticator) Check(ctx context.Context, p *RecoveryManagerPeer, scope pd.Scope, dbNow time.Time) (RecoveryManagerPeerFacts, error) {
	deny := func() (RecoveryManagerPeerFacts, error) { return RecoveryManagerPeerFacts{}, ErrAuth }
	if a == nil || a.closed.Load() || ctx == nil || ctx.Err() != nil || p == nil || p.owner != a || p.request == nil || p.request.Err() != nil || scope != a.c.Scope || !systemPeerTime(dbNow) {
		return deny()
	}
	now := time.Now().UTC()
	if dbNow.Before(now.Add(-5*time.Second)) || dbNow.After(now.Add(5*time.Second)) {
		return deny()
	}
	until, err := pinnedPeerExpiryAt(p.request, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt, now)
	if err != nil {
		return deny()
	}
	dbUntil, err := pinnedPeerExpiryAt(p.request, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt, dbNow)
	if err != nil || a.closed.Load() || ctx.Err() != nil || p.request.Err() != nil || !time.Now().Before(until) {
		return deny()
	}
	return RecoveryManagerPeerFacts{Scope: a.c.Scope, IdentityHash: a.identity, IssuerIdentityHash: a.c.IssuerIdentityHash, CredentialBindingHash: a.credentialBinding, ExpiresAt: earlier(until, dbUntil)}, nil
}

func (a *RecoveryManagerPeerAuthenticator) Close() {
	if a != nil {
		a.closed.Store(true)
	}
}
