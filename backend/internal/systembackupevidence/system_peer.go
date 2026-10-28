package systembackupevidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"clawreef/internal/systembackupproducer"
)

// SystemPeerConfig is an independently reviewed deployment mapping, never an
// HTTP body or candidate probe result. Subject is this mapping's exact workload
// label; it is not read from headers, certificate CN or an unsigned JWT. The
// exact CA+certificate pin authenticates possession of its admitted private key.
type SystemPeerConfig struct {
	Scope                             systembackupproducer.Scope
	IssuerIdentityHash, Subject       string
	ClientCAPEM                       []byte
	ClientCASHA256, CertificateSHA256 string
	ExpiresAt                         time.Time
}

type SystemPeerAuthenticator struct {
	c                                       SystemPeerConfig
	roots                                   *x509.CertPool
	workload, actor, admission, subjectHash string
	closed                                  atomic.Bool
}

// SystemPeer is request-bound transport proof, NOT a C1 execution handle or
// deployment authorization. Its fields cannot be supplied by request JSON.
// D must still lock and check current deployment/revocation/domain/host facts.
type SystemPeer struct {
	owner   *SystemPeerAuthenticator
	request context.Context
}

func (SystemPeer) MarshalJSON() ([]byte, error) { return nil, ErrAuth }
func (*SystemPeer) UnmarshalJSON([]byte) error  { return ErrAuth }

// SystemPeerFacts are detached comparison inputs, not independently valid
// credentials. Obtain them only by Check during the authenticating transaction
// and again at its final Guard. They convey no management/evaluator permission.
type SystemPeerFacts struct {
	Scope                                                                      systembackupproducer.Scope
	ActorIdentityHash, WorkloadIdentityHash, IssuerIdentityHash, AdmissionHash string
	SubjectHash, ClientCASHA256, CertificateSHA256                             string
	Subject                                                                    string
	ExpiresAt                                                                  time.Time
}

func NewSystemPeerAuthenticator(c SystemPeerConfig) (*SystemPeerAuthenticator, error) {
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
	// Versioned, closed JSON encodings are internal identity mapping digests,
	// not C1 typed-frame hashes or externally asserted identity credentials.
	workload := systemPeerHash(struct {
		Domain          string
		Scope           systembackupproducer.Scope
		Issuer, Subject string
	}{"system-backup-workload.v1", c.Scope, c.IssuerIdentityHash, c.Subject})
	actor := systemPeerHash(struct{ Domain, Workload, CA, Certificate string }{"system-backup-peer-actor.v1", workload, c.ClientCASHA256, c.CertificateSHA256})
	admission := systemPeerHash(struct {
		Domain, Actor string
		ExpiresAt     time.Time
	}{"system-backup-peer-admission.v1", actor, c.ExpiresAt})
	subjectHash := systemPeerHash(struct{ Domain, Subject string }{"system-backup-recovery-subject.v1", c.Subject})
	c.ClientCAPEM = nil
	return &SystemPeerAuthenticator{c: c, roots: roots, workload: workload, actor: actor, admission: admission, subjectHash: subjectHash}, nil
}

func systemPeerHash(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return hash(raw)
}
func systemPeerTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1000 && t.Year() <= 9999 && offset == 0 && t.Nanosecond()%1000 == 0
}

func (a *SystemPeerAuthenticator) AuthenticateRequest(r *http.Request) (*SystemPeer, error) {
	if a == nil || a.closed.Load() || r == nil || r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
		return nil, ErrAuth
	}
	ctx, err := authenticatePinnedPeer(r, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return nil, ErrAuth
	}
	p := &SystemPeer{owner: a, request: ctx}
	if _, err := a.Check(r.Context(), p, a.c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return nil, ErrAuth
	}
	return p, nil
}

// Check performs only local cryptographic verification; no network or SQL and
// no new locks. scope and dbNow MUST come from D's checked transaction, not from
// request data. Both local and fresh database time must be within the original
// certificate/admission validity; clock disagreement over five seconds denies.
func (a *SystemPeerAuthenticator) Check(ctx context.Context, p *SystemPeer, scope systembackupproducer.Scope, dbNow time.Time) (SystemPeerFacts, error) {
	deny := func() (SystemPeerFacts, error) { return SystemPeerFacts{}, ErrAuth }
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
	return SystemPeerFacts{Scope: a.c.Scope, ActorIdentityHash: a.actor, WorkloadIdentityHash: a.workload, IssuerIdentityHash: a.c.IssuerIdentityHash, AdmissionHash: a.admission, SubjectHash: a.subjectHash, ClientCASHA256: a.c.ClientCASHA256, CertificateSHA256: a.c.CertificateSHA256, Subject: a.c.Subject, ExpiresAt: earlier(until, dbUntil)}, nil
}

// Close locally invalidates proofs issued by this instance. It is not the
// shared deployment/domain revocation channel and does not cancel remote work.
func (a *SystemPeerAuthenticator) Close() {
	if a != nil {
		a.closed.Store(true)
	}
}
