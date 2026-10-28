package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// RelayJobBinding is the existing public config/Job cursor projection. It is
// comparison data, not a WorkerGrant, claim/fence or a status-relay wire schema.
// D supplies Current from its locked public records, never from relay JSON.
type RelayJobBinding struct {
	Scope                                        pd.Scope
	ConfigVersion                                int64
	ConfigSHA256                                 string
	TargetType, TargetPublicID                   string
	AttemptNo                                    int64
	Phase, JobUnitKey, JobUID                    string
	JobGeneration                                int64
	RelayIdentityRef, RelayIdentityVersion       string
	RelayIdentityBoundAt, RelayIdentityExpiresAt time.Time
}

// Peer is independently admitted deployment trust. Its Subject is the exact
// SPIFFE URI in the client certificate, not a CN, header or URI-derived grant.
// Removing/rotating/revoking that mapping remains the original owner's job.
type RelayPeerConfig struct {
	Peer    SystemPeerConfig
	Binding RelayJobBinding
}

type RelayPeerAuthenticator struct {
	peer    *SystemPeerAuthenticator
	binding RelayJobBinding
	uri     string
}

// RelayPeerProof is request-bound and one-shot. Context preserves the TLS
// request's cancellation chain. Derive the operation timeout before Begin/Bind.
type RelayPeerProof struct{ state *relayPeerProofState }
type relayPeerProofState struct {
	owner *RelayPeerAuthenticator
	peer  *SystemPeer
	ctx   context.Context
	used  atomic.Bool
}

// RelayPeerFacts are detached observations, never authorization. B/D must
// additionally authorize claim/fence, revocation and the message in the SAME
// transaction, and enforce the original final SQL clock before its commit.
type RelayPeerFacts struct {
	Binding                                                       RelayJobBinding
	SPIFFE, IssuerIdentityHash, ClientCASHA256, CertificateSHA256 string
	ValidUntil                                                    time.Time
}

type RelayPeerCheck struct{ state *relayPeerCheckState }
type relayPeerCheckState struct {
	mu     sync.Mutex
	proof  *RelayPeerProof
	ctx    context.Context
	tx     *sql.Tx
	floor  time.Time
	until  time.Time
	failed bool
}

func (RelayPeerConfig) String() string                      { return "RelayPeerConfig" }
func (RelayPeerConfig) GoString() string                    { return "RelayPeerConfig" }
func (RelayPeerConfig) MarshalJSON() ([]byte, error)        { return nil, ErrDenied }
func (*RelayPeerConfig) UnmarshalJSON([]byte) error         { return ErrDenied }
func (RelayPeerAuthenticator) String() string               { return "RelayPeerAuthenticator" }
func (RelayPeerAuthenticator) GoString() string             { return "RelayPeerAuthenticator" }
func (RelayPeerAuthenticator) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*RelayPeerAuthenticator) UnmarshalJSON([]byte) error  { return ErrDenied }
func (RelayPeerProof) String() string                       { return "RelayPeerProof" }
func (RelayPeerProof) GoString() string                     { return "RelayPeerProof" }
func (RelayPeerProof) MarshalJSON() ([]byte, error)         { return nil, ErrDenied }
func (*RelayPeerProof) UnmarshalJSON([]byte) error          { return ErrDenied }
func (RelayPeerCheck) String() string                       { return "RelayPeerCheck" }
func (RelayPeerCheck) GoString() string                     { return "RelayPeerCheck" }
func (RelayPeerCheck) MarshalJSON() ([]byte, error)         { return nil, ErrDenied }
func (*RelayPeerCheck) UnmarshalJSON([]byte) error          { return ErrDenied }

func validRelayBinding(b RelayJobBinding) bool {
	p := ownerPatterns[b.TargetType]
	return p != nil && p.MatchString(b.TargetPublicID) && taskTable(b.TargetType) != "" && taskPhase(b.TargetType, b.Phase) &&
		b.ConfigVersion > 0 && digestPattern.MatchString(b.ConfigSHA256) && b.AttemptNo > 0 && b.JobGeneration > 0 &&
		versionPattern.MatchString(b.JobUnitKey) && taskJobUID.MatchString(b.JobUID) &&
		s3Token([]byte(b.RelayIdentityRef), 1, 256) && versionPattern.MatchString(b.RelayIdentityVersion) &&
		systemPeerTime(b.RelayIdentityBoundAt) && systemPeerTime(b.RelayIdentityExpiresAt) && b.RelayIdentityExpiresAt.After(b.RelayIdentityBoundAt)
}

func canonicalRelayBinding(b RelayJobBinding) RelayJobBinding {
	b.RelayIdentityBoundAt = b.RelayIdentityBoundAt.UTC().Round(0)
	b.RelayIdentityExpiresAt = b.RelayIdentityExpiresAt.UTC().Round(0)
	return b
}

func validRelayURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 255 && u.Scheme == "spiffe" && u.Host != "" && u.Host == u.Hostname() &&
		u.User == nil && u.Opaque == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		strings.HasPrefix(u.Path, "/") && u.Path != "/" && u.String() == s
}

func publicRelayRoots(raw []byte) bool {
	count := 0
	for len(bytes.TrimSpace(raw)) != 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return false
		}
		count++
		if count > 128 {
			return false
		}
		raw = rest
	}
	return count != 0
}

// NewRelayPeerAuthenticator freezes existing mapping data and public trust.
// It neither certifies its supplier nor creates/renews a key, grant or cursor.
// It performs no SQL/network I/O and cannot be a bootstrap owner by itself.
func NewRelayPeerAuthenticator(c RelayPeerConfig) (*RelayPeerAuthenticator, error) {
	if !validRelayBinding(c.Binding) || c.Binding.Scope != c.Peer.Scope || !validRelayURI(c.Peer.Subject) ||
		len(c.Peer.ClientCAPEM) > 65536 || !publicRelayRoots(c.Peer.ClientCAPEM) ||
		c.Binding.RelayIdentityExpiresAt.After(c.Peer.ExpiresAt) {
		return nil, ErrInvalid
	}
	peer, err := NewSystemPeerAuthenticator(c.Peer)
	if err != nil {
		return nil, ErrInvalid
	}
	return &RelayPeerAuthenticator{peer: peer, binding: canonicalRelayBinding(c.Binding), uri: c.Peer.Subject}, nil
}

func (a *RelayPeerAuthenticator) AuthenticateRequest(r *http.Request) (*RelayPeerProof, error) {
	if a == nil || a.peer == nil || r == nil || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil, ErrAuth
	}
	// Parse DER ourselves. Caller-mutable Certificate.URIs/CN and forwarded
	// headers cannot describe a different identity from the verified bytes.
	leaf, err := x509.ParseCertificate(r.TLS.PeerCertificates[0].Raw)
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != a.uri {
		return nil, ErrAuth
	}
	peer, err := a.peer.AuthenticateRequest(r)
	if err != nil {
		return nil, ErrAuth
	}
	p := &RelayPeerProof{state: &relayPeerProofState{owner: a, peer: peer}}
	p.state.ctx = context.WithValue(peer.request, p.state, p.state)
	return p, nil
}

func (p *RelayPeerProof) Context() context.Context {
	if p == nil || p.state == nil {
		return nil
	}
	return p.state.ctx
}

func relayContext(ctx context.Context, p *RelayPeerProof) bool {
	return !nilSystemAdapter(ctx) && p != nil && p.state != nil && p.state.ctx != nil && ctx.Err() == nil && p.state.ctx.Err() == nil && ctx.Value(p.state) == p.state
}

func sameRelayContext(a, b context.Context) bool {
	return !nilSystemAdapter(a) && !nilSystemAdapter(b) && reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

func (a *RelayPeerAuthenticator) observe(ctx context.Context, p *RelayPeerProof, current RelayJobBinding, now time.Time) (RelayPeerFacts, error) {
	if a == nil || a.peer == nil || p == nil || p.state == nil || p.state.owner != a || !relayContext(ctx, p) || !validRelayBinding(current) ||
		canonicalRelayBinding(current) != a.binding || !systemPeerTime(now) || now.Before(a.binding.RelayIdentityBoundAt) {
		return RelayPeerFacts{}, ErrAuth
	}
	facts, err := a.peer.Check(ctx, p.state.peer, current.Scope, now)
	wall := time.Now().UTC()
	until := earlier(facts.ExpiresAt, a.binding.RelayIdentityExpiresAt)
	if err != nil || wall.Before(a.binding.RelayIdentityBoundAt) || !wall.Before(until) || !now.Before(until) {
		return RelayPeerFacts{}, ErrAuth
	}
	return RelayPeerFacts{a.binding, a.uri, facts.IssuerIdentityHash, facts.ClientCASHA256, facts.CertificateSHA256, until}, nil
}

// Bind is a transport/material check inside D's already-authorized transaction.
// The non-nil tx is an identity anchor only: this code never queries, commits or
// claims it. Current and SQL UTC(6) time must come from D's locked current facts.
func (a *RelayPeerAuthenticator) Bind(ctx context.Context, tx *sql.Tx, p *RelayPeerProof, current RelayJobBinding, now time.Time) (*RelayPeerCheck, RelayPeerFacts, error) {
	if p == nil || p.state == nil || !p.state.used.CompareAndSwap(false, true) || tx == nil {
		return nil, RelayPeerFacts{}, ErrAuth
	}
	if _, bounded := relayPeerDeadline(ctx); !bounded {
		return nil, RelayPeerFacts{}, ErrAuth
	}
	facts, err := a.observe(ctx, p, current, now)
	if err != nil {
		return nil, RelayPeerFacts{}, ErrAuth
	}
	return &RelayPeerCheck{&relayPeerCheckState{proof: p, ctx: ctx, tx: tx, floor: now, until: facts.ValidUntil}}, facts, nil
}

func relayPeerDeadline(ctx context.Context) (time.Time, bool) {
	if nilSystemAdapter(ctx) {
		return time.Time{}, false
	}
	return ctx.Deadline()
}

func (c *RelayPeerCheck) Recheck(ctx context.Context, tx *sql.Tx, current RelayJobBinding, now time.Time) (RelayPeerFacts, error) {
	if c == nil || c.state == nil {
		return RelayPeerFacts{}, ErrAuth
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || tx == nil || tx != s.tx || !sameRelayContext(ctx, s.ctx) || now.Before(s.floor) {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	facts, err := s.proof.state.owner.observe(ctx, s.proof, current, now)
	if err != nil || !now.Before(s.until) || facts.ValidUntil.Before(s.until) {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	s.floor = now
	facts.ValidUntil = s.until // Never extend the original observation.
	return facts, nil
}

func (a *RelayPeerAuthenticator) Close() {
	if a != nil && a.peer != nil {
		a.peer.Close()
	}
}
