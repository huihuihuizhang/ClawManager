package publicadapter

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"sync"
	"time"

	d "clawreef/internal/systembackupdispatch"
	e "clawreef/internal/systembackupevidence"
	p "clawreef/internal/systembackupproducer"
)

// RelayAuthentication resolves an OWNER-MANAGED admitted mapping. Message
// fields are untrusted lookup hints only; Bind compares D's locked records to
// both the message and A's independently admitted certificate mapping. B does
// not create/close authenticators, issue grants or infer revocation from TLS.
type RelayAuthentication struct {
	ResolvePeer       func(context.Context, RelayMessage) (*e.RelayPeerAuthenticator, error)
	TransactionBudget time.Duration
}

// AuthenticatedRelayAcceptor is D's one transaction owner. It uses the supplied
// context, locks the public scope/claim/fence/Job/cursor, calls Bind, persists
// result/cursor/evidence, calls Recheck, then its FINAL SQL authority/clock guard
// and COMMIT. It returns success only after confirmed commit or exact committed
// replay readback. B neither opens SQL nor treats Recheck as proof of a commit.
type AuthenticatedRelayAcceptor interface {
	AcceptAuthenticatedRelay(context.Context, *AuthenticatedRelay) (RelayDecision, error)
}

type authenticatedRelayAcceptor struct {
	config RelayAuthentication
	owner  AuthenticatedRelayAcceptor
}

func NewAuthenticatedRelayHandler(config RelayAuthentication, owner AuthenticatedRelayAcceptor) (http.Handler, error) {
	if config.ResolvePeer == nil || nilValue(owner) || config.TransactionBudget <= 0 || config.TransactionBudget > time.Minute {
		return nil, d.ErrNotReady
	}
	return newRelayHandler(authenticatedRelayAcceptor{config, owner})
}

func (a authenticatedRelayAcceptor) AcceptRelay(ctx context.Context, request *http.Request, message RelayMessage, raw []byte, hash string) (RelayDecision, error) {
	peer, err := a.config.ResolvePeer(ctx, copyRelayMessage(message))
	if err != nil || peer == nil {
		return "", d.ErrNotReady
	}
	proof, err := peer.AuthenticateRequest(request)
	if err != nil {
		return "", &Failure{"permission_denied"}
	}
	// A's request-bound context MUST survive into D's original transaction.
	bounded, cancel := context.WithTimeout(proof.Context(), a.config.TransactionBudget)
	defer cancel()
	session := &AuthenticatedRelay{state: &relaySession{ctx: bounded, peer: peer, proof: proof, message: copyRelayMessage(message), raw: append([]byte(nil), raw...), hash: hash}}
	decision, err := a.owner.AcceptAuthenticatedRelay(bounded, session)
	return session.finish(decision, err)
}

type RelayCursor struct {
	Sequence   uint64
	BodySHA256 string
	Status     string
}

// AuthenticatedRelay is opaque, request-bound and one-shot. No serialized
// request or copied facts can mint it. Returned message/body values are data,
// never authenticated database authority. Bind/Recheck use A's ORIGINAL types.
type AuthenticatedRelay struct{ state *relaySession }
type relaySession struct {
	mu                           sync.Mutex
	ctx                          context.Context
	peer                         *e.RelayPeerAuthenticator
	proof                        *e.RelayPeerProof
	message                      RelayMessage
	raw                          []byte
	hash                         string
	check                        *e.DispatchRelayCheck
	decision                     RelayDecision
	until                        time.Time
	used, verified, failed, done bool
}

func (*AuthenticatedRelay) MarshalJSON() ([]byte, error) { return nil, d.ErrNotReady }
func (*AuthenticatedRelay) UnmarshalJSON([]byte) error   { return d.ErrNotReady }
func (*AuthenticatedRelay) String() string               { return "AuthenticatedRelay" }
func (*AuthenticatedRelay) GoString() string             { return "AuthenticatedRelay" }

func copyRelayMessage(m RelayMessage) RelayMessage {
	if m.ResultEvidence != nil {
		evidence := *m.ResultEvidence
		m.ResultEvidence = &evidence
	}
	return m
}

func (r *AuthenticatedRelay) Message() RelayMessage {
	if r == nil || r.state == nil {
		return RelayMessage{}
	}
	return copyRelayMessage(r.state.message)
}
func (r *AuthenticatedRelay) Body() ([]byte, string) {
	if r == nil || r.state == nil {
		return nil, ""
	}
	return append([]byte(nil), r.state.raw...), r.state.hash
}

func relayMatches(m RelayMessage, a d.Authority, j d.JobBinding) bool {
	return m.InstallationID == a.InstallationID && m.TaskPublicID == a.TaskPublicID && m.TaskType == a.TaskType && m.AttemptNo == strconv.FormatUint(a.AttemptNo, 10) && m.Phase == a.Phase && m.JobUnitKey == j.JobUnitKey && m.Namespace == j.Namespace && m.JobName == j.Name && m.JobUID == j.UID && m.JobGeneration == strconv.FormatUint(j.Generation, 10) && m.RelayIdentityRef == j.RelayIdentityRef && m.RelayIdentityVersion == j.RelayIdentityVersion
}

func (r *AuthenticatedRelay) Bind(tx *sql.Tx, scope p.Scope, current d.Authority, job d.JobBinding, dbNow time.Time, cursor RelayCursor) (RelayDecision, e.RelayPeerFacts, error) {
	if r == nil || r.state == nil {
		return "", e.RelayPeerFacts{}, d.ErrNotReady
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.failed || s.done {
		s.failed = true
		return "", e.RelayPeerFacts{}, &Failure{"coordination_invalid"}
	}
	s.used = true // invalid scope consumes the request too; no retry in a new tx
	if !relayMatches(s.message, current, job) {
		s.failed = true
		return "", e.RelayPeerFacts{}, &Failure{"control_evidence_invalid"}
	}
	check, facts, err := s.peer.BindDispatch(s.ctx, tx, s.proof, scope, current, job, dbNow)
	if err != nil {
		s.failed = true
		return "", e.RelayPeerFacts{}, &Failure{"permission_denied"}
	}
	sequence, _ := positiveDecimal(s.message.Sequence)
	decision, err := RelaySequence(cursor.Sequence, cursor.BodySHA256, sequence, s.hash)
	if err == nil {
		err = RelayProgress(cursor.Status, s.message, decision)
	}
	if err != nil {
		s.failed = true
		return "", e.RelayPeerFacts{}, err
	}
	s.check, s.decision, s.until = check, decision, facts.ValidUntil
	return decision, facts, nil
}

func (r *AuthenticatedRelay) Recheck(tx *sql.Tx, scope p.Scope, current d.Authority, job d.JobBinding, dbNow time.Time) (e.RelayPeerFacts, error) {
	if r == nil || r.state == nil {
		return e.RelayPeerFacts{}, d.ErrNotReady
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check == nil || s.failed || s.done || !relayMatches(s.message, current, job) {
		s.failed = true
		return e.RelayPeerFacts{}, &Failure{"coordination_invalid"}
	}
	facts, err := s.check.RecheckDispatch(s.ctx, tx, scope, current, job, dbNow)
	if err != nil {
		s.failed = true
		return e.RelayPeerFacts{}, &Failure{"permission_denied"}
	}
	s.verified = true
	return facts, nil
}

func (r *AuthenticatedRelay) finish(decision RelayDecision, err error) (RelayDecision, error) {
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if err != nil {
		return "", classify(err)
	}
	if s.failed || !s.verified || decision != s.decision || s.ctx.Err() != nil || !time.Now().Before(s.until) {
		return "", d.ErrNotReady
	}
	return decision, nil
}
