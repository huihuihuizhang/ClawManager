package systembackupevidence

import (
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemRecoveryAuthorityDecision is the separately provisioned policy for
// the next deployment and audit capacity. Its methods run under D's SQL
// transaction and must not perform network or provider I/O. No default or
// permissive implementation is supplied here.
type SystemRecoveryAuthorityDecision interface {
	NextDeployment(context.Context, pd.SQL, pd.RecoveryAuthorityRequest, *pd.RecoveryDeploymentProposal, RecoveryManagerPeerFacts) (pd.RecoveryDeploymentProposal, error)
	Audit(context.Context, pd.SQL, pd.RecoveryAuthorityRequest, string) error
}

// SystemRecoveryAuthorityEnvironment binds an independent management mTLS
// request to D's L1b management row and atomic L1a/L2 mutation.
type SystemRecoveryAuthorityEnvironment struct {
	auth     *RecoveryManagerPeerAuthenticator
	peer     *RecoveryManagerPeer
	decision SystemRecoveryAuthorityDecision
}

func NewSystemRecoveryAuthorityEnvironment(auth *RecoveryManagerPeerAuthenticator, peer *RecoveryManagerPeer, decision SystemRecoveryAuthorityDecision) (*SystemRecoveryAuthorityEnvironment, error) {
	if auth == nil || peer == nil || peer.owner != auth || nilSystemAdapter(decision) {
		return nil, ErrDenied
	}
	return &SystemRecoveryAuthorityEnvironment{auth: auth, peer: peer, decision: decision}, nil
}

func (e *SystemRecoveryAuthorityEnvironment) PrepareRecoveryAuthority(ctx context.Context, r pd.RecoveryAuthorityRequest) (pd.RecoveryAuthoritySession, error) {
	if e == nil || e.auth == nil || e.peer == nil || nilSystemAdapter(e.decision) || ctx == nil || ctx.Err() != nil || r.Fence.Scope != e.auth.c.Scope {
		return nil, ErrDenied
	}
	hash, err := pd.RecoveryAuthorityHash(r)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err := e.auth.Check(ctx, e.peer, r.Fence.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return nil, ErrAuth
	}
	return &systemRecoveryAuthoritySession{auth: e.auth, peer: e.peer, decision: e.decision, request: r, requestHash: hash}, nil
}

type systemRecoveryAuthoritySession struct {
	auth        *RecoveryManagerPeerAuthenticator
	peer        *RecoveryManagerPeer
	decision    SystemRecoveryAuthorityDecision
	request     pd.RecoveryAuthorityRequest
	requestHash pd.Hash
	guard       *RecoveryManagerRowGuard
	facts       RecoveryManagerPeerFacts
	authorized  bool
}

func (s *systemRecoveryAuthoritySession) matches(r pd.RecoveryAuthorityRequest) bool {
	if s == nil || r.Fence.Scope != s.request.Fence.Scope {
		return false
	}
	hash, err := pd.RecoveryAuthorityHash(r)
	return err == nil && hash == s.requestHash
}

func (s *systemRecoveryAuthoritySession) LockManager(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, current *pd.RecoveryDeploymentProposal) (pd.RecoveryAuthorityAdmission, error) {
	if s == nil || s.authorized || s.guard != nil || !s.matches(r) || tx == nil || ctx == nil || ctx.Err() != nil {
		return pd.RecoveryAuthorityAdmission{}, ErrDenied
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbNow); err != nil {
		return pd.RecoveryAuthorityAdmission{}, ErrUnavailable
	}
	facts, err := s.auth.Check(ctx, s.peer, r.Fence.Scope, dbNow)
	if err != nil {
		return pd.RecoveryAuthorityAdmission{}, ErrAuth
	}
	guard, err := NewRecoveryManagerRowGuard(r.Fence.Scope, facts)
	if err != nil {
		return pd.RecoveryAuthorityAdmission{}, ErrDenied
	}
	s.guard = guard
	if err := guard.Lock(ctx, tx); err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	for _, permission := range []RecoveryManagerPermission{RecoveryManagerWriteFence, RecoveryManagerManageDeployment} {
		if err := guard.Admit(facts, permission, dbNow); err != nil {
			return pd.RecoveryAuthorityAdmission{}, err
		}
	}
	next, err := s.decision.NextDeployment(ctx, tx, r, current, facts)
	if err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	if next.ManagementIssuerHash != pd.Hash(facts.IssuerIdentityHash) {
		return pd.RecoveryAuthorityAdmission{}, ErrDenied
	}
	s.facts, s.authorized = facts, true
	return pd.RecoveryAuthorityAdmission{VerifiedRequestHash: s.requestHash, ManagerExpiresAt: systemPublicationTimestamp(facts.ExpiresAt), WriteFenceAllowed: true, ManageAllowed: true, NextDeployment: next}, nil
}

func (s *systemRecoveryAuthoritySession) Audit(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, stage string) error {
	if s == nil || !s.authorized || !s.matches(r) || tx == nil || ctx == nil || ctx.Err() != nil || !oneOf(stage, "intent", "result") {
		return ErrDenied
	}
	return s.decision.Audit(ctx, tx, r, stage)
}

func (s *systemRecoveryAuthoritySession) RecheckManager(ctx context.Context, tx pd.ReadSQL, r pd.RecoveryAuthorityRequest, dbNow time.Time) error {
	if s == nil || !s.authorized || !s.matches(r) || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	facts, err := s.auth.Check(ctx, s.peer, r.Fence.Scope, dbNow)
	if err != nil || facts.Scope != s.facts.Scope || facts.IdentityHash != s.facts.IdentityHash ||
		facts.IssuerIdentityHash != s.facts.IssuerIdentityHash || facts.CredentialBindingHash != s.facts.CredentialBindingHash ||
		!facts.ExpiresAt.Equal(s.facts.ExpiresAt) {
		return ErrAuth
	}
	for _, permission := range []RecoveryManagerPermission{RecoveryManagerWriteFence, RecoveryManagerManageDeployment} {
		if err := s.guard.Recheck(ctx, tx, facts, permission, dbNow); err != nil {
			return err
		}
	}
	if guarded, ok := s.decision.(interface {
		RecheckDecision(context.Context, pd.RecoveryAuthorityRequest, RecoveryManagerPeerFacts, time.Time) error
	}); ok {
		if err := guarded.RecheckDecision(ctx, r, facts, dbNow); err != nil {
			return err
		}
	}
	return nil
}

var _ pd.RecoveryAuthorityEnvironment = (*SystemRecoveryAuthorityEnvironment)(nil)
var _ pd.RecoveryAuthoritySession = (*systemRecoveryAuthoritySession)(nil)
