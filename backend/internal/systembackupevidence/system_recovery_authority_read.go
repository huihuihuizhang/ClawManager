package systembackupevidence

import (
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemRecoveryAuthorityReadEnvironment grants D's current-state observation
// only after a fresh management mTLS and current L1b read_fence admission.
// It neither issues a deployment mutation nor identifies an earlier commit.
type SystemRecoveryAuthorityReadEnvironment struct {
	auth *RecoveryManagerPeerAuthenticator
	peer *RecoveryManagerPeer
}

func NewSystemRecoveryAuthorityReadEnvironment(auth *RecoveryManagerPeerAuthenticator, peer *RecoveryManagerPeer) (*SystemRecoveryAuthorityReadEnvironment, error) {
	if auth == nil || peer == nil || peer.owner != auth {
		return nil, ErrDenied
	}
	return &SystemRecoveryAuthorityReadEnvironment{auth: auth, peer: peer}, nil
}

func (e *SystemRecoveryAuthorityReadEnvironment) PrepareRecoveryAuthorityRead(ctx context.Context, r pd.RecoveryAuthorityReadRequest) (pd.RecoveryAuthorityReadSession, error) {
	if e == nil || e.auth == nil || e.peer == nil || ctx == nil || ctx.Err() != nil || r.Scope != e.auth.c.Scope {
		return nil, ErrDenied
	}
	hash, err := pd.RecoveryAuthorityReadHash(r)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err := e.auth.Check(ctx, e.peer, r.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return nil, ErrAuth
	}
	return &systemRecoveryAuthorityReadSession{auth: e.auth, peer: e.peer, scope: r.Scope, requestHash: hash}, nil
}

type systemRecoveryAuthorityReadSession struct {
	auth        *RecoveryManagerPeerAuthenticator
	peer        *RecoveryManagerPeer
	scope       pd.Scope
	requestHash pd.Hash
	guard       *RecoveryManagerRowGuard
	facts       RecoveryManagerPeerFacts
	admitted    bool
}

func (s *systemRecoveryAuthorityReadSession) matches(r pd.RecoveryAuthorityReadRequest, hash pd.Hash) bool {
	if s == nil || r.Scope != s.scope || hash != s.requestHash {
		return false
	}
	actual, err := pd.RecoveryAuthorityReadHash(r)
	return err == nil && actual == hash
}

func (s *systemRecoveryAuthorityReadSession) LockManagerRead(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityReadRequest, _ *pd.RecoveryDeploymentProposal, hash pd.Hash) (pd.RecoveryAuthorityReadAdmission, error) {
	if s == nil || s.guard != nil || s.admitted || !s.matches(r, hash) || tx == nil || ctx == nil || ctx.Err() != nil {
		return pd.RecoveryAuthorityReadAdmission{}, ErrDenied
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbNow); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, ErrUnavailable
	}
	facts, err := s.auth.Check(ctx, s.peer, r.Scope, dbNow)
	if err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, ErrAuth
	}
	guard, err := NewRecoveryManagerRowGuard(r.Scope, facts)
	if err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, ErrDenied
	}
	s.guard = guard
	if err := guard.Lock(ctx, tx); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	if err := guard.Admit(facts, RecoveryManagerReadFence, dbNow); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	s.facts, s.admitted = facts, true
	return pd.RecoveryAuthorityReadAdmission{VerifiedRequestHash: hash, ManagerExpiresAt: systemPublicationTimestamp(facts.ExpiresAt), ReadAllowed: true}, nil
}

func (s *systemRecoveryAuthorityReadSession) RecheckManagerRead(ctx context.Context, tx pd.ReadSQL, r pd.RecoveryAuthorityReadRequest, dbNow time.Time) error {
	if s == nil || !s.admitted || tx == nil || ctx == nil || ctx.Err() != nil || !s.matches(r, s.requestHash) {
		return ErrDenied
	}
	facts, err := s.auth.Check(ctx, s.peer, r.Scope, dbNow)
	if err != nil || facts.Scope != s.facts.Scope || facts.IdentityHash != s.facts.IdentityHash ||
		facts.IssuerIdentityHash != s.facts.IssuerIdentityHash || facts.CredentialBindingHash != s.facts.CredentialBindingHash ||
		!facts.ExpiresAt.Equal(s.facts.ExpiresAt) {
		return ErrAuth
	}
	return s.guard.Recheck(ctx, tx, facts, RecoveryManagerReadFence, dbNow)
}

var _ pd.RecoveryAuthorityReadEnvironment = (*SystemRecoveryAuthorityReadEnvironment)(nil)
var _ pd.RecoveryAuthorityReadSession = (*systemRecoveryAuthorityReadSession)(nil)
