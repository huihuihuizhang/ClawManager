package systembackupevidence

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
	"time"

	b "clawreef/internal/systembackup/relaywire"
	d "clawreef/internal/systembackupdispatch"
	pd "clawreef/internal/systembackupproducer"
)

// DispatchRelayMessageCheck adds B's message projection to the original pinned
// mTLS/dispatch check. It is NOT the wire validator, cursor or an execution grant.
// Message must come from B's closed decoder; D still performs the original SQL
// authority/revocation checks and B sequence/progress rules in the same tx.
type DispatchRelayMessageCheck struct{ state *dispatchRelayMessageState }
type dispatchRelayMessageState struct {
	mu      sync.Mutex
	base    *DispatchRelayCheck
	message b.RelayMessage
	failed  bool
}

func (DispatchRelayMessageCheck) String() string               { return "DispatchRelayMessageCheck" }
func (DispatchRelayMessageCheck) GoString() string             { return "DispatchRelayMessageCheck" }
func (DispatchRelayMessageCheck) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*DispatchRelayMessageCheck) UnmarshalJSON([]byte) error  { return ErrDenied }

func relayMessageMatches(a d.Authority, j d.JobBinding, m b.RelayMessage) bool {
	return m.SchemaVersion == b.RelayVersion && m.InstallationID == a.InstallationID &&
		m.TaskPublicID == a.TaskPublicID && m.TaskType == a.TaskType &&
		m.AttemptNo == strconv.FormatUint(a.AttemptNo, 10) && m.Phase == a.Phase &&
		m.JobUnitKey == j.JobUnitKey && m.Namespace == j.Namespace && m.JobName == j.Name &&
		m.JobUID == j.UID && m.JobGeneration == strconv.FormatUint(j.Generation, 10) &&
		m.RelayIdentityRef == j.RelayIdentityRef && m.RelayIdentityVersion == j.RelayIdentityVersion
}

func copyRelayMessage(m b.RelayMessage) b.RelayMessage {
	if m.ResultEvidence != nil {
		e := *m.ResultEvidence
		m.ResultEvidence = &e
	}
	return m
}

func sameRelayMessage(a, b b.RelayMessage) bool {
	ae, be := a.ResultEvidence, b.ResultEvidence
	a.ResultEvidence, b.ResultEvidence = nil, nil
	return a == b && ((ae == nil && be == nil) || (ae != nil && be != nil && *ae == *be))
}

// BindDispatchMessage never fills current authority/Job from message fields.
// Those observations must already be independently authorized and locked by D.
// On mismatch the proof is consumed; fixing the body cannot revive that proof.
func (a *RelayPeerAuthenticator) BindDispatchMessage(ctx context.Context, tx *sql.Tx, proof *RelayPeerProof, scope pd.Scope, current d.Authority, job d.JobBinding, message b.RelayMessage, now time.Time) (*DispatchRelayMessageCheck, RelayPeerFacts, error) {
	if !relayMessageMatches(current, job, message) {
		if proof != nil && proof.state != nil {
			proof.state.used.CompareAndSwap(false, true)
		}
		return nil, RelayPeerFacts{}, ErrAuth
	}
	base, facts, err := a.BindDispatch(ctx, tx, proof, scope, current, job, now)
	if err != nil {
		return nil, RelayPeerFacts{}, ErrAuth
	}
	return &DispatchRelayMessageCheck{&dispatchRelayMessageState{base: base, message: copyRelayMessage(message)}}, facts, nil
}

// RecheckDispatchMessage freezes every typed message field, including status,
// sequence and the optional immutable result reference. This does not interpret
// or authorize them: D retains B's exact original body/hash and cursor CAS.
func (c *DispatchRelayMessageCheck) RecheckDispatchMessage(ctx context.Context, tx *sql.Tx, scope pd.Scope, current d.Authority, job d.JobBinding, message b.RelayMessage, now time.Time) (RelayPeerFacts, error) {
	if c == nil || c.state == nil {
		return RelayPeerFacts{}, ErrAuth
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || !relayMessageMatches(current, job, message) || !sameRelayMessage(s.message, message) {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	facts, err := s.base.RecheckDispatch(ctx, tx, scope, current, job, now)
	if err != nil {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	return facts, nil
}
