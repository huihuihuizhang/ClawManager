package systembackupevidence

import (
	"context"
	"database/sql"
	"sync"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
	pd "clawreef/internal/systembackupproducer"
)

// DispatchRelayCheck binds the existing D dispatch ABI to A's pinned mTLS
// check. Authority and JobBinding remain observations: D must authenticate them
// against its public locked records before calling BindDispatch. No Ports.Check
// callback, secondary SQL connection, message schema or new grant is introduced.
type DispatchRelayCheck struct{ state *dispatchRelayState }
type dispatchRelayState struct {
	mu        sync.Mutex
	base      *RelayPeerCheck
	scope     pd.Scope
	authority dispatch.Authority
	job       dispatch.JobBinding
	until     time.Time
	failed    bool
}

func (DispatchRelayCheck) String() string               { return "DispatchRelayCheck" }
func (DispatchRelayCheck) GoString() string             { return "DispatchRelayCheck" }
func (DispatchRelayCheck) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*DispatchRelayCheck) UnmarshalJSON([]byte) error  { return ErrDenied }

func dispatchRelayBinding(scope pd.Scope, a dispatch.Authority, j dispatch.JobBinding) (RelayJobBinding, bool) {
	// Public SQL counters are positive signed BIGINT values. Do not narrow an
	// overflowing ABI uint into a valid-looking identity or silently drop it.
	const max = uint64(1<<63 - 1)
	if a.InstallationID != string(scope.Installation) || a.ConfigVersion == 0 || a.ConfigVersion > max ||
		a.AttemptNo == 0 || a.AttemptNo > max || j.Generation == 0 || j.Generation > max ||
		a.ClaimRowVersion == 0 || a.ClaimRowVersion > max || a.MaintenanceFencingToken > max || !s3Token([]byte(a.ClaimOwner), 1, 128) || !systemPeerTime(a.DeadlineAt) ||
		!s3Token([]byte(a.RequestID), 1, 128) || !s3Token([]byte(j.Namespace), 1, 253) || !s3Token([]byte(j.Name), 1, 253) {
		return RelayJobBinding{}, false
	}
	b := RelayJobBinding{Scope: scope, ConfigVersion: int64(a.ConfigVersion), ConfigSHA256: a.ConfigSHA256,
		TargetType: a.TaskType, TargetPublicID: a.TaskPublicID, AttemptNo: int64(a.AttemptNo), Phase: a.Phase,
		JobUnitKey: j.JobUnitKey, JobUID: j.UID, JobGeneration: int64(j.Generation),
		RelayIdentityRef: j.RelayIdentityRef, RelayIdentityVersion: j.RelayIdentityVersion,
		RelayIdentityBoundAt: j.RelayBoundAt, RelayIdentityExpiresAt: j.RelayExpiresAt}
	return b, validRelayBinding(b)
}

func freezeDispatchRelay(a dispatch.Authority, j dispatch.JobBinding) (dispatch.Authority, dispatch.JobBinding) {
	a.DeadlineAt = a.DeadlineAt.UTC().Round(0)
	j.RelayBoundAt = j.RelayBoundAt.UTC().Round(0)
	j.RelayExpiresAt = j.RelayExpiresAt.UTC().Round(0)
	return a, j
}

// BindDispatch runs inside D's single already-authorized transaction. scope,
// current authority and Job binding come from the public installation/task/
// attempt/claim/cursor records, never the relay request. The original admitted
// certificate configuration must independently match their complete projection.
func (a *RelayPeerAuthenticator) BindDispatch(ctx context.Context, tx *sql.Tx, proof *RelayPeerProof, scope pd.Scope, current dispatch.Authority, job dispatch.JobBinding, now time.Time) (*DispatchRelayCheck, RelayPeerFacts, error) {
	b, ok := dispatchRelayBinding(scope, current, job)
	if !ok || !now.Before(current.DeadlineAt) || !time.Now().Before(current.DeadlineAt) {
		if proof != nil && proof.state != nil {
			proof.state.used.CompareAndSwap(false, true)
		}
		return nil, RelayPeerFacts{}, ErrAuth
	}
	base, facts, err := a.Bind(ctx, tx, proof, b, now)
	if err != nil {
		return nil, RelayPeerFacts{}, ErrAuth
	}
	current, job = freezeDispatchRelay(current, job)
	until := earlier(facts.ValidUntil, current.DeadlineAt)
	facts.ValidUntil = until
	return &DispatchRelayCheck{&dispatchRelayState{base: base, scope: scope, authority: current, job: job, until: until}}, facts, nil
}

// RecheckDispatch compares every original Authority/Job field, including the
// claim owner/row version, maintenance owner/fence, request ID, namespace/name
// and original deadline. It cannot extend a lease or infer a live DB claim.
// D still performs its final SQL guard and clock sample after its callbacks.
func (c *DispatchRelayCheck) RecheckDispatch(ctx context.Context, tx *sql.Tx, scope pd.Scope, current dispatch.Authority, job dispatch.JobBinding, now time.Time) (RelayPeerFacts, error) {
	if c == nil || c.state == nil {
		return RelayPeerFacts{}, ErrAuth
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := dispatchRelayBinding(scope, current, job)
	current, job = freezeDispatchRelay(current, job)
	if s.failed || !ok || scope != s.scope || current != s.authority || job != s.job || !now.Before(s.until) || !time.Now().Before(s.until) {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	facts, err := s.base.Recheck(ctx, tx, b, now)
	if err != nil || facts.ValidUntil.Before(s.until) {
		s.failed = true
		return RelayPeerFacts{}, ErrAuth
	}
	facts.ValidUntil = s.until
	return facts, nil
}
