package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemDeploymentBoundHistoricalAuthority adds the current L1a deployment
// check to an authority that owns the remaining historical recovery policy.
// The wrapped LockInstallation must acquire only L0 installation locks; this
// adapter then acquires L1a before Authorize can reach D's L2 revocation row.
type SystemDeploymentBoundHistoricalAuthority struct {
	inner            SystemHistoricalAuthority
	managementIssuer string
}

func NewSystemDeploymentBoundHistoricalAuthority(inner SystemHistoricalAuthority, managementIssuerHash string) (*SystemDeploymentBoundHistoricalAuthority, error) {
	if nilSystemAdapter(inner) || !digestPattern.MatchString(managementIssuerHash) {
		return nil, ErrInvalid
	}
	return &SystemDeploymentBoundHistoricalAuthority{inner: inner, managementIssuer: managementIssuerHash}, nil
}

func (a *SystemDeploymentBoundHistoricalAuthority) PrepareHistoricalAuthority(ctx context.Context, r pd.RecoveryRequest, op string, finish *pd.RecoveryFinishRequest) (SystemHistoricalAuthoritySession, ProducerEvidenceChannel, *time.Time, error) {
	if a == nil || nilSystemAdapter(a.inner) || ctx == nil || ctx.Err() != nil {
		return nil, ProducerEvidenceChannel{}, nil, ErrDenied
	}
	inner, channel, sample, err := a.inner.PrepareHistoricalAuthority(ctx, r, op, finish)
	if err != nil || nilSystemAdapter(inner) {
		return nil, ProducerEvidenceChannel{}, nil, ErrDenied
	}
	guard, err := NewSystemHistoricalDeploymentGuard(r.Scope, channel.RecoveryProfileHash, a.managementIssuer)
	if err != nil {
		return nil, ProducerEvidenceChannel{}, nil, ErrDenied
	}
	return &systemDeploymentBoundSession{SystemHistoricalAuthoritySession: inner, guard: guard, request: r}, channel, sample, nil
}

type systemDeploymentBoundSession struct {
	SystemHistoricalAuthoritySession
	guard      *SystemHistoricalDeploymentGuard
	request    pd.RecoveryRequest
	facts      SystemPeerFacts
	admission  pd.RecoveryAdmission
	l2Version  int64
	locked     bool
	authorized bool
	refLocked  bool
}

const systemHistoricalRevocationSelect = `SELECT revocation_epoch,revoked_at,row_version FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=?`

func (s *systemDeploymentBoundSession) readRevocation(ctx context.Context, tx pd.ReadSQL, lock bool) (int64, error) {
	key, err := pd.RecoveryScopeKey(s.request.Scope)
	if err != nil {
		return 0, ErrDenied
	}
	identity, err := hex.DecodeString(string(s.admission.IdentityHash))
	if err != nil || len(identity) != 32 {
		return 0, ErrDenied
	}
	query := systemHistoricalRevocationSelect
	if lock {
		query += " FOR UPDATE"
	}
	var epoch, version int64
	var revoked sql.NullTime
	if err := tx.QueryRowContext(ctx, query, key, identity).Scan(&epoch, &revoked, &version); err != nil {
		return 0, ErrDenied
	}
	want, err := s.admission.RevocationEpoch.SQLInt64()
	if err != nil || want <= 0 || epoch != want || version < 1 || revoked.Valid {
		return 0, ErrDenied
	}
	return version, nil
}

func (s *systemDeploymentBoundSession) LockInstallation(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest) error {
	if s == nil || s.locked || r != s.request || ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrDenied
	}
	if err := s.SystemHistoricalAuthoritySession.LockInstallation(ctx, tx, r); err != nil {
		return err
	}
	if err := s.guard.Lock(ctx, tx); err != nil {
		return err
	}
	s.locked = true
	return nil
}

func (s *systemDeploymentBoundSession) Authorize(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, requestHash pd.Hash, op string, facts SystemPeerFacts, binding string) (pd.RecoveryAdmission, error) {
	if s == nil || !s.locked || s.authorized || r != s.request || ctx == nil || ctx.Err() != nil || tx == nil {
		return pd.RecoveryAdmission{}, ErrDenied
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbNow); err != nil {
		return pd.RecoveryAdmission{}, ErrUnavailable
	}
	admission, err := s.SystemHistoricalAuthoritySession.Authorize(ctx, tx, r, requestHash, op, facts, binding)
	if err != nil {
		return pd.RecoveryAdmission{}, err
	}
	if err := s.guard.Admit(facts, admission, dbNow); err != nil {
		return pd.RecoveryAdmission{}, err
	}
	s.facts, s.admission, s.authorized = facts, admission, true
	return admission, nil
}

// D has already locked the exact L2 row before calling L5 references. This
// current read captures its row version; the final guard must see that version
// again, in addition to A's L1a deployment and the delegated policy checks.
func (s *systemDeploymentBoundSession) LockReferences(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord) error {
	if s == nil || !s.authorized || s.refLocked || r != s.request || h.Scope != r.Scope || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	version, err := s.readRevocation(ctx, tx, true)
	if err != nil {
		return err
	}
	if err := s.SystemHistoricalAuthoritySession.LockReferences(ctx, tx, r, h); err != nil {
		return err
	}
	s.l2Version, s.refLocked = version, true
	return nil
}

func (s *systemDeploymentBoundSession) Recheck(ctx context.Context, tx pd.ReadSQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord, admission pd.RecoveryAdmission, dbNow time.Time) error {
	if s == nil || !s.authorized || !s.refLocked || r != s.request || admission != s.admission || ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrDenied
	}
	if err := s.SystemHistoricalAuthoritySession.Recheck(ctx, tx, r, h, admission, dbNow); err != nil {
		return err
	}
	if err := s.guard.Recheck(ctx, tx, s.facts, admission, dbNow); err != nil {
		return err
	}
	version, err := s.readRevocation(ctx, tx, false)
	if err != nil || version != s.l2Version {
		return ErrDenied
	}
	return nil
}

var _ SystemHistoricalAuthority = (*SystemDeploymentBoundHistoricalAuthority)(nil)
var _ SystemHistoricalAuthoritySession = (*systemDeploymentBoundSession)(nil)
