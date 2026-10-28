package systembackupevidence

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemHistoricalAuthority owns the current deployment, reference, capacity,
// audit and revocation policy. It must load the original immutable channel,
// rather than the currently active configuration. No permissive implementation
// is supplied by this package.
type SystemHistoricalAuthority interface {
	PrepareHistoricalAuthority(context.Context, pd.RecoveryRequest, string, *pd.RecoveryFinishRequest) (SystemHistoricalAuthoritySession, ProducerEvidenceChannel, *time.Time, error)
}

type SystemHistoricalAuthoritySession interface {
	LockInstallation(context.Context, pd.SQL, pd.RecoveryRequest) error
	Authorize(context.Context, pd.SQL, pd.RecoveryRequest, pd.Hash, string, SystemPeerFacts, string) (pd.RecoveryAdmission, error)
	LockReferences(context.Context, pd.SQL, pd.RecoveryRequest, pd.HistoricalBindingRecord) error
	Reserve(context.Context, pd.SQL, pd.RecoveryRequest, uint64) error
	Audit(context.Context, pd.SQL, pd.RecoveryRequest, string) error
	VerifyStat(context.Context, pd.SQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryFinishRequest) (pd.RecoveryStatAdmission, error)
	Recheck(context.Context, pd.ReadSQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryAdmission, time.Time) error
}

// SystemHistoricalRecoveryEnvironment is request-bound. The peer is an mTLS
// proof, not a recovery grant; D separately locks its current revocation row.
type SystemHistoricalRecoveryEnvironment struct {
	auth      *SystemPeerAuthenticator
	peer      *SystemPeer
	authority SystemHistoricalAuthority
}

func NewSystemHistoricalRecoveryEnvironment(auth *SystemPeerAuthenticator, peer *SystemPeer, authority SystemHistoricalAuthority) (*SystemHistoricalRecoveryEnvironment, error) {
	if auth == nil || peer == nil || peer.owner != auth || nilSystemAdapter(authority) {
		return nil, ErrDenied
	}
	return &SystemHistoricalRecoveryEnvironment{auth: auth, peer: peer, authority: authority}, nil
}

func (e *SystemHistoricalRecoveryEnvironment) PrepareRecovery(ctx context.Context, r pd.RecoveryRequest, op string, finish *pd.RecoveryFinishRequest) (pd.PreparedRecovery, error) {
	if e == nil || e.auth == nil || e.peer == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) || r.Scope != e.auth.c.Scope || !oneOf(op, "load", "claim", "finish") || (op == "finish") != (finish != nil) {
		return pd.PreparedRecovery{}, ErrDenied
	}
	intent, err := newSystemHistoricalWorkloadIntent(ctx, e.auth, e.peer, string(r.EvidenceID))
	if err != nil {
		return pd.PreparedRecovery{}, ErrAuth
	}
	var copied *pd.RecoveryFinishRequest
	if finish != nil {
		v := *finish
		if finish.ImmutableVersion != nil {
			version := *finish.ImmutableVersion
			v.ImmutableVersion = &version
		}
		copied = &v
	}
	a, channel, sample, err := e.authority.PrepareHistoricalAuthority(ctx, r, op, copied)
	if err != nil || nilSystemAdapter(a) || ctx.Err() != nil || !channel.Store.valid() || !channel.Write.valid() || !digestPattern.MatchString(channel.RecoveryProfileHash) || channel.Root == "" {
		return pd.PreparedRecovery{}, ErrDenied
	}
	return pd.PreparedRecovery{Session: &systemHistoricalRecoverySession{SystemHistoricalAuthoritySession: a, intent: intent, request: r, op: op, finish: copied, channel: channel}, CapacityObservedAt: copySystemPublicationSample(sample)}, nil
}

type systemHistoricalRecoverySession struct {
	SystemHistoricalAuthoritySession
	intent      *systemHistoricalWorkloadIntent
	request     pd.RecoveryRequest
	op          string
	finish      *pd.RecoveryFinishRequest
	channel     ProducerEvidenceChannel
	admission   pd.RecoveryAdmission
	requestHash pd.Hash
	binding     string
	record      Record
	stored      systemPendingStored
	locked      bool
}

func (s *systemHistoricalRecoverySession) LockInstallation(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest) error {
	if s == nil || r != s.request || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	return s.SystemHistoricalAuthoritySession.LockInstallation(ctx, tx, r)
}

func (s *systemHistoricalRecoverySession) Authorize(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, requestHash pd.Hash, op string) (pd.RecoveryAdmission, error) {
	if s == nil || r != s.request || op != s.op || tx == nil || ctx == nil || ctx.Err() != nil || s.requestHash != "" {
		return pd.RecoveryAdmission{}, ErrDenied
	}
	var dbNow time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbNow) != nil {
		return pd.RecoveryAdmission{}, ErrUnavailable
	}
	facts, binding, err := s.intent.check(ctx, r.Scope, string(r.EvidenceID), dbNow)
	if err != nil {
		return pd.RecoveryAdmission{}, ErrAuth
	}
	a, err := s.SystemHistoricalAuthoritySession.Authorize(ctx, tx, r, requestHash, op, facts, binding)
	if err != nil {
		return pd.RecoveryAdmission{}, err
	}
	identityUntil, identityErr := a.IdentityExpiresAt.Time()
	deploymentUntil, deploymentErr := a.DeploymentExpiresAt.Time()
	epoch, epochErr := a.RevocationEpoch.Uint64()
	if identityErr != nil || deploymentErr != nil || epochErr != nil || epoch == 0 ||
		a.IdentityHash != pd.Hash(facts.WorkloadIdentityHash) || a.VerifiedRequestHash != requestHash || !a.StatAllowed ||
		identityUntil.After(facts.ExpiresAt) || !dbNow.Before(identityUntil) || !dbNow.Before(deploymentUntil) {
		return pd.RecoveryAdmission{}, ErrDenied
	}
	s.admission, s.requestHash, s.binding = a, requestHash, binding
	return a, nil
}

func (s *systemHistoricalRecoverySession) LockEvidence(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord) (pd.FinishEvidence, error) {
	if s == nil || r != s.request || h.Scope != r.Scope || h.Evidence.EvidenceID != r.EvidenceID || s.requestHash == "" || s.locked || ctx == nil || ctx.Err() != nil {
		return pd.FinishEvidence{}, ErrDenied
	}
	t, ok := tx.(*pd.Transaction)
	if !ok || t == nil {
		return pd.FinishEvidence{}, ErrDenied
	}
	record, err := loadSystemHistoricalRecord(ctx, t, h, s.channel)
	if err != nil {
		return pd.FinishEvidence{}, err
	}
	hash, err := pd.PendingHistoryHash(h)
	if err != nil {
		return pd.FinishEvidence{}, ErrIntegrity
	}
	stored, found, err := loadSystemPublication(ctx, t, record, record.Ref.ImmutableVersion)
	if err != nil || !found {
		if err != nil {
			return pd.FinishEvidence{}, err
		}
		return pd.FinishEvidence{}, ErrIntegrity
	}
	original := systemPublicationOriginal{record: record, historyHash: hash, scope: h.Scope}
	s.record, s.stored, s.locked = record, stored, true
	var immutable *pd.Text
	if record.Ref.ImmutableVersion != "" {
		v := pd.Text(record.Ref.ImmutableVersion)
		immutable = &v
	}
	return pd.FinishEvidence{ClaimEvidence: original.claimEvidence(stored), ImmutableVersion: immutable, Failure: record.Failure}, nil
}

func (s *systemHistoricalRecoverySession) Recheck(ctx context.Context, tx pd.ReadSQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord, now time.Time) error {
	if s == nil || r != s.request || h.Scope != r.Scope || h.Evidence.EvidenceID != r.EvidenceID || s.requestHash == "" || s.binding == "" || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	facts, binding, err := s.intent.check(ctx, r.Scope, string(r.EvidenceID), now)
	if err != nil || pd.Hash(facts.WorkloadIdentityHash) != s.admission.IdentityHash || binding != s.binding {
		return ErrAuth
	}
	identityUntil, identityErr := s.admission.IdentityExpiresAt.Time()
	deploymentUntil, deploymentErr := s.admission.DeploymentExpiresAt.Time()
	if identityErr != nil || deploymentErr != nil || !now.Before(identityUntil) || !now.Before(deploymentUntil) {
		return ErrDenied
	}
	if err := s.SystemHistoricalAuthoritySession.Recheck(ctx, tx, r, h, s.admission, now); err != nil {
		return err
	}
	if !s.locked {
		return ErrIntegrity
	}
	// D already holds this exact A row and its ordered chunks at L8. A rereads
	// them after D's CAS to detect any unexpected mutation before final commit.
	want := s.stored
	ready := ""
	if s.op == "load" {
		ready = s.record.Ref.ImmutableVersion
	} else if s.op == "claim" {
		want.Version++
		until, err := r.ClaimExpiresAt.Time()
		if err != nil {
			return ErrIntegrity
		}
		want.Claim = sql.NullString{String: string(s.requestHash), Valid: true}
		want.ClaimUntil = sql.NullTime{Time: until, Valid: true}
	} else if s.op == "finish" {
		want.Version++
		if s.finish == nil {
			return ErrIntegrity
		}
		want.State = s.finish.State
		want.Failure = "provider_unavailable"
		want.Claim = sql.NullString{}
		want.ClaimUntil = sql.NullTime{}
		if s.finish.State == "ready" {
			if s.finish.ImmutableVersion == nil {
				return ErrIntegrity
			}
			want.Failure = "none"
			ready = string(*s.finish.ImmutableVersion)
		}
	}
	got, found, err := loadSystemPublication(ctx, tx, s.record, ready)
	if err != nil || !found {
		if err != nil {
			return err
		}
		return ErrIntegrity
	}
	if !reflect.DeepEqual(got, want) {
		return ErrIntegrity
	}
	return nil
}

var _ pd.HistoricalRecoveryEnvironment = (*SystemHistoricalRecoveryEnvironment)(nil)
var _ pd.HistoricalRecoverySession = (*systemHistoricalRecoverySession)(nil)
