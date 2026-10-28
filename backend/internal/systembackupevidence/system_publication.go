package systembackupevidence

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Production authorities must authenticate current deployment/revocation/host,
// references, capacity and audit independently. No successful implementation is
// provided. Prepared/history are comparison inputs, never caller credentials.
type SystemClaimAuthority interface {
	PrepareClaimAuthority(context.Context, pd.ClaimRequestBinding, bool, Record) (SystemClaimAuthoritySession, *time.Time, error)
}
type SystemClaimAuthoritySession interface {
	LockInstallation(context.Context, pd.SQL, pd.ClaimRequestBinding) error
	Authenticate(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.DomainRecord, bool) (pd.ClaimAdmission, error)
	LockHost(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.GrantRecord) error
	LockReferences(context.Context, pd.SQL, pd.ClaimRequestBinding, pd.ClaimFacts) (pd.ReferenceApproval, error)
	Reserve(context.Context, pd.SQL, pd.ClaimRequestBinding, uint64) error
	Audit(context.Context, pd.SQL, pd.ClaimRequestBinding, string) error
	Recheck(context.Context, pd.ReadSQL, pd.ClaimRequestBinding, pd.ClaimFacts, time.Time) error
}

// Finish authority must additionally verify C result provenance for the entire
// claim/store/key/manifest/version/time tuple. PUT success or a supplied hash is
// not proof. All remote work happens before PrepareFinishAuthority and BEGIN.
type SystemFinishAuthority interface {
	PrepareFinishAuthority(context.Context, pd.FinishBinding, Record) (SystemFinishAuthoritySession, *time.Time, error)
}
type SystemFinishAuthoritySession interface {
	LockInstallation(context.Context, pd.SQL, pd.FinishBinding) error
	Authenticate(context.Context, pd.SQL, pd.FinishBinding, pd.DomainRecord) (pd.FinishAdmission, error)
	LockHost(context.Context, pd.SQL, pd.FinishBinding, pd.GrantRecord) error
	LockReferences(context.Context, pd.SQL, pd.FinishBinding, pd.FinishFacts) (pd.ReferenceApproval, error)
	Reserve(context.Context, pd.SQL, pd.FinishBinding, uint64) error
	Audit(context.Context, pd.SQL, pd.FinishBinding, string) error
	Recheck(context.Context, pd.ReadSQL, pd.FinishBinding, pd.FinishFacts, time.Time) error
}
type systemPublicationOriginal struct {
	record      Record
	historyHash pd.Hash
	scope       pd.Scope
	runID       pd.ID
	targetHash  pd.Hash
	inputHash   pd.Hash
	history     pd.HistoricalBindingRecord
}

func newSystemPublicationOriginal(p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord) (systemPublicationOriginal, error) {
	r, hash, e := systemPreparedRecord(p, c, h)
	if e != nil {
		return systemPublicationOriginal{}, e
	}
	var fixed pd.HistoricalBindingRecord
	if pd.DecodeRecord(canonical(h), &fixed) != nil {
		return systemPublicationOriginal{}, ErrInvalid
	}
	return systemPublicationOriginal{record: r, historyHash: hash, scope: fixed.Scope, runID: fixed.RunID, targetHash: fixed.TargetHash, inputHash: fixed.InputHash, history: fixed}, nil
}
func (o systemPublicationOriginal) copyRecord() Record {
	r := o.record
	r.Manifest.Chunks = append([]Chunk(nil), r.Manifest.Chunks...)
	return r
}
func copySystemPublicationSample(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
func systemPublicationTimestamp(t time.Time) pd.Timestamp {
	return pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}
func (o systemPublicationOriginal) historyMatches(h pd.HistoricalBindingRecord) bool {
	v, e := pd.PendingHistoryHash(h)
	return e == nil && v == o.historyHash
}
func (o systemPublicationOriginal) claimEvidence(row systemPendingStored) pd.ClaimEvidence {
	m := pd.Hash(hash(canonical(o.record.Manifest)))
	v := pd.CallEvidence{EvidenceID: pd.EvidenceID(o.record.Manifest.Identity.ID), OwnerType: "system", OwnerID: o.scope.Installation, EvidenceType: "capability_snapshot", State: row.State, RowVersion: pd.ZeroCounter(systemPendingCounter(row.Version)), ManifestHash: &m}
	if row.Claim.Valid {
		owner, until := pd.ID(row.Claim.String), systemPublicationTimestamp(row.ClaimUntil.Time)
		v.ClaimOwner = &owner
		v.ClaimExpiresAt = &until
	}
	return pd.ClaimEvidence{Evidence: v, HistoryHash: o.historyHash, RetentionExpiresAt: systemPublicationTimestamp(o.record.ExpiresAt), ProtectedUntil: systemPublicationTimestamp(o.record.ProtectedUntil)}
}

// These environments are for the live producer that retains original Prepared.
// Historical recovery after process loss needs a separate authenticated loader.
type SystemClaimEnvironment struct {
	authority SystemClaimAuthority
	original  systemPublicationOriginal
}
type SystemFinishEnvironment struct {
	authority SystemFinishAuthority
	original  systemPublicationOriginal
}

func NewSystemClaimEnvironment(a SystemClaimAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord) (*SystemClaimEnvironment, error) {
	if nilSystemAdapter(a) {
		return nil, ErrDenied
	}
	o, e := newSystemPublicationOriginal(p, c, h)
	if e != nil {
		return nil, e
	}
	return &SystemClaimEnvironment{a, o}, nil
}
func NewSystemFinishEnvironment(a SystemFinishAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord) (*SystemFinishEnvironment, error) {
	if nilSystemAdapter(a) {
		return nil, ErrDenied
	}
	o, e := newSystemPublicationOriginal(p, c, h)
	if e != nil {
		return nil, e
	}
	return &SystemFinishEnvironment{a, o}, nil
}
func (e *SystemClaimEnvironment) PrepareClaim(ctx context.Context, b pd.ClaimRequestBinding, readback bool) (pd.PreparedClaim, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) || b.Scope != e.original.scope || string(b.Request.EvidenceID) != e.original.record.Manifest.Identity.ID {
		return pd.PreparedClaim{}, ErrDenied
	}
	h, err := pd.ClaimRequestHash(b)
	if err != nil {
		return pd.PreparedClaim{}, ErrInvalid
	}
	a, sample, err := e.authority.PrepareClaimAuthority(ctx, b, readback, e.original.copyRecord())
	if err != nil || nilSystemAdapter(a) || ctx.Err() != nil {
		return pd.PreparedClaim{}, ErrDenied
	}
	return pd.PreparedClaim{Session: &systemClaimSession{SystemClaimAuthoritySession: a, original: e.original, bindingHash: h, readback: readback}, CapacityObservedAt: copySystemPublicationSample(sample)}, nil
}

type systemClaimSession struct {
	SystemClaimAuthoritySession
	original                 systemPublicationOriginal
	bindingHash              pd.Hash
	readback, locked, failed bool
	stored                   systemPendingStored
}

func (s *systemClaimSession) matches(ctx context.Context, b pd.ClaimRequestBinding, f pd.ClaimFacts) bool {
	if s == nil || s.failed || ctx == nil || ctx.Err() != nil || f.Readback != s.readback || !s.original.historyMatches(f.History) {
		return false
	}
	h, e := pd.ClaimRequestHash(b)
	return e == nil && h == s.bindingHash
}
func (s *systemClaimSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, f pd.ClaimFacts) (pd.ClaimEvidence, error) {
	if !s.matches(ctx, b, f) || s.locked {
		s.failed = true
		return pd.ClaimEvidence{}, ErrIntegrity
	}
	if t, ok := tx.(*pd.Transaction); !ok || t == nil {
		s.failed = true
		return pd.ClaimEvidence{}, ErrDenied
	}
	r, found, e := loadSystemPending(ctx, tx, s.original.record)
	if e != nil || !found {
		s.failed = true
		if e != nil {
			return pd.ClaimEvidence{}, e
		}
		return pd.ClaimEvidence{}, ErrIntegrity
	}
	s.locked = true
	s.stored = r
	return s.original.claimEvidence(r), nil
}
func (s *systemClaimSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ClaimRequestBinding, f pd.ClaimFacts, now time.Time) error {
	if !s.matches(ctx, b, f) || !s.locked {
		return ErrIntegrity
	}
	want := s.stored
	version, err := b.Request.ExpectedEvidenceVersion.SQLInt64()
	if err != nil || version == int64(^uint64(0)>>1) {
		return ErrIntegrity
	}
	expires, err := b.Request.ExpiresAt.Time()
	if err != nil {
		return ErrIntegrity
	}
	if s.readback {
		if want.Version != version+1 || !want.Claim.Valid || want.Claim.String != string(s.bindingHash) || !want.ClaimUntil.Valid || !want.ClaimUntil.Time.Equal(expires) {
			return ErrIntegrity
		}
	} else {
		if want.Version != version {
			return ErrIntegrity
		}
		want.Version++
		want.Claim = sql.NullString{String: string(s.bindingHash), Valid: true}
		want.ClaimUntil = sql.NullTime{Time: expires, Valid: true}
	}
	if !reflect.DeepEqual(f.Evidence, s.original.claimEvidence(want)) {
		return ErrIntegrity
	}
	if err := s.SystemClaimAuthoritySession.Recheck(ctx, tx, b, f, now); err != nil {
		return err
	}
	got, found, err := loadSystemPending(ctx, tx, s.original.record)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(got, want) {
		return ErrIntegrity
	}
	return nil
}

func (e *SystemFinishEnvironment) PrepareFinish(ctx context.Context, b pd.FinishBinding) (pd.PreparedFinish, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) || b.Scope != e.original.scope || string(b.Claim.EvidenceID) != e.original.record.Manifest.Identity.ID {
		return pd.PreparedFinish{}, ErrDenied
	}
	h, err := pd.FinishBindingHash(b)
	if err != nil {
		return pd.PreparedFinish{}, ErrInvalid
	}
	// Keep every scalar/hash binding, but detach the optional version pointer
	// before it crosses the authority boundary.
	if b.Request.ImmutableVersion != nil {
		v := *b.Request.ImmutableVersion
		b.Request.ImmutableVersion = &v
	}
	a, sample, err := e.authority.PrepareFinishAuthority(ctx, b, e.original.copyRecord())
	if err != nil || nilSystemAdapter(a) || ctx.Err() != nil {
		return pd.PreparedFinish{}, ErrDenied
	}
	return pd.PreparedFinish{Session: &systemFinishSession{SystemFinishAuthoritySession: a, original: e.original, bindingHash: h}, CapacityObservedAt: copySystemPublicationSample(sample)}, nil
}

type systemFinishSession struct {
	SystemFinishAuthoritySession
	original       systemPublicationOriginal
	bindingHash    pd.Hash
	locked, failed bool
	stored         systemPendingStored
}

func (s *systemFinishSession) matches(ctx context.Context, b pd.FinishBinding, f pd.FinishFacts) bool {
	if s == nil || s.failed || ctx == nil || ctx.Err() != nil || !s.original.historyMatches(f.History) {
		return false
	}
	h, e := pd.FinishBindingHash(b)
	return e == nil && h == s.bindingHash
}
func (s *systemFinishSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.FinishBinding, f pd.FinishFacts) (pd.FinishEvidence, error) {
	if !s.matches(ctx, b, f) || s.locked {
		s.failed = true
		return pd.FinishEvidence{}, ErrIntegrity
	}
	if t, ok := tx.(*pd.Transaction); !ok || t == nil {
		s.failed = true
		return pd.FinishEvidence{}, ErrDenied
	}
	r, found, e := loadSystemPending(ctx, tx, s.original.record)
	if e != nil || !found {
		s.failed = true
		if e != nil {
			return pd.FinishEvidence{}, e
		}
		return pd.FinishEvidence{}, ErrIntegrity
	}
	s.locked = true
	s.stored = r
	return pd.FinishEvidence{ClaimEvidence: s.original.claimEvidence(r), Failure: r.Failure}, nil
}
func (s *systemFinishSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.FinishBinding, f pd.FinishFacts, now time.Time) error {
	if !s.matches(ctx, b, f) || !s.locked {
		return ErrIntegrity
	}
	want := s.stored
	version, err := b.Claim.EvidenceVersion.SQLInt64()
	if err != nil || version == int64(^uint64(0)>>1) {
		return ErrIntegrity
	}
	expires, err := b.Claim.ExpiresAt.Time()
	if err != nil || want.Version != version || !want.Claim.Valid || want.Claim.String != string(b.Claim.Owner) || !want.ClaimUntil.Valid || !want.ClaimUntil.Time.Equal(expires) {
		return ErrIntegrity
	}
	want.Version++
	want.State = b.Request.State
	want.Failure = "provider_unavailable"
	want.Claim = sql.NullString{}
	want.ClaimUntil = sql.NullTime{}
	ready := ""
	var immutable *pd.Text
	if b.Request.State == "ready" {
		want.Failure = "none"
		v := *b.Request.ImmutableVersion
		immutable = &v
		ready = string(v)
	}
	expected := pd.FinishEvidence{ClaimEvidence: s.original.claimEvidence(want), ImmutableVersion: immutable, Failure: want.Failure}
	if !reflect.DeepEqual(f.Evidence, expected) {
		return ErrIntegrity
	}
	if err := s.SystemFinishAuthoritySession.Recheck(ctx, tx, b, f, now); err != nil {
		return err
	}
	got, found, err := loadSystemPublication(ctx, tx, s.original.record, ready)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(got, want) {
		return ErrIntegrity
	}
	return nil
}

var _ pd.ClaimEnvironment = (*SystemClaimEnvironment)(nil)
var _ pd.FinishEnvironment = (*SystemFinishEnvironment)(nil)
