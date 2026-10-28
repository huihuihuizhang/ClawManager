package systembackupevidence

import (
	"context"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemPendingAuthority supplies the actual installation/identity/host/ref,
// retention, capacity and audit policy. The Record argument is a detached copy
// of A's successful preparation, not permission to admit it. Implementations
// must independently authenticate its provenance and entire historical binding.
// AdditionalCost must cover A registry/chunks, legacy refs and audits once.
type SystemPendingAuthority interface {
	PreparePendingAuthority(context.Context, pd.PendingBinding, Record) (SystemPendingAuthoritySession, *time.Time, error)
}
type SystemPendingAuthoritySession interface {
	LockInstallation(context.Context, pd.SQL, pd.PendingBinding) error
	Authenticate(context.Context, pd.SQL, pd.PendingBinding, pd.DomainRecord) (pd.PendingAdmission, error)
	LockHost(context.Context, pd.SQL, pd.PendingBinding, pd.GrantRecord) error
	LockReferences(context.Context, pd.SQL, pd.PendingBinding, pd.PendingFacts) error
	Reserve(context.Context, pd.SQL, pd.PendingBinding, uint64) error
	Audit(context.Context, pd.SQL, pd.PendingBinding, string) error
	// Only current reads of already locked authority; no new locks or I/O.
	Recheck(context.Context, pd.ReadSQL, pd.PendingBinding, pd.PendingFacts, time.Time) error
}

// SystemPendingEnvironment composes mandatory authority with A's real SQL rows.
// Pass it to D NewPending. It neither owns a DB nor exposes Commit/Begin; D owns
// the transaction and always invokes both authority and A final checks.
type SystemPendingEnvironment struct {
	authority   SystemPendingAuthority
	record      Record
	historyHash pd.Hash
}

func NewSystemPendingEnvironment(authority SystemPendingAuthority, prepared Prepared, channel ProducerEvidenceChannel, history pd.HistoricalBindingRecord) (*SystemPendingEnvironment, error) {
	if nilSystemAdapter(authority) {
		return nil, ErrDenied
	}
	r, h, err := systemPreparedRecord(prepared, channel, history)
	if err != nil {
		return nil, err
	}
	return &SystemPendingEnvironment{authority: authority, record: r, historyHash: h}, nil
}

func systemPreparedRecord(prepared Prepared, channel ProducerEvidenceChannel, history pd.HistoricalBindingRecord) (Record, pd.Hash, error) {
	return systemManifestRecord(prepared.Manifest(), channel, history)
}

func systemManifestRecord(m Manifest, channel ProducerEvidenceChannel, history pd.HistoricalBindingRecord) (Record, pd.Hash, error) {
	// D's strict record decoder validates the complete C1 shape as well as types.
	var h pd.HistoricalBindingRecord
	if pd.DecodeRecord(canonical(history), &h) != nil || h.Evidence.ImmutableVersion != nil {
		return Record{}, "", ErrInvalid
	}
	created, e1 := h.CreatedAt.Time()
	expires, e2 := h.RetentionExpiresAt.Time()
	deadline, e3 := h.OwnerWriteExpiresAt.Time()
	observation, e4 := h.ObservationExpiresAt.Time()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || expires.Before(observation) || string(h.Scope.Installation) != m.Identity.Installation {
		return Record{}, "", ErrInvalid
	}
	r := Record{Manifest: m, Ref: Ref{channel.Store.Identity, channel.Store.Version, string(h.RelativeKey), ""}, State: "pending", Failure: "none", RowVersion: 1, CreatedAt: created, ExpiresAt: expires, ProtectedUntil: expires, OwnerDeadline: deadline}
	if MatchProducerBinding(r, channel, h.Evidence) != nil {
		return Record{}, "", ErrIntegrity
	}
	hash, err := pd.PendingHistoryHash(h)
	if err != nil {
		return Record{}, "", ErrInvalid
	}
	return r, hash, nil
}

func (e *SystemPendingEnvironment) PreparePending(ctx context.Context, b pd.PendingBinding) (pd.PreparedPending, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) {
		return pd.PreparedPending{}, ErrDenied
	}
	h, err := pd.PendingHistoryHash(b.Request.History)
	bh, bindErr := pd.PendingBindingHash(b)
	if err != nil || bindErr != nil || h != e.historyHash {
		return pd.PreparedPending{}, ErrIntegrity
	}
	r := e.record
	r.Manifest.Chunks = append([]Chunk(nil), r.Manifest.Chunks...)
	a, sample, err := e.authority.PreparePendingAuthority(ctx, b, r)
	if err != nil || nilSystemAdapter(a) || ctx.Err() != nil {
		return pd.PreparedPending{}, ErrDenied
	}
	// Never retain authority-owned mutable report pointers.
	var pinned *time.Time
	if sample != nil {
		v := *sample
		pinned = &v
	}
	s := &systemPendingSession{SystemPendingAuthoritySession: a, record: e.record, historyHash: e.historyHash, bindingHash: bh}
	return pd.PreparedPending{Session: s, CapacityObservedAt: pinned}, nil
}

type systemPendingSession struct {
	SystemPendingAuthoritySession
	record                   Record
	historyHash, bindingHash pd.Hash
	tx                       *pd.Transaction
	stored                   systemPendingStored
	locked, inserted, failed bool
}

func (s *systemPendingSession) matches(ctx context.Context, b pd.PendingBinding) bool {
	if s == nil || s.failed || ctx == nil || ctx.Err() != nil {
		return false
	}
	h, e := pd.PendingBindingHash(b)
	return e == nil && h == s.bindingHash
}
func (s *systemPendingSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.PendingBinding, facts pd.PendingFacts) (pd.PendingEvidence, error) {
	deny := func() (pd.PendingEvidence, error) { s.failed = true; return pd.PendingEvidence{}, ErrIntegrity }
	if !s.matches(ctx, b) || s.locked {
		return deny()
	}
	t, ok := tx.(*pd.Transaction)
	if !ok || t == nil {
		return deny()
	}
	s.tx = t
	row, found, err := loadSystemPending(ctx, tx, s.record)
	if err != nil {
		s.failed = true
		return pd.PendingEvidence{}, err // already bounded by the A SQL loader
	}
	if found != facts.Replayed {
		return deny()
	}
	s.locked = true
	s.stored = row
	state, version := "absent", pd.ZeroCounter("0")
	if found {
		state, version = row.State, pd.ZeroCounter(systemPendingCounter(row.Version))
	}
	return pd.PendingEvidence{Existing: found, EvidenceID: b.Request.History.Evidence.EvidenceID, HistoryHash: s.historyHash, RowVersion: version, State: state}, nil
}

func (s *systemPendingSession) InsertEvidence(ctx context.Context, tx pd.SQL, b pd.PendingBinding, facts pd.PendingFacts) error {
	if !s.matches(ctx, b) || !s.locked || s.inserted || s.stored.ID != 0 || tx != s.tx || facts.Replayed {
		s.failed = true
		return ErrIntegrity
	}
	id, err := insertSystemPending(ctx, s.tx, s.record)
	if err != nil {
		s.failed = true
		return err
	}
	s.stored = systemPendingStored{ID: id, State: "pending", Failure: "none", Version: 1, Health: "unknown"}
	s.inserted = true
	return nil
}

func (s *systemPendingSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.PendingBinding, facts pd.PendingFacts, now time.Time) error {
	if !s.matches(ctx, b) || !s.locked || s.stored.ID <= 0 || (!facts.Replayed && !s.inserted) || !facts.Evidence.Existing || facts.Evidence.EvidenceID != b.Request.History.Evidence.EvidenceID || facts.Evidence.HistoryHash != s.historyHash || facts.Evidence.State != s.stored.State || string(facts.Evidence.RowVersion) != systemPendingCounter(s.stored.Version) {
		return ErrIntegrity
	}
	if err := s.SystemPendingAuthoritySession.Recheck(ctx, tx, b, facts, now); err != nil {
		return err
	}
	// These exact rows/ranges were already locked at L8; FOR UPDATE is a current
	// read, not a new business lock. It includes mutations by result-audit code.
	row, found, err := loadSystemPending(ctx, tx, s.record)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(row, s.stored) {
		return ErrIntegrity
	}
	return nil
}

var _ pd.PendingEnvironment = (*SystemPendingEnvironment)(nil)
var _ pd.PendingSession = (*systemPendingSession)(nil)
