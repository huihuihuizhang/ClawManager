package systembackupevidence

import (
	"context"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemResultAuthority must independently authenticate the COMPLETE evaluator
// request, current identity/revocation and projection mapping. Ready evidence is
// a storage fact, never a capability verdict. Receipt read authority is separate.
// All callbacks run under D's lock order; Recheck may only read prelocked facts.
type SystemResultAuthority interface {
	PrepareResultAuthority(context.Context, pd.ResultBinding, Record) (SystemResultAuthoritySession, *time.Time, error)
}
type SystemResultAuthoritySession interface {
	LockInstallation(context.Context, pd.SQL, pd.ResultBinding) error
	Authenticate(context.Context, pd.SQL, pd.ResultBinding, pd.DomainRecord) (pd.ResultAdmission, error)
	LockHost(context.Context, pd.SQL, pd.ResultBinding, pd.GrantRecord) error
	LockProjectionReferences(context.Context, pd.SQL, pd.ResultBinding, pd.ResultFacts) (pd.ResultProjection, error)
	Reserve(context.Context, pd.SQL, pd.ResultBinding, uint64) error
	Audit(context.Context, pd.SQL, pd.ResultBinding, string) error
	ApplyProjections(context.Context, pd.SQL, pd.ResultBinding, pd.ResultFacts) error
	Recheck(context.Context, pd.ReadSQL, pd.ResultBinding, pd.ResultFacts, time.Time) error
}

// The live producer retains Prepared. Process-loss/historical reconstruction
// requires its own authenticated environment, not an invented Prepared value.
type SystemResultEnvironment struct {
	authority SystemResultAuthority
	original  systemPublicationOriginal
	channel   ProducerEvidenceChannel
}

func NewSystemResultEnvironment(a SystemResultAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord) (*SystemResultEnvironment, error) {
	if nilSystemAdapter(a) {
		return nil, ErrDenied
	}
	o, err := newSystemPublicationOriginal(p, c, h)
	if err != nil {
		return nil, err
	}
	return &SystemResultEnvironment{a, o, c}, nil
}

func (e *SystemResultEnvironment) PrepareResult(ctx context.Context, b pd.ResultBinding) (pd.PreparedResult, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) || b.Request.Scope != e.original.scope {
		return pd.PreparedResult{}, ErrDenied
	}
	h, err := pd.ResultBindingHash(b)
	if err != nil {
		return pd.PreparedResult{}, ErrInvalid
	}
	// Strict decoding also detaches nested admission, slots and version pointers
	// before exposing them to the authority. Hashes bind the original full input.
	var request pd.ResultRequest
	if pd.DecodeRecord(canonical(b.Request), &request) != nil || request.Evidence.ImmutableVersion == nil {
		return pd.PreparedResult{}, ErrInvalid
	}
	digests, err := pd.ResultHashes(request)
	if err != nil {
		return pd.PreparedResult{}, ErrInvalid
	}
	version := string(*request.Evidence.ImmutableVersion)
	want, err := producerBinding(e.original.record.Manifest, e.channel, version)
	if err != nil || version == "" || !reflect.DeepEqual(want, request.Evidence) {
		return pd.PreparedResult{}, ErrIntegrity
	}
	b.Request = request
	a, sample, err := e.authority.PrepareResultAuthority(ctx, b, e.original.copyRecord())
	if err != nil || nilSystemAdapter(a) || ctx.Err() != nil {
		return pd.PreparedResult{}, ErrDenied
	}
	return pd.PreparedResult{Session: &systemResultSession{SystemResultAuthoritySession: a, original: e.original, channel: e.channel, bindingHash: h, digests: digests, version: version}, CapacityObservedAt: copySystemPublicationSample(sample)}, nil
}

type systemResultSession struct {
	SystemResultAuthoritySession
	original       systemPublicationOriginal
	channel        ProducerEvidenceChannel
	bindingHash    pd.Hash
	digests        pd.ResultDigests
	version        string
	locked, failed bool
	stored         systemPendingStored
}

func (s *systemResultSession) matches(ctx context.Context, b pd.ResultBinding) bool {
	if s == nil || s.failed || ctx == nil || ctx.Err() != nil {
		return false
	}
	h, err := pd.ResultBindingHash(b)
	return err == nil && h == s.bindingHash
}

func (s *systemResultSession) evidence(row systemPendingStored) (pd.ResultEvidence, error) {
	b, err := producerBinding(s.original.record.Manifest, s.channel, s.version)
	if err != nil {
		return pd.ResultEvidence{}, err
	}
	return pd.ResultEvidence{Evidence: b, RowVersion: pd.Counter(systemPendingCounter(row.Version)), State: row.State, Failure: row.Failure, RetentionExpiresAt: systemPublicationTimestamp(s.original.record.ExpiresAt), ProtectedUntil: systemPublicationTimestamp(s.original.record.ProtectedUntil)}, nil
}

func (s *systemResultSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.ResultBinding, f pd.ResultFacts) (pd.ResultEvidence, error) {
	if s == nil {
		return pd.ResultEvidence{}, ErrDenied
	}
	if !s.matches(ctx, b) || s.locked || f.Replayed || f.History == nil || !s.original.historyMatches(*f.History) {
		s.failed = true
		return pd.ResultEvidence{}, ErrIntegrity
	}
	if t, ok := tx.(*pd.Transaction); !ok || t == nil {
		s.failed = true
		return pd.ResultEvidence{}, ErrDenied
	}
	row, found, err := loadSystemPublication(ctx, tx, s.original.record, s.version)
	if err != nil {
		s.failed = true
		return pd.ResultEvidence{}, err
	}
	if !found || row.Claim.Valid || row.ClaimUntil.Valid || pd.Counter(systemPendingCounter(row.Version)) != b.Request.ExpectedEvidenceVersion {
		s.failed = true
		return pd.ResultEvidence{}, ErrIntegrity
	}
	s.locked, s.stored = true, row
	return s.evidence(row)
}

func (s *systemResultSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ResultBinding, f pd.ResultFacts, now time.Time) error {
	if !s.matches(ctx, b) || f.Receipt == nil || f.Receipt.Scope != b.Request.Scope || f.Receipt.ReceiptKeyHash != s.digests.Key || f.Receipt.RequestHash != s.digests.Request || !reflect.DeepEqual(f.Receipt.Request, b.Request) {
		return ErrIntegrity
	}
	if f.Replayed {
		// D's receipt branch takes no execution/evidence/projection locks. Do not
		// introduce L8 reads or refresh storage/retention on this historical path.
		if s.locked || !f.Admission.ReadReceipt || f.Evidence != nil || f.History != nil || f.Grant != nil || f.Run != nil || f.Target != nil || f.Projection != nil || len(f.References) != 0 {
			return ErrIntegrity
		}
		return s.SystemResultAuthoritySession.Recheck(ctx, tx, b, f, now)
	}
	if !s.locked || f.History == nil || !s.original.historyMatches(*f.History) || f.Evidence == nil {
		return ErrIntegrity
	}
	want, err := s.evidence(s.stored)
	if err != nil || !reflect.DeepEqual(*f.Evidence, want) || want.RetentionExpiresAt < f.Receipt.RetentionExpiresAt || want.ProtectedUntil < f.Receipt.RetentionExpiresAt {
		return ErrIntegrity
	}
	if err := s.SystemResultAuthoritySession.Recheck(ctx, tx, b, f, now); err != nil {
		return err
	}
	row, found, err := loadSystemPublication(ctx, tx, s.original.record, s.version)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(row, s.stored) {
		return ErrIntegrity
	}
	return nil
}

var _ pd.ResultEnvironment = (*SystemResultEnvironment)(nil)
