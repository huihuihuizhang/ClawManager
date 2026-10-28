package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

// HistoricalReceiptAuthority is an independent read authority. It must bind a
// current identity and revocation state to the complete request, even when the
// producer domain is closed or the original execution grant has expired.
// It cannot issue an ExecutionHandle or authorize a provider operation.
type HistoricalReceiptAuthority interface {
	PrepareReceiptRead(context.Context, ResultRequest) (HistoricalReceiptSession, error)
}

// Each read gets its own session. The implementation locks its current identity
// and revocation facts before returning an admission, then checks those same
// facts once more after the receipt has been locked.
type HistoricalReceiptSession interface {
	AuthorizeReceiptRead(context.Context, SQL, ResultRequest, ResultDigests) (HistoricalReceiptAdmission, error)
	RecheckReceiptRead(context.Context, ReadSQL, ResultRequest, ReceiptRecord, time.Time) error
}

type HistoricalReceiptAdmission struct {
	VerifiedRequestHash Hash
	IdentityExpiresAt   Timestamp
	ReadAllowed         bool
}

type HistoricalReceiptReader struct {
	db        *sql.DB
	scope     Scope
	authority HistoricalReceiptAuthority
	clock     func() time.Time
}

func NewHistoricalReceiptReader(db *sql.DB, scope Scope, authority HistoricalReceiptAuthority) (*HistoricalReceiptReader, error) {
	if db == nil || nilEnvironment(authority) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &HistoricalReceiptReader{db: db, scope: scope, authority: authority, clock: time.Now}, nil
}

// ReadResultReceipt returns only an immutable historical receipt. A matching
// request key alone never grants access; the independent authority must approve
// every call. No domain, grant, run, evidence, or provider state is consulted.
func (s *HistoricalReceiptReader) ReadResultReceipt(ctx context.Context, request ResultRequest) (ReceiptRecord, error) {
	if s == nil || s.db == nil || nilEnvironment(s.authority) || ctx == nil || ctx.Err() != nil {
		return ReceiptRecord{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return ReceiptRecord{}, ErrInvalid
	}
	digests, err := ResultHashes(request)
	if err != nil {
		return ReceiptRecord{}, err
	}
	request = detached(request)
	session, err := s.authority.PrepareReceiptRead(ctx, detached(request))
	if err != nil {
		return ReceiptRecord{}, err
	}
	if nilEnvironment(session) {
		return ReceiptRecord{}, ErrGuardRequired
	}
	p := &historicalReceiptPolicy{request: request, digests: digests, session: session}
	tx, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return ReceiptRecord{}, err
	}
	tx.clock = s.clock
	committed, err := tx.Run(ctx, func(context.Context, *Transaction) error { return nil })
	if !committed.Committed() {
		return ReceiptRecord{}, err
	}
	return detached(p.receipt), err
}

type historicalReceiptPolicy struct {
	request ResultRequest
	digests ResultDigests
	session HistoricalReceiptSession
	receipt ReceiptRecord
}

func (p *historicalReceiptPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	admission, err := p.session.AuthorizeReceiptRead(ctx, tx, detached(p.request), p.digests)
	if err != nil {
		return GuardPlan{}, err
	}
	if !admission.ReadAllowed || admission.VerifiedRequestHash != p.digests.Request {
		return GuardPlan{}, ErrGuardRequired
	}
	identityUntil, err := admission.IdentityExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	locked, err := tx.LockRecord(ctx, RecordKey{Hash: p.digests.Key}, &p.receipt)
	if err != nil {
		return GuardPlan{}, err
	}
	if !locked.Found() {
		return GuardPlan{}, ErrConflict
	}
	if p.receipt.ReceiptKeyHash != p.digests.Key || p.receipt.RequestHash != p.digests.Request || !reflect.DeepEqual(p.receipt.Request, p.request) {
		return GuardPlan{}, ErrConflict
	}
	retention, err := p.receipt.RetentionExpiresAt.Time()
	if err != nil {
		return GuardPlan{}, ErrInvalid
	}
	return GuardPlan{BindingHash: p.digests.Request, Deadlines: []time.Time{identityUntil, retention}}, nil
}

func (p *historicalReceiptPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.digests.Request {
		return ErrGuardRequired
	}
	return p.session.RecheckReceiptRead(ctx, tx, detached(p.request), detached(p.receipt), now)
}
