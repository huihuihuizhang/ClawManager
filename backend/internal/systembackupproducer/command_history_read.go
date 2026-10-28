package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

// HistoricalCommandReceiptAuthority is independent of the old command actor
// and execution handle. A production implementation must authenticate current
// management/history-read permission and revocation for every exact request.
type HistoricalCommandReceiptAuthority interface {
	PrepareCommandReceiptRead(context.Context, CommandRequest) (HistoricalCommandReceiptSession, error)
}

type HistoricalCommandReceiptSession interface {
	AuthorizeCommandReceiptRead(context.Context, SQL, CommandRequest, CommandDigests) (HistoricalReceiptAdmission, error)
	RecheckCommandReceiptRead(context.Context, ReadSQL, CommandRequest, CommandReceiptRecord, time.Time) error
}

type HistoricalCommandReceiptReader struct {
	db        *sql.DB
	scope     Scope
	authority HistoricalCommandReceiptAuthority
	clock     func() time.Time
}

func NewHistoricalCommandReceiptReader(db *sql.DB, scope Scope, authority HistoricalCommandReceiptAuthority) (*HistoricalCommandReceiptReader, error) {
	if db == nil || nilEnvironment(authority) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &HistoricalCommandReceiptReader{db: db, scope: scope, authority: authority, clock: time.Now}, nil
}

// ReadCommandReceipt proves only a past commit. It cannot renew a grant,
// recreate a handle, change the domain, or replay the original mutation.
func (s *HistoricalCommandReceiptReader) ReadCommandReceipt(ctx context.Context, request CommandRequest) (CommandReceiptRecord, error) {
	if s == nil || s.db == nil || nilEnvironment(s.authority) || ctx == nil || ctx.Err() != nil {
		return CommandReceiptRecord{}, ErrGuardRequired
	}
	if request.Scope != s.scope {
		return CommandReceiptRecord{}, ErrInvalid
	}
	digests, err := CommandHashes(request)
	if err != nil {
		return CommandReceiptRecord{}, err
	}
	request = detached(request)
	session, err := s.authority.PrepareCommandReceiptRead(ctx, detached(request))
	if err != nil {
		return CommandReceiptRecord{}, err
	}
	if nilEnvironment(session) {
		return CommandReceiptRecord{}, ErrGuardRequired
	}
	p := &historicalCommandReceiptPolicy{request: request, digests: digests, session: session}
	tx, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return CommandReceiptRecord{}, err
	}
	tx.clock = s.clock
	committed, err := tx.Run(ctx, func(context.Context, *Transaction) error { return nil })
	if !committed.Committed() {
		return CommandReceiptRecord{}, err
	}
	return detached(p.receipt), err
}

type historicalCommandReceiptPolicy struct {
	request CommandRequest
	digests CommandDigests
	session HistoricalCommandReceiptSession
	receipt CommandReceiptRecord
}

func (p *historicalCommandReceiptPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	admission, err := p.session.AuthorizeCommandReceiptRead(ctx, tx, detached(p.request), p.digests)
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

func (p *historicalCommandReceiptPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.digests.Request {
		return ErrGuardRequired
	}
	return p.session.RecheckCommandReceiptRead(ctx, tx, detached(p.request), detached(p.receipt), now)
}
