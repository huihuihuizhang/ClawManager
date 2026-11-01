package systembackupcontroller

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// HeldExecutionAuthorizationGuard keeps the original owner callback while
// preparing its closed signed identity after CURRENT deployment/file checks.
// The original guard alone then reads current owner and held SQL facts AFTER
// this callback returns. Preparation itself grants no SQL/provider authority.
// Other owners and phases retain their independent SQL checks.
type HeldExecutionAuthorizationGuard interface {
	ExecutionAuthorizationGuard
	SupportsHeldExecutionRecheck() bool
	PrepareHeldExecutionRecheck(context.Context, *sql.Tx, d.Authority, time.Time, *HeldExecutionRead) error
}

type heldExecutionOwnerFacts struct {
	profile                   []byte
	profileHash               string
	enabled                   bool
	account, server, database string
}

// HeldExecutionRead is an opaque synchronous callback capability created only
// by the original guard. It conveys no cached permission: its one consumption
// performs complete CURRENT locking reads and an independent SQL clock AFTER
// result delivery. A zero, copied, foreign, unused or closed read cannot pass
// the originating guard's finish check. Copies share private lifecycle state
// and retain the original instance anchor; copying back cannot reset it.
type HeldExecutionRead struct {
	state *heldExecutionReadState
}

type heldExecutionReadState struct {
	mu        sync.Mutex
	origin    *HeldExecutionRead
	ctx       context.Context
	tx        *sql.Tx
	store     SQLExecutionAuthority
	authority d.Authority
	first     executionSnapshot
	active    bool
	used      bool
	identity  *PinnedExecutionIdentity
	ownerNow  time.Time
}

func newHeldExecutionRead(ctx context.Context, tx *sql.Tx, store SQLExecutionAuthority, a d.Authority, first executionSnapshot) *HeldExecutionRead {
	read := &HeldExecutionRead{}
	read.state = &heldExecutionReadState{origin: read, ctx: ctx, tx: tx, store: store, authority: a, first: first, active: true}
	return read
}

func (r *HeldExecutionRead) registerOwner(ctx context.Context, tx *sql.Tx, a d.Authority, identity *PinnedExecutionIdentity, now time.Time) error {
	if r == nil || r.state == nil {
		return ErrExecutionAuthority
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != r || !s.active || s.used || absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx != s.ctx || ctx.Err() != nil || tx == nil || tx != s.tx || a != s.authority || identity == nil || now.IsZero() {
		return ErrExecutionAuthority
	}
	s.used = true
	s.identity, s.ownerNow = identity, now
	return nil
}

func (r *HeldExecutionRead) finish() (executionSnapshot, error) {
	if r == nil || r.state == nil {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != r || !s.active {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	s.active = false
	if !s.used || s.identity == nil {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	// The original owner callback has RETURNED. This preserves the original
	// callback-before-final-facts order and observes any same-transaction
	// changes the callback made, while combining both complete current reads.
	var facts heldExecutionOwnerFacts
	v, err := s.store.readHeldCapture(s.ctx, s.tx, s.authority, s.first, &facts)
	identity, a, now := s.identity, s.authority, s.ownerNow
	if err != nil || !facts.enabled || facts.profileHash != identity.grant.ProfileSHA256 || recordHash(facts.profile) != facts.profileHash ||
		facts.account != identity.grant.DatabaseAccount || facts.server != identity.grant.ServerUUID || facts.database != identity.grant.Database ||
		v.now.Before(now) || v.now.Before(identity.grant.NotBefore) || !v.now.Before(identity.grant.ExpiresAt) || !v.now.Before(a.DeadlineAt) || identity.allowSQLAction(a, v.status, "") != nil {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	return v, nil
}

func (r *HeldExecutionRead) abort() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin == r {
		s.active = false
	}
}

func (g *pinnedExecutionGuard) SupportsHeldExecutionRecheck() bool {
	return g != nil && g.effective
}

func (g *pinnedExecutionGuard) PrepareHeldExecutionRecheck(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time, read *HeldExecutionRead) error {
	if g == nil || !g.effective || a != g.authority || !now.Before(g.until) || g.identity.current(a, now) != nil {
		return ErrExecutionAuthority
	}
	return read.registerOwner(ctx, tx, a, g.identity, now)
}
