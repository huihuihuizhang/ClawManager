package systembackupevidence

import (
	"context"
	"database/sql"
	"time"
)

// GC must authorize its database mutations as well as its provider requests.
// SQLRegistry alone does not bind mutations to a system operation lease.
type gcRegistry struct{ authority *SQLGCAuthority }

func (gcRegistry) PersistPending(context.Context, Record) error { return ErrDenied }

func (g gcRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	a := g.authority
	if a == nil || fn == nil || !idPattern.MatchString(id) {
		return ErrInvalid
	}
	if a.journal != nil && a.journal.check() != nil {
		return ErrUnavailable
	}
	until, err := pinnedPeerExpiry(ctx, a, a.roots, a.c.CertificateSHA256, a.c.ExpiresAt)
	if err != nil {
		return ErrDenied
	}
	c, s := a.c, a.c.Registry
	tx, _, err := s.begin(ctx)
	if err != nil {
		return boundary(err)
	}
	defer tx.Rollback()
	retry, err := a.lockConfig(ctx, tx)
	if err != nil {
		return ErrDenied
	}
	i := Identity{Installation: s.Installation, ID: id}
	if tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&i.OwnerType, &i.OwnerID) != nil || s.Policy.LockScope(ctx, tx, s.Installation, i) != nil {
		return ErrDenied
	}
	op, err := a.lockOperation(ctx, tx)
	if err != nil {
		return ErrDenied
	}
	r, err := s.load(ctx, tx, id)
	if err != nil {
		return boundary(err)
	}
	if r.Manifest.Identity.OwnerType != i.OwnerType || r.Manifest.Identity.OwnerID != i.OwnerID {
		return ErrIntegrity
	}
	// Tombstones have no provider reference. Idempotent acknowledgement still
	// requires the live installation, owner scope and exact GC operation lease.
	if r.State != "deleted" {
		key, err := keyFor(c.Root, r.Manifest.Identity)
		if err != nil || key != r.Ref.RelativeKey || r.Ref.Identity != c.Store.Identity || r.Ref.Version != c.Store.Version {
			return ErrDenied
		}
	}
	until = earlier(earlier(until, op.until), op.deadline)
	access, result := evidenceAccessFrom(ctx, "gc", id)
	if result {
		if r.Claim != access.Claim || r.RowVersion != access.RowVersion {
			return ErrConflict
		}
		until = earlier(until, r.ClaimUntil)
	}
	var now time.Time
	live := func() bool {
		return (a.journal == nil || a.journal.check() == nil) && tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) == nil && now.Before(until) && time.Since(now) <= 5*time.Second && time.Until(now) <= 5*time.Second && ctx.Err() == nil
	}
	if !live() {
		return ErrDenied
	}
	if !result && r.State != "deleted" {
		// Scanner candidates are only hints; enforce persisted backoff under
		// the evidence lock before any new claim/audit or provider request.
		var due sql.NullTime
		if tx.QueryRowContext(ctx, "SELECT next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&due) != nil {
			return ErrUnavailable
		}
		if due.Valid && now.Before(due.Time) {
			return ErrConflict
		}
	}
	locked := &sqlLocked{registry: s, tx: tx, record: r, now: now}
	if err := fn(gcLocked{sqlLocked: locked, actor: "gc:" + a.principal, retry: retry}); err != nil {
		return boundary(err)
	}
	if locked.record.Claim != "" {
		until = earlier(until, locked.record.ClaimUntil)
	}
	// Audit/policy/CAS may have waited. Expiry aborts the entire transaction,
	// including chunk deletion and result audit, before discarding any ref.
	if !live() {
		return ErrDenied
	}
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	if ctx.Err() != nil || !time.Now().Before(until) {
		return ErrUnavailable
	}
	return nil
}

type gcLocked struct {
	*sqlLocked
	actor string
	retry time.Duration
}

func (t gcLocked) Save(ctx context.Context, next Record) error {
	if next.State == "deleting" && next.Claim != "" && next.Claim != t.record.Claim {
		// A claim does not constitute a provider observation.
		return t.sqlLocked.Save(ctx, next)
	}
	return t.sqlLocked.saveGCResult(ctx, next, t.retry)
}

func (t gcLocked) Audit(ctx context.Context, event Audit) error {
	if !oneOf(event.Action, "evidence.gc.intent", "evidence.gc.result") || event.EvidenceID != t.record.Manifest.Identity.ID {
		return ErrDenied
	}
	event.ActorID = t.actor
	return t.sqlLocked.Audit(ctx, event)
}
