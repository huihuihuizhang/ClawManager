package systembackupkekadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sync"

	ev "clawreef/internal/systembackupevidence"
)

// OriginalC1HistoryRead authenticates historical provenance, NOT current
// health or complete KEK coverage. The original 17-source owner separately
// authenticates the entire adopted index. Unlike the pre-install pure-C1
// closure, this read permits later legitimate non-C1 inline control evidence.
type OriginalC1HistoryRead struct {
	mu       sync.Mutex
	failed   bool
	origin   *OriginalC1HistoryRead
	ctx      context.Context
	tx       *sql.Tx
	sources  []*ev.OriginalC1EvidenceSource
	snapshot OriginalC1SQLSnapshot
}

func (*OriginalC1HistoryRead) MarshalJSON() ([]byte, error) { return nil, ErrAuthorityWrite }

func AuthenticateOriginalC1History(ctx context.Context, tx *sql.Tx, sources []*ev.OriginalC1EvidenceSource) (*OriginalC1HistoryRead, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || len(sources) == 0 || len(sources) > 20 {
		return nil, ErrAuthorityWrite
	}
	r := &OriginalC1HistoryRead{ctx: ctx, tx: tx, sources: append([]*ev.OriginalC1EvidenceSource(nil), sources...)}
	r.origin = r
	seen := map[*ev.OriginalC1EvidenceSource]bool{}
	for _, source := range r.sources {
		if source == nil || seen[source] {
			return nil, ErrAuthorityWrite
		}
		seen[source] = true
		f, e := source.OriginalGuardData(ctx)
		if e != nil {
			return nil, ErrAuthorityWrite
		}
		if len(r.snapshot.Sources) == 0 {
			r.snapshot.InstallationID = string(f.History.Scope.Installation)
			r.snapshot.Database.ServerUUID = string(f.History.Scope.ServerUUID)
			r.snapshot.Database.Database = string(f.History.Scope.Database)
		}
		if string(f.History.Scope.Installation) != r.snapshot.InstallationID || string(f.History.Scope.ServerUUID) != r.snapshot.Database.ServerUUID || string(f.History.Scope.Database) != r.snapshot.Database.Database {
			return nil, ErrAuthorityWrite
		}
		r.snapshot.Sources = append(r.snapshot.Sources, f)
	}
	tables, now, e := scanOriginalC1ProtocolClosure(ctx, tx, r.snapshot)
	if e != nil {
		return nil, e
	}
	r.snapshot.Tables = tables
	r.snapshot.ObservedAt = now
	if r.Recheck(ctx, tx) != nil {
		return nil, ErrAuthorityWrite
	}
	return r, nil
}

func (r *OriginalC1HistoryRead) Recheck(ctx context.Context, tx *sql.Tx) error {
	if r == nil {
		return ErrAuthorityWrite
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || r.origin != r || ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != r.ctx || ctx.Err() != nil || tx == nil || tx != r.tx {
		r.failed = true
		return ErrAuthorityWrite
	}
	tables, now, e := scanOriginalC1ProtocolClosure(ctx, tx, r.snapshot)
	if e != nil || now.Before(r.snapshot.ObservedAt) || !reflect.DeepEqual(tables, r.snapshot.Tables) {
		r.failed = true
		return ErrAuthorityWrite
	}
	for n, source := range r.sources {
		f, e := source.ReadCommitted(ctx, tx)
		if e != nil || !reflect.DeepEqual(f, r.snapshot.Sources[n]) {
			r.failed = true
			return ErrAuthorityWrite
		}
	}
	return nil
}

func (r *OriginalC1HistoryRead) Snapshot() (OriginalC1SQLSnapshot, error) {
	var out OriginalC1SQLSnapshot
	if r == nil {
		return out, ErrAuthorityWrite
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || r.origin != r {
		return out, ErrAuthorityWrite
	}
	raw, e := json.Marshal(r.snapshot)
	if e != nil || json.Unmarshal(raw, &out) != nil {
		return OriginalC1SQLSnapshot{}, ErrAuthorityWrite
	}
	return out, nil
}
