package recovery

import "context"

type RedisCollector struct {
	Policy       RedisPolicy
	Source       RedisReader
	Snapshot     RedisSnapshotProvider
	Sink         RedisSealer
	DatabaseTime func(context.Context) (int64, error)
}

func (c RedisCollector) Capture(ctx context.Context, r CaptureRequest) (PartResult, error) {
	if c.Policy.Validate() != nil || r.Validate() != nil {
		return PartResult{}, ErrContract
	}
	if c.Policy.CaptureMode == "scan_dump" {
		return CaptureRedis(ctx, r, c.Policy, c.Source, c.Sink, c.DatabaseTime)
	}
	if c.Policy.Topology != "dedicated_instance" || c.Snapshot == nil {
		return PartResult{}, ErrUnavailable
	}
	p, e := c.Snapshot.CaptureSnapshot(ctx, r, c.Policy)
	if e != nil {
		return PartResult{}, e
	}
	if p.Part != "redis" || p.Schema != Version || p.Status != "completed" || p.Checkpoint.Validate() != nil || len(p.Objects) == 0 || p.Consistency != "strong" {
		return PartResult{}, ErrContract
	}
	for _, o := range p.Objects {
		if !o.valid() {
			return PartResult{}, ErrContract
		}
	}
	return p, nil
}

// ReadVerified authenticates the entire encrypted archive and final record
// before returning items. Private item bytes must not be logged or persisted.
type VerifiedRedisArchive interface {
	ReadVerified(context.Context, Reference) ([]RedisItem, error)
}
type RedisRestoreJournal interface {
	Begin(context.Context, RestoreTarget, Reference, RedisPolicy, []string) error
	// Freeze binds exact item hash and target identity. Unknown writes require
	// independent comparison/reconciliation, never an automatic resend.
	Freeze(context.Context, RestoreTarget, Reference, int, string) (string, error)
	Sent(context.Context, RestoreTarget, Reference, int, string) error
	Done(context.Context, RestoreTarget, Reference, int, string, bool) error
}
type RedisRestorer struct {
	Policy       RedisPolicy
	Source       VerifiedRedisArchive
	Target       RedisRestore
	Journal      RedisRestoreJournal
	DatabaseTime func(context.Context) (int64, error)
}

func (r RedisRestorer) Restore(ctx context.Context, archive Reference, target RestoreTarget) error {
	if r.Policy.Validate() != nil || r.Source == nil || r.Target == nil || r.Journal == nil || r.DatabaseTime == nil || archive.Validate() != nil || target.Isolation.Validate() != nil {
		return ErrUnavailable
	}
	items, e := r.Source.ReadVerified(ctx, archive)
	defer func() {
		for _, v := range items {
			clear(v.Key)
			clear(v.Dump)
			clear(v.StreamGroups)
		}
	}()
	if e != nil {
		return e
	}
	if int64(len(items)) > r.Policy.MaxItems {
		return ErrContract
	}
	seen := map[string]bool{}
	hashes := []string{}
	var bytes int64
	for _, v := range items {
		if r.Policy.ValidateItem(v, v.CapturedAt) != nil || seen[string(v.Key)] {
			return ErrContract
		}
		seen[string(v.Key)] = true
		b, e := Marshal(v)
		if e != nil {
			return ErrContract
		}
		bytes += int64(len(b))
		hashes = append(hashes, Hash(b))
		clear(b)
		if bytes > r.Policy.MaxBytes {
			return ErrContract
		}
	}
	if e = r.Journal.Begin(ctx, target, archive, r.Policy, hashes); e != nil {
		return e
	}
	if e = r.Target.CheckIsolated(ctx, target, r.Policy.Source); e != nil {
		return ErrUnavailable
	}
	for index, v := range items {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b, _ := Marshal(v)
		hash := Hash(b)
		clear(b)
		state, e := r.Journal.Freeze(ctx, target, archive, index, hash)
		if e != nil {
			return e
		}
		if state == "completed" {
			continue
		}
		if state != "prepared" {
			return ErrUnavailable
		}
		if e = r.Journal.Sent(ctx, target, archive, index, hash); e != nil {
			return e
		}
		skipped, e := RestoreRedisItem(ctx, r.Policy, v, target, r.Target, r.DatabaseTime)
		if e != nil {
			return e
		}
		if e = r.Journal.Done(ctx, target, archive, index, hash, skipped); e != nil {
			return e
		}
	}
	return nil
}
