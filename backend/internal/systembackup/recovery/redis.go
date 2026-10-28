package recovery

import (
	"context"
	"encoding/json"
	"io"
)

type RedisSealer interface {
	// Must stream directly to encrypted task staging, aborting the artifact on
	// produce error. The public result contains no key names or raw DUMP bytes.
	SealRedis(context.Context, CaptureRequest, func(io.Writer) error) (PartResult, error)
}

func CaptureRedis(ctx context.Context, request CaptureRequest, p RedisPolicy, source RedisReader, sink RedisSealer, dbClock func(context.Context) (int64, error)) (PartResult, error) {
	if request.Validate() != nil || p.Validate() != nil || p.CaptureMode != "scan_dump" || source == nil || sink == nil || dbClock == nil {
		return PartResult{}, ErrUnavailable
	}
	result, e := sink.SealRedis(ctx, request, func(out io.Writer) error {
		enc := json.NewEncoder(out)
		if enc.Encode(struct{ Version, TTLPolicy string }{"redis-scan-dump.v1", p.TTLPolicy}) != nil {
			return ErrUnavailable
		}
		seen := map[string]string{}
		cursors := map[string]bool{}
		cursor := ""
		var total int64
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			now, e := dbClock(ctx)
			if e != nil || now >= request.Deadline {
				return ErrUnavailable
			}
			items, next, e := source.ScanDump(ctx, p, cursor)
			if e != nil {
				return ErrUnavailable
			}
			if len(items) > 1000 {
				return ErrContract
			}
			for _, v := range items {
				if e = p.ValidateItem(v, now); e != nil {
					return e
				}
				raw, e := Marshal(struct {
					Key     []byte
					Type    string
					Dump    []byte
					Expires int64
					Groups  []byte
				}{v.Key, v.Type, v.Dump, v.ExpiresAt, v.StreamGroups})
				if e != nil {
					return e
				}
				key := string(v.Key)
				hash := Hash(raw)
				if previous, ok := seen[key]; ok {
					if previous != hash {
						return ErrConflict
					}
					continue
				}
				seen[key] = hash
				encoded, e := json.Marshal(v)
				if e != nil {
					return ErrContract
				}
				total += int64(len(encoded)) + 1
				if int64(len(seen)) > p.MaxItems || total > p.MaxBytes {
					return ErrContract
				}
				if e = enc.Encode(v); e != nil {
					return ErrUnavailable
				}
			}
			if next == "" {
				break
			}
			if cursors[next] || next == cursor {
				return ErrContract
			}
			cursors[next] = true
			cursor = next
		}
		return nil
	})
	if e != nil {
		return PartResult{}, e
	}
	if result.Schema != Version || result.Part != "redis" || result.Status != "completed" || len(result.Objects) == 0 || !result.Checkpoint.valid() {
		return PartResult{}, ErrContract
	}
	for _, o := range result.Objects {
		if !o.valid() {
			return PartResult{}, ErrContract
		}
	}
	result.Consistency = "bounded"
	result.Warnings = append(result.Warnings, Warning{"redis_scan_dump_bounded", "consistency"})
	return result, nil
}
func RestoreRedisItem(ctx context.Context, p RedisPolicy, item RedisItem, target RestoreTarget, dest RedisRestore, dbClock func(context.Context) (int64, error)) (bool, error) {
	if dest == nil || dbClock == nil || !target.Isolation.valid() || !validID(target.ID) || dest.CheckIsolated(ctx, target, p.Source) != nil {
		return false, ErrUnavailable
	}
	time, e := dest.ServerTime(ctx)
	if e != nil {
		return false, ErrUnavailable
	}
	now, e := dbClock(ctx)
	if e != nil {
		return false, ErrUnavailable
	}
	ttl, skip, e := p.RemainingTTL(item, time, now)
	if e != nil || skip {
		return skip, e
	}
	if e = dest.CheckIsolated(ctx, target, p.Source); e != nil {
		return false, ErrUnavailable
	}
	return false, dest.Restore(ctx, item, ttl)
}
