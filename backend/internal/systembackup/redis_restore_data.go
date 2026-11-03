package systembackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"clawreef/internal/systembackup/recovery"
)

var ErrRedisData = errors.New("redis restore data transport rejected")
var ErrRedisDataOutcomeUnknown = errors.New("redis restore data send outcome requires original journal reconciliation")

// These are transport primitives, not target isolation/restore authority.
// D's concrete IsolatedSession must check the current drill, identity, DB,
// runID/prefix, credentials and durable send journal around every operation.
func (c *RedisClient) RedisServerTimeMillis(ctx context.Context) (int64, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return 0, ErrRedisData
	}
	value, err := c.command(ctx, []byte("TIME"))
	if err != nil {
		return 0, ErrRedisData
	}
	parts, ok := value.([]any)
	if !ok || len(parts) != 2 {
		return 0, ErrRedisData
	}
	return redisRestoreClock(parts[0], parts[1])
}

func redisRestoreClock(seconds, micros any) (int64, error) {
	s, ok := seconds.([]byte)
	if !ok {
		return 0, ErrRedisData
	}
	us, ok := micros.([]byte)
	if !ok {
		return 0, ErrRedisData
	}
	sec, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil || sec <= 0 || sec > 9007199254740 {
		return 0, ErrRedisData
	}
	micro, err := strconv.ParseInt(string(us), 10, 64)
	if err != nil || micro < 0 || micro >= 1000000 {
		return 0, ErrRedisData
	}
	clock := sec*1000 + micro/1000
	if clock > 9007199254740991 {
		return 0, ErrRedisData
	}
	return clock, nil
}

// RestoreCapturedRedisItem sends exactly once, without REPLACE or retry.
// RemainingTTL must already have been computed using the current target TIME
// and controller clock by recovery.RestoreRedisItem. Expired/zero TTL refuses.
// ABSTTL pins the ORIGINAL expiry even if the network write is delayed.
func (c *RedisClient) RestoreCapturedRedisItem(ctx context.Context, item recovery.RedisItem, remainingMillis int64) error {
	if c == nil || ctx == nil || ctx.Err() != nil || len(item.Key) == 0 || len(item.Key) > 4096 || len(item.Dump) == 0 || len(item.Dump) > 32<<20 || item.CapturedAt <= 0 {
		return ErrRedisData
	}
	switch item.Type {
	case "string", "list", "set", "zset", "hash", "stream":
	default:
		return ErrRedisData
	}
	digest := sha256.Sum256(item.Dump)
	if hex.EncodeToString(digest[:]) != item.SHA256 {
		return ErrRedisData
	}
	args := [][]byte{[]byte("RESTORE"), item.Key, nil, item.Dump}
	if item.PTTL == -1 && item.ExpiresAt == 0 && remainingMillis == -1 {
		// Redis's explicit zero only represents a SOURCE persistent key here;
		// it is never a fallback for an expired or unknown finite TTL.
		args[2] = []byte("0")
	} else {
		if item.PTTL < 0 || item.PTTL > 9007199254740991-item.CapturedAt || item.ExpiresAt != item.CapturedAt+item.PTTL || remainingMillis <= 0 || remainingMillis > item.PTTL {
			return ErrRedisData
		}
		args[2] = []byte(strconv.FormatInt(item.ExpiresAt, 10))
		args = append(args, []byte("ABSTTL"))
	}
	value, err := c.command(ctx, args...)
	if err != nil {
		return errors.Join(ErrRedisDataOutcomeUnknown, err)
	}
	ack, ok := value.([]byte)
	if !ok || string(ack) != "OK" {
		return ErrRedisDataOutcomeUnknown
	}
	return nil
}

type RedisItemObservation struct {
	Exists                 bool
	Type                   string
	Dump                   []byte
	PTTL, ObservedAtMillis int64
}

func (o *RedisItemObservation) Clear() {
	if o != nil {
		clear(o.Dump)
		*o = RedisItemObservation{}
	}
}

const observeRestoredRedisScript = `local t=redis.call('TIME'); local kind=redis.call('TYPE',KEYS[1]).ok; local dump=redis.call('DUMP',KEYS[1]); local ttl=redis.call('PTTL',KEYS[1]); return {kind,dump or false,ttl,t[1],t[2]}`

// ObserveRestoredRedisItem reads TYPE/DUMP/PTTL/TIME atomically in EVAL_RO.
// The caller supplies an independently authorized read-only target connection;
// opening that independent capability and proving isolation remain D's work.
func (c *RedisClient) ObserveRestoredRedisItem(ctx context.Context, key []byte) (RedisItemObservation, error) {
	var zero RedisItemObservation
	if c == nil || ctx == nil || ctx.Err() != nil || len(key) == 0 || len(key) > 4096 {
		return zero, ErrRedisData
	}
	value, err := c.command(ctx, []byte("EVAL_RO"), []byte(observeRestoredRedisScript), []byte("1"), key)
	if err != nil {
		return zero, ErrRedisData
	}
	row, ok := value.([]any)
	if !ok || len(row) != 5 {
		return zero, ErrRedisData
	}
	kind, ok := row[0].([]byte)
	if !ok {
		return zero, ErrRedisData
	}
	ttl, ok := row[2].(int64)
	if !ok {
		return zero, ErrRedisData
	}
	clock, err := redisRestoreClock(row[3], row[4])
	if err != nil {
		return zero, err
	}
	if string(kind) == "none" {
		if row[1] != nil || ttl != -2 {
			return zero, ErrRedisData
		}
		return RedisItemObservation{ObservedAtMillis: clock, PTTL: -2, Type: "none"}, nil
	}
	dump, ok := row[1].([]byte)
	if !ok || len(dump) == 0 || len(dump) > 32<<20 || ttl < -1 {
		return zero, ErrRedisData
	}
	switch string(kind) {
	case "string", "list", "set", "zset", "hash", "stream":
	default:
		clear(dump)
		return zero, ErrRedisData
	}
	return RedisItemObservation{Exists: true, Type: string(kind), Dump: dump, PTTL: ttl, ObservedAtMillis: clock}, nil
}
