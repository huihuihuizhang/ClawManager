package systembackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/recovery"
)

const RedisSourceSnapshotVersion = "original-scoped-redis-snapshot.v1"

// A real finite source scope, independent of Team existence. Source is the
// original deployment source reference; no Team ID is synthesized to capture
// an empty keyspace. Exclusions are frozen alongside the positive allowlist.
type RedisCapturePolicy struct {
	Policy          recovery.RedisPolicy
	ServerID        string
	ExcludePrefixes []string
}

func (p RedisCapturePolicy) Validate() error {
	if p.Policy.Validate() != nil || p.Policy.CaptureMode != "scan_dump" || p.Policy.TTLPolicy != "preserve_absolute" || len(p.ServerID) != 40 || p.Policy.MaxItems > 10000 || p.Policy.MaxBytes > 32<<20 || p.Policy.MaxClockSkew > 30000 || len(p.Policy.Prefixes) > 32 || len(p.ExcludePrefixes) > 32 {
		return errors.New("redis_source_scope_invalid")
	}
	for _, c := range p.ServerID {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return errors.New("redis_source_scope_invalid")
		}
	}
	seen := map[string]bool{}
	for _, prefix := range p.ExcludePrefixes {
		if prefix == "" || len(prefix) > 512 || seen[prefix] || strings.ContainsAny(prefix, "*?[]\\\x00\r\n") {
			return errors.New("redis_source_scope_invalid")
		}
		seen[prefix] = true
	}
	for _, prefix := range p.Policy.Prefixes {
		if len(prefix) > 512 {
			return errors.New("redis_source_scope_invalid")
		}
	}
	return nil
}

func (p RedisCapturePolicy) allows(key string) bool {
	for _, prefix := range p.ExcludePrefixes {
		if strings.HasPrefix(key, prefix) {
			return false
		}
	}
	// Legacy restore histories are temporary control output, never source data.
	if strings.HasPrefix(key, "cm:restore-history:") {
		return false
	}
	for _, prefix := range p.Policy.Prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// CaptureSourceRedis reuses the original Redis client and recovery item/TTL
// contract. SCAN enumerates a finite keyset under the original writer barrier;
// ONE EVAL_RO then captures all surviving DUMPs/type/PTTL/groups with one TIME.
// Expirations during SCAN are absent at that observation. This function grants
// no permission or consistency level; the caller must prove the source gate.
func CaptureSourceRedis(ctx context.Context, client *RedisClient, dst io.Writer, policy RedisCapturePolicy, check TeamSourceCheck) error {
	closed := func() error { return errors.New("redis_source_capture_unavailable") }
	if ctx == nil || client == nil || dst == nil || check == nil || policy.Validate() != nil || client.database != policy.Policy.DB {
		return closed()
	}
	guard := func() error {
		if ctx.Err() != nil || check(ctx) != nil {
			return closed()
		}
		return nil
	}
	if guard() != nil {
		return closed()
	}
	server, err := redisServerID(ctx, client)
	if err != nil || server != policy.ServerID {
		return closed()
	}
	seen := map[string]bool{}
	var keys []string
	var inventoryBytes int64
	for _, prefix := range policy.Policy.Prefixes {
		cursor := "0"
		cursors := map[string]bool{}
		for {
			if guard() != nil {
				return closed()
			}
			reply, err := client.command(ctx, []byte("SCAN"), []byte(cursor), []byte("MATCH"), []byte(prefix+"*"), []byte("COUNT"), []byte("500"))
			if err != nil || guard() != nil {
				return closed()
			}
			parts, ok := reply.([]any)
			if !ok || len(parts) != 2 {
				return closed()
			}
			next, ok := parts[0].([]byte)
			if !ok || len(next) > 20 {
				return closed()
			}
			cursor = string(next)
			if _, err := strconv.ParseUint(cursor, 10, 64); err != nil {
				return closed()
			}
			items, ok := parts[1].([]any)
			if !ok || len(items) > 10000 {
				return closed()
			}
			for _, item := range items {
				raw, ok := item.([]byte)
				if !ok || len(raw) < 1 || len(raw) > 4096 || !strings.HasPrefix(string(raw), prefix) {
					return closed()
				}
				key := string(raw)
				if !policy.allows(key) || seen[key] {
					continue
				}
				inventoryBytes += int64(len(key))*2 + 128
				if int64(len(keys)) >= policy.Policy.MaxItems || inventoryBytes > policy.Policy.MaxBytes {
					return closed()
				}
				seen[key] = true
				keys = append(keys, key)
			}
			if cursor == "0" {
				break
			}
			if cursors[cursor] || len(cursors) >= 10000 {
				return closed()
			}
			cursors[cursor] = true
		}
	}
	sort.Strings(keys)
	script := []byte(`local clock=redis.call('TIME'); local out={clock[1],clock[2]}; local total=0; for _,k in ipairs(KEYS) do local v=redis.call('DUMP',k); if v then total=total+#v+#k; if total>tonumber(ARGV[1]) then return redis.error_reply('source capacity exceeded') end; local kind=redis.call('TYPE',k).ok; local groups={}; if kind=='stream' then groups=redis.call('XINFO','GROUPS',k) end; out[#out+1]={k,v,kind,redis.call('PTTL',k),groups} end end; return out`)
	args := [][]byte{[]byte("EVAL_RO"), script, []byte(strconv.Itoa(len(keys)))}
	for _, key := range keys {
		args = append(args, []byte(key))
	}
	args = append(args, []byte(strconv.FormatInt(policy.Policy.MaxBytes, 10)))
	if guard() != nil {
		return closed()
	}
	reply, err := client.command(ctx, args...)
	defer clearRedisSourceReply(reply)
	if err != nil || guard() != nil {
		return closed()
	}
	values, ok := reply.([]any)
	if !ok || len(values) < 2 || int64(len(values)-2) > policy.Policy.MaxItems {
		return closed()
	}
	seconds, sok := values[0].([]byte)
	micros, uok := values[1].([]byte)
	if !sok || !uok {
		return closed()
	}
	s, se := strconv.ParseInt(string(seconds), 10, 64)
	us, ue := strconv.ParseInt(string(micros), 10, 64)
	if se != nil || ue != nil || s <= 0 || s > 9007199254740 || us < 0 || us >= 1000000 {
		return closed()
	}
	at := s*1000 + us/1000
	controllerTime := time.Now().UnixMilli()
	if at-controllerTime > policy.Policy.MaxClockSkew || controllerTime-at > policy.Policy.MaxClockSkew {
		return closed()
	}
	var total, count int64
	sum := sha256.New()
	previous := ""
	header, err := json.Marshal(RedisSourceSnapshotHeader{RedisSourceSnapshotVersion, policy.Policy.Source, server, client.database, policy.Policy.Prefixes, policy.ExcludePrefixes, at})
	if err != nil {
		return closed()
	}
	write := func(raw []byte) error {
		total += int64(len(raw)) + 1
		if total > policy.Policy.MaxBytes || guard() != nil {
			return closed()
		}
		encoded := append(raw, '\n')
		if n, err := dst.Write(encoded); err != nil || n != len(encoded) {
			return closed()
		}
		return nil
	}
	if write(header) != nil {
		return closed()
	}
	for _, value := range values[2:] {
		if guard() != nil {
			return closed()
		}
		row, ok := value.([]any)
		if !ok || len(row) != 5 {
			return closed()
		}
		key, kok := row[0].([]byte)
		dump, dok := row[1].([]byte)
		kind, tok := row[2].([]byte)
		ttl, xok := row[3].(int64)
		if !kok || !dok || !tok || !xok || !seen[string(key)] || !policy.allows(string(key)) || string(key) <= previous || ttl < -1 {
			return closed()
		}
		previous = string(key)
		item := recovery.RedisItem{Key: key, Dump: dump, Type: string(kind), SHA256: recovery.Hash(dump), CapturedAt: at, PTTL: ttl}
		if ttl >= 0 {
			if ttl > 9007199254740991-at {
				return closed()
			}
			item.ExpiresAt = at + ttl
		}
		groups, ok := row[4].([]any)
		if !ok {
			return closed()
		}
		if item.Type == "stream" {
			item.StreamGroups, err = json.Marshal(groups)
			if err != nil || !validRedisSourceGroups(item.StreamGroups) {
				return closed()
			}
		} else if len(groups) != 0 {
			return closed()
		}
		if policy.Policy.ValidateItem(item, at) != nil {
			return closed()
		}
		raw, err := json.Marshal(item)
		if err != nil || write(raw) != nil {
			return closed()
		}
		sum.Write(raw)
		sum.Write([]byte{'\n'})
		count++
	}
	end, err := json.Marshal(struct {
		Kind   string
		Count  int64
		SHA256 string
	}{"end", count, hex.EncodeToString(sum.Sum(nil))})
	if err != nil || write(end) != nil {
		return closed()
	}
	actual, database, err := client.Identity(ctx)
	if err != nil || actual != server || database != policy.Policy.DB || guard() != nil {
		return closed()
	}
	return nil
}

func clearRedisSourceReply(value any) {
	switch v := value.(type) {
	case []byte:
		clear(v)
	case []any:
		for _, item := range v {
			clearRedisSourceReply(item)
		}
	}
}
