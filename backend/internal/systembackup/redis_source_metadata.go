package systembackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Metadata only: no DUMP/value/TTL capture, writer barrier claim or stopped
// witness. Complete scoped SCAN plus one EVAL_RO reads surviving key types and
// full stream-group metadata. The actual capture still needs its real barrier.
type RedisSourceMetadataEntry struct {
	Key    []byte
	Type   string
	Groups json.RawMessage
}

func ObserveSourceRedisMetadata(ctx context.Context, client *RedisClient, policy RedisCapturePolicy, account string, check TeamSourceCheck) ([]RedisSourceMetadataEntry, error) {
	denied := func() error { return errors.New("redis_source_metadata_unavailable") }
	if ctx == nil || client == nil || check == nil || policy.Validate() != nil || account == "" || client.database != policy.Policy.DB {
		return nil, denied()
	}
	guard := func() error {
		if ctx.Err() != nil || check(ctx) != nil {
			return denied()
		}
		return nil
	}
	if guard() != nil {
		return nil, denied()
	}
	who, err := client.command(ctx, []byte("ACL"), []byte("WHOAMI"))
	name, ok := who.([]byte)
	if err != nil || !ok || string(name) != account || guard() != nil {
		return nil, denied()
	}
	server, err := redisServerID(ctx, client)
	if err != nil || server != policy.ServerID || guard() != nil {
		return nil, denied()
	}
	keys, seen := []string{}, map[string]bool{}
	var keyBytes int64
	for _, prefix := range policy.Policy.Prefixes {
		cursor := "0"
		cursors := map[string]bool{}
		for {
			if guard() != nil {
				return nil, denied()
			}
			reply, err := client.command(ctx, []byte("SCAN"), []byte(cursor), []byte("MATCH"), []byte(prefix+"*"), []byte("COUNT"), []byte("500"))
			if err != nil || guard() != nil {
				return nil, denied()
			}
			parts, ok := reply.([]any)
			if !ok || len(parts) != 2 {
				return nil, denied()
			}
			next, ok := parts[0].([]byte)
			if !ok || len(next) > 20 {
				return nil, denied()
			}
			cursor = string(next)
			if _, err := strconv.ParseUint(cursor, 10, 64); err != nil {
				return nil, denied()
			}
			items, ok := parts[1].([]any)
			if !ok || len(items) > 10000 {
				return nil, denied()
			}
			for _, item := range items {
				raw, ok := item.([]byte)
				if !ok || len(raw) == 0 || len(raw) > 4096 || !strings.HasPrefix(string(raw), prefix) {
					return nil, denied()
				}
				key := string(raw)
				if !policy.allows(key) || seen[key] {
					continue
				}
				keyBytes += int64(len(key))
				if int64(len(keys)) >= policy.Policy.MaxItems || keyBytes > policy.Policy.MaxBytes {
					return nil, denied()
				}
				seen[key] = true
				keys = append(keys, key)
			}
			if cursor == "0" {
				break
			}
			if cursors[cursor] || len(cursors) >= 10000 {
				return nil, denied()
			}
			cursors[cursor] = true
		}
	}
	sort.Strings(keys)
	script := []byte(`local out={}; for _,k in ipairs(KEYS) do local t=redis.call('TYPE',k).ok; if t~='none' then local g={}; if t=='stream' then g=redis.call('XINFO','GROUPS',k) end; out[#out+1]={k,t,g}; end; end; return out`)
	args := [][]byte{[]byte("EVAL_RO"), script, []byte(strconv.Itoa(len(keys)))}
	for _, key := range keys {
		args = append(args, []byte(key))
	}
	if guard() != nil {
		return nil, denied()
	}
	reply, err := client.command(ctx, args...)
	defer clearRedisSourceReply(reply)
	if err != nil || guard() != nil {
		return nil, denied()
	}
	values, ok := reply.([]any)
	if !ok || len(values) > len(keys) {
		return nil, denied()
	}
	out := []RedisSourceMetadataEntry{}
	returned := map[string]bool{}
	var total int64
	for _, value := range values {
		row, ok := value.([]any)
		if !ok || len(row) != 3 {
			return nil, denied()
		}
		key, kok := row[0].([]byte)
		kind, tok := row[1].([]byte)
		if !kok || !tok || !seen[string(key)] || returned[string(key)] {
			return nil, denied()
		}
		switch string(kind) {
		case "string", "hash", "list", "set", "zset", "stream":
		default:
			return nil, denied()
		}
		groups, err := json.Marshal(row[2])
		if err != nil || string(kind) == "stream" && !validRedisSourceGroups(groups) || string(kind) != "stream" && !bytes.Equal(groups, []byte("[]")) {
			return nil, denied()
		}
		total += int64(len(key) + len(kind) + len(groups))
		if total > policy.Policy.MaxBytes {
			return nil, denied()
		}
		returned[string(key)] = true
		out = append(out, RedisSourceMetadataEntry{Key: bytes.Clone(key), Type: string(kind), Groups: bytes.Clone(groups)})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Key, out[j].Key) < 0 })
	if guard() != nil {
		return nil, denied()
	}
	return out, nil
}
