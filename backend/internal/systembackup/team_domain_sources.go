package systembackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/team"
	"github.com/minio/minio-go/v7"
)

// check is the original public task's LIVE capture barrier/credential grant.
// Source identities and object references come from the authenticated inventory.
// None of these collectors acquire a gate, create a task or assert acceptance.
type TeamSourceCheck func(context.Context) error

func CaptureTeamRedisScope(ctx context.Context, c *RedisClient, w io.Writer, b RedisBudget, scope team.RedisScope, check TeamSourceCheck) error {
	if ctx == nil || c == nil || w == nil || check == nil || scope.Validate() != nil || b.validate() != nil || b.MaxItems > 10000 || b.MaxBytes > 32<<20 || c.database != scope.Database {
		return errors.New("teams_source_unavailable")
	}
	if check(ctx) != nil {
		return errors.New("permission_denied")
	}
	id, err := redisServerID(ctx, c)
	if err != nil || id != scope.ServerID {
		return errors.New("source_identity_mismatch")
	}
	seen := map[string]bool{}
	var keys []string
	var inventoryBytes int64
	for _, tid := range scope.TeamIDs {
		prefix := "claw:team:" + strconv.Itoa(tid) + ":"
		cursor := "0"
		for {
			if check(ctx) != nil || ctx.Err() != nil {
				return errors.New("permission_denied")
			}
			reply, e := c.command(ctx, []byte("SCAN"), []byte(cursor), []byte("MATCH"), []byte(prefix+"*"), []byte("COUNT"), []byte("500"))
			if e != nil {
				return errors.New("teams_redis_unavailable")
			}
			parts, ok := reply.([]any)
			if !ok || len(parts) != 2 {
				return errors.New("invalid_redis_inventory")
			}
			next, ok := parts[0].([]byte)
			if !ok {
				return errors.New("invalid_redis_inventory")
			}
			cursor = string(next)
			if _, e = strconv.ParseUint(cursor, 10, 64); e != nil {
				return errors.New("invalid_redis_inventory")
			}
			items, ok := parts[1].([]any)
			if !ok {
				return errors.New("invalid_redis_inventory")
			}
			for _, item := range items {
				raw, ok := item.([]byte)
				if !ok || !strings.HasPrefix(string(raw), prefix) {
					return errors.New("redis_scope_mismatch")
				}
				key := string(raw)
				if seen[key] {
					continue
				}
				inventoryBytes += int64(len(key))*2 + 128
				if len(keys) >= b.MaxItems || inventoryBytes > b.MaxInventoryBytes {
					return errors.New("capacity_exceeded")
				}
				seen[key] = true
				keys = append(keys, key)
			}
			if cursor == "0" {
				break
			}
		}
	}
	sort.Strings(keys)
	// One bounded read-only script fixes DUMP/type/PTTL to the same Redis TIME.
	// Keys expiring during SCAN are absent at THIS snapshot. No TTL is extended.
	script := []byte(`local clock=redis.call('TIME'); local out={clock[1],clock[2]}; local total=0; for _,k in ipairs(KEYS) do local v=redis.call('DUMP',k); if v then total=total+#v+#k; if total>tonumber(ARGV[1]) then return redis.error_reply('teams capacity exceeded') end; local kind=redis.call('TYPE',k); out[#out+1]={k,v,kind.ok,redis.call('PTTL',k)} end end; return out`)
	args := [][]byte{[]byte("EVAL_RO"), script, []byte(strconv.Itoa(len(keys)))}
	for _, key := range keys {
		args = append(args, []byte(key))
	}
	args = append(args, []byte(strconv.FormatInt(b.MaxBytes, 10)))
	if check(ctx) != nil {
		return errors.New("permission_denied")
	}
	reply, err := c.command(ctx, args...)
	if err != nil {
		return errors.New("teams_redis_snapshot_failed")
	}
	values, ok := reply.([]any)
	if !ok || len(values) < 2 {
		return errors.New("invalid_redis_snapshot")
	}
	sec, ok := values[0].([]byte)
	if !ok {
		return errors.New("invalid_redis_snapshot")
	}
	micros, ok := values[1].([]byte)
	if !ok {
		return errors.New("invalid_redis_snapshot")
	}
	s, err := strconv.ParseInt(string(sec), 10, 64)
	if err != nil {
		return errors.New("invalid_redis_snapshot")
	}
	us, err := strconv.ParseInt(string(micros), 10, 64)
	if err != nil || us < 0 || us >= 1000000 {
		return errors.New("invalid_redis_snapshot")
	}
	at := s*1000 + us/1000
	enc := json.NewEncoder(w)
	if err = enc.Encode(RedisRecord{Kind: "redis_dump_v1", ServerID: id, CapturedAtMillis: at}); err != nil {
		return err
	}
	sum := sha256.New()
	var total, count int64
	previous := ""
	for _, value := range values[2:] {
		row, ok := value.([]any)
		if !ok || len(row) != 4 {
			return errors.New("invalid_redis_snapshot")
		}
		key, kok := row[0].([]byte)
		dump, dok := row[1].([]byte)
		kind, tok := row[2].([]byte)
		ttl, xok := row[3].(int64)
		if !kok || !dok || !tok || !xok || ttl < -1 || !seen[string(key)] || string(key) <= previous {
			return errors.New("invalid_redis_snapshot")
		}
		previous = string(key)
		expires := int64(0)
		if ttl >= 0 {
			expires = at + ttl
		}
		raw, e := json.Marshal(RedisRecord{Kind: "key", Key: key, Dump: dump, Type: string(kind), ExpiresAtMillis: expires})
		if e != nil {
			return e
		}
		raw = append(raw, '\n')
		total += int64(len(raw))
		if total > b.MaxBytes {
			return errors.New("capacity_exceeded")
		}
		sum.Write(raw)
		if e = writeFull(w, raw); e != nil {
			return e
		}
		count++
	}
	if observed, e := redisServerID(ctx, c); e != nil || observed != id || check(ctx) != nil {
		return errors.New("source_identity_mismatch")
	}
	return enc.Encode(RedisRecord{Kind: "end", Count: count, SHA256: hex.EncodeToString(sum.Sum(nil))})
}

// CaptureTeamObjectRefs reads only explicit immutable versions, never LISTs an
// entire bucket or substitutes today's object for a missing original version.
func CaptureTeamObjectRefs(ctx context.Context, c *minio.Client, w io.Writer, b ObjectBudget, refs []team.ObjectRef, check TeamSourceCheck) error {
	if ctx == nil || c == nil || w == nil || check == nil || len(refs) == 0 || len(refs) > b.MaxItems || b.MaxBytes <= 0 {
		return errors.New("teams_source_unavailable")
	}
	refs = append([]team.ObjectRef(nil), refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Bucket+"\x00"+refs[i].Key < refs[j].Bucket+"\x00"+refs[j].Key })
	buckets := []string{}
	previous := ""
	for _, ref := range refs {
		id := ref.Bucket + "\x00" + ref.Key
		if ref.Validate() != nil || id == previous {
			return errors.New("invalid_object_scope")
		}
		previous = id
		if len(buckets) == 0 || buckets[len(buckets)-1] != ref.Bucket {
			buckets = append(buckets, ref.Bucket)
		}
	}
	whole := sha256.New()
	var total int64
	emit := func(record ObjectRecord, final bool) error {
		raw, e := json.Marshal(record)
		if e != nil {
			return e
		}
		raw = append(raw, '\n')
		total += int64(len(raw))
		if total > b.MaxBytes {
			return errors.New("capacity_exceeded")
		}
		if !final {
			whole.Write(raw)
		}
		return writeFull(w, raw)
	}
	if err := emit(ObjectRecord{Kind: "object_bytes_v1", Buckets: buckets}, false); err != nil {
		return err
	}
	buffer := make([]byte, 128<<10)
	for _, ref := range refs {
		if check(ctx) != nil || ctx.Err() != nil {
			return errors.New("permission_denied")
		}
		stat, err := c.StatObject(ctx, ref.Bucket, ref.Key, minio.StatObjectOptions{VersionID: ref.Version})
		if err != nil || stat.VersionID != ref.Version || stat.Size != ref.Size {
			return errors.New("source_object_mismatch")
		}
		meta := ObjectMetadata{Bucket: ref.Bucket, Key: ref.Key, Version: ref.Version, Size: ref.Size, ContentType: stat.ContentType, UserMetadata: stat.UserMetadata, ModifiedAt: stat.LastModified}
		if err = emit(ObjectRecord{Kind: "object", Metadata: &meta}, false); err != nil {
			return err
		}
		object, err := c.GetObject(ctx, ref.Bucket, ref.Key, minio.GetObjectOptions{VersionID: ref.Version})
		if err != nil {
			return errors.New("source_object_unavailable")
		}
		sum := sha256.New()
		var size int64
		for {
			n, e := object.Read(buffer)
			if n > 0 {
				size += int64(n)
				if size > ref.Size || check(ctx) != nil {
					object.Close()
					return errors.New("source_object_mismatch")
				}
				sum.Write(buffer[:n])
				if err = emit(ObjectRecord{Kind: "chunk", Data: buffer[:n]}, false); err != nil {
					object.Close()
					return err
				}
			}
			if e != nil {
				object.Close()
				if e != io.EOF {
					return errors.New("source_object_unavailable")
				}
				break
			}
		}
		if size != ref.Size || !bytes.Equal(sum.Sum(nil), mustDecodeTeamHash(ref.SHA256)) {
			return errors.New("source_object_mismatch")
		}
		if err = emit(ObjectRecord{Kind: "end_object", Count: size, SHA256: ref.SHA256}, false); err != nil {
			return err
		}
	}
	if check(ctx) != nil {
		return errors.New("permission_denied")
	}
	return emit(ObjectRecord{Kind: "end", Count: int64(len(refs)), SHA256: hex.EncodeToString(whole.Sum(nil))}, true)
}
func mustDecodeTeamHash(s string) []byte { b, _ := hex.DecodeString(s); return b }
