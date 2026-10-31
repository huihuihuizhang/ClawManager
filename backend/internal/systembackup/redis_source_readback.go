package systembackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"clawreef/internal/systembackup/recovery"
)

type RedisSourceSnapshotHeader struct {
	Version                    string
	Source                     recovery.Reference
	ServerID                   string
	Database                   int
	Prefixes, ExcludedPrefixes []string
	CapturedAtMillis           int64
}
type RedisSourceSnapshot struct {
	Header RedisSourceSnapshotHeader
	Items  []recovery.RedisItem
}
type redisSourceEnd struct {
	Kind   string
	Count  int64
	SHA256 string
}

func decodeRedisSourceRecord(raw []byte, out any) error {
	closed := json.NewDecoder(bytes.NewReader(raw))
	closed.DisallowUnknownFields()
	if closed.Decode(out) != nil || closed.Decode(new(any)) != io.EOF {
		return errors.New("redis_source_readback_invalid")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("redis_source_readback_invalid")
	}
	return nil
}

// Independent inert parser: no source reads, decryption callback or mutations.
// A caller must authenticate the original encrypted stream separately. Failure
// returns no partial rows, including a missing/mismatched end record or suffix.
func ReadSourceRedisSnapshot(ctx context.Context, src io.Reader, policy RedisCapturePolicy) (RedisSourceSnapshot, error) {
	var zero RedisSourceSnapshot
	bad := func() (RedisSourceSnapshot, error) { return zero, errors.New("redis_source_readback_invalid") }
	if ctx == nil || ctx.Err() != nil || src == nil || policy.Validate() != nil {
		return bad()
	}
	limited := &io.LimitedReader{R: src, N: policy.Policy.MaxBytes + 1}
	decoder := json.NewDecoder(limited)
	var header RedisSourceSnapshotHeader
	var raw json.RawMessage
	if decoder.Decode(&raw) != nil || decodeRedisSourceRecord(raw, &header) != nil || header.Version != RedisSourceSnapshotVersion || header.Source != policy.Policy.Source || header.ServerID != policy.ServerID || header.Database != policy.Policy.DB || !reflect.DeepEqual(header.Prefixes, policy.Policy.Prefixes) || !reflect.DeepEqual(header.ExcludedPrefixes, policy.ExcludePrefixes) || header.CapturedAtMillis <= 0 || header.CapturedAtMillis > 9007199254740991 {
		return bad()
	}
	result := RedisSourceSnapshot{Header: header, Items: []recovery.RedisItem{}}
	success := false
	defer func() {
		if !success {
			ClearSourceRedisSnapshot(result)
		}
	}()
	sum := sha256.New()
	previous := ""
	for {
		if ctx.Err() != nil || limited.N <= 0 {
			return bad()
		}
		if decoder.Decode(&raw) != nil || int64(len(raw)) > policy.Policy.MaxBytes {
			return bad()
		}
		var marker struct{ Kind string }
		if json.Unmarshal(raw, &marker) != nil {
			return bad()
		}
		if marker.Kind == "end" {
			var end redisSourceEnd
			if decodeRedisSourceRecord(raw, &end) != nil || end.Count != int64(len(result.Items)) || end.SHA256 != hex.EncodeToString(sum.Sum(nil)) || decoder.Decode(new(any)) != io.EOF || limited.N < 1 || ctx.Err() != nil {
				return bad()
			}
			success = true
			return result, nil
		}
		if int64(len(result.Items)) >= policy.Policy.MaxItems {
			return bad()
		}
		var item recovery.RedisItem
		if decodeRedisSourceRecord(raw, &item) != nil || item.CapturedAt != header.CapturedAtMillis || policy.Policy.ValidateItem(item, header.CapturedAtMillis) != nil || !policy.allows(string(item.Key)) || string(item.Key) <= previous {
			return bad()
		}
		if item.Type == "stream" {
			if !validRedisSourceGroups(item.StreamGroups) {
				return bad()
			}
		}
		previous = string(item.Key)
		sum.Write(raw)
		sum.Write([]byte{'\n'})
		result.Items = append(result.Items, item)
	}
}

func ClearSourceRedisSnapshot(snapshot RedisSourceSnapshot) {
	for _, item := range snapshot.Items {
		clear(item.Key)
		clear(item.Dump)
		clear(item.StreamGroups)
	}
}

// Bridge verified source snapshots to the existing inert cm:restore-history
// reader. Original binary DUMP includes group/PEL state; absolute expiry is
// retained. This adapter performs no restore and grants no target permission.
func AdaptSourceRedisHistory(ctx context.Context, src io.Reader, dst io.Writer, policy RedisCapturePolicy) error {
	if dst == nil {
		return errors.New("redis_source_readback_invalid")
	}
	snapshot, err := ReadSourceRedisSnapshot(ctx, src, policy)
	if err != nil {
		return err
	}
	defer ClearSourceRedisSnapshot(snapshot)
	encoder := json.NewEncoder(dst)
	if encoder.Encode(RedisRecord{Kind: "redis_dump_v1", ServerID: snapshot.Header.ServerID, CapturedAtMillis: snapshot.Header.CapturedAtMillis}) != nil {
		return errors.New("redis_source_readback_invalid")
	}
	sum := sha256.New()
	for _, item := range snapshot.Items {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := json.Marshal(RedisRecord{Kind: "key", Key: item.Key, Type: item.Type, Dump: item.Dump, ExpiresAtMillis: item.ExpiresAt})
		if err != nil {
			return errors.New("redis_source_readback_invalid")
		}
		if n, err := dst.Write(append(raw, '\n')); err != nil || n != len(raw)+1 {
			return errors.New("redis_source_readback_invalid")
		}
		sum.Write(raw)
		sum.Write([]byte{'\n'})
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return encoder.Encode(RedisRecord{Kind: "end", Count: int64(len(snapshot.Items)), SHA256: hex.EncodeToString(sum.Sum(nil))})
}
