package systembackupproducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"unicode/utf8"
)

const (
	ScopeDomain          = "system-backup-producer-scope.c1"
	TargetDomain         = "system-backup-producer-target.c1"
	ResultKeyDomain      = "system-backup-producer-result-key.c1"
	ResultRequestDomain  = "system-backup-producer-result-request.c1"
	CommandKeyDomain     = "system-backup-producer-command-key.c1"
	CommandRequestDomain = "system-backup-producer-command-request.c1"
)

type ResultDigests struct {
	Scope   Hash `json:"scope"`
	Target  Hash `json:"target"`
	Key     Hash `json:"key"`
	Request Hash `json:"request"`
}
type CommandDigests struct {
	Key     Hash `json:"key"`
	Request Hash `json:"request"`
}

// CanonicalJSON is the C1 typed frame, NOT JSON/JCS. Raw numeric JSON is rejected.
func CanonicalJSON(raw []byte) ([]byte, error) {
	v, e := parseJSON(raw)
	if e != nil {
		return nil, e
	}
	return canonicalTree(v)
}
func canonicalTree(v any) ([]byte, error) {
	var b bytes.Buffer
	writeLen := func(n int) { var size [8]byte; binary.BigEndian.PutUint64(size[:], uint64(n)); b.Write(size[:]) }
	var encode func(any) error
	encode = func(v any) error {
		switch x := v.(type) {
		case nil:
			b.WriteByte('n')
		case bool:
			if x {
				b.WriteByte('t')
			} else {
				b.WriteByte('f')
			}
		case string:
			if !utf8.ValidString(x) {
				return ErrInvalid
			}
			b.WriteByte('s')
			writeLen(len(x))
			b.WriteString(x)
		case []any:
			b.WriteByte('a')
			writeLen(len(x))
			for _, v := range x {
				if e := encode(v); e != nil {
					return e
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('o')
			writeLen(len(keys))
			for _, k := range keys {
				if e := encode(k); e != nil {
					return e
				}
				if e := encode(x[k]); e != nil {
					return e
				}
			}
		default:
			return ErrInvalid
		}
		if b.Len() > MaxJSONBytes {
			return ErrInvalid
		}
		return nil
	}
	if e := encode(v); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func hashTree(domain string, v any) (Hash, error) {
	if !utf8.ValidString(domain) {
		return "", ErrInvalid
	}
	encoded, e := canonicalTree(v)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(domain)))
	h.Write(size[:])
	h.Write([]byte(domain))
	h.Write(encoded)
	return Hash(hex.EncodeToString(h.Sum(nil))), nil
}
func recordTree(v any) (map[string]any, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, ErrInvalid
	}
	tree, e := parseJSON(raw)
	if e != nil {
		return nil, e
	}
	m, ok := tree.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return m, nil
}
func logicalTarget(target map[string]any) map[string]any {
	m := map[string]any{}
	for _, k := range []string{"evaluator_owner", "role", "identity_hash", "ref_version", "probe_scope_hash"} {
		m[k] = target[k]
	}
	return m
}
func targetDigest(t Target) (Hash, error) {
	m, e := recordTree(t)
	if e != nil {
		return "", e
	}
	return hashTree(TargetDomain, logicalTarget(m))
}
func ResultHashes(r ResultRequest) (ResultDigests, error) {
	if e := validateTyped(reflect.ValueOf(r)); e != nil {
		return ResultDigests{}, e
	}
	return resultHashesUnchecked(r)
}
func resultHashesUnchecked(r ResultRequest) (ResultDigests, error) {
	m, e := recordTree(r)
	if e != nil {
		return ResultDigests{}, e
	}
	target := logicalTarget(m["target"].(map[string]any))
	key := map[string]any{"target_key": target}
	for _, k := range []string{"scope", "grant_id", "grant_generation", "run_id", "purpose", "request_key"} {
		key[k] = m[k]
	}
	var h ResultDigests
	if h.Scope, e = hashTree(ScopeDomain, m["scope"]); e != nil {
		return h, e
	}
	if h.Target, e = hashTree(TargetDomain, target); e != nil {
		return h, e
	}
	if h.Key, e = hashTree(ResultKeyDomain, key); e != nil {
		return h, e
	}
	h.Request, e = hashTree(ResultRequestDomain, m)
	return h, e
}
func CommandHashes(r CommandRequest) (CommandDigests, error) {
	if e := validateTyped(reflect.ValueOf(r)); e != nil {
		return CommandDigests{}, e
	}
	return commandHashesUnchecked(r)
}
func commandHashesUnchecked(r CommandRequest) (CommandDigests, error) {
	m, e := recordTree(r)
	if e != nil {
		return CommandDigests{}, e
	}
	key := map[string]any{}
	for _, k := range []string{"scope", "actor_identity_hash", "command", "request_key"} {
		key[k] = m[k]
	}
	var h CommandDigests
	if h.Key, e = hashTree(CommandKeyDomain, key); e != nil {
		return h, e
	}
	h.Request, e = hashTree(CommandRequestDomain, m)
	return h, e
}
