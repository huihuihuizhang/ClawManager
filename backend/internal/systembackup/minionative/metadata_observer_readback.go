package minionative

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// NormalizeSeptemberMetadataObserverReadback is data normalization, never
// authority. The caller MUST first authenticate the fixed September native
// release/commit/deployment/region over its pinned TLS transport.
// Only the exact two-statement metadata observer document is accepted. Its
// admin resource singleton "**" is the observed September serialization of
// the originally submitted "*". All bucket ARNs and original policy pins stay
// unchanged; callers MUST still verify the entire original hash and rules.
func NormalizeSeptemberMetadataObserverReadback(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 65536 || metadataReadbackUniqueJSON(raw) != nil {
		return nil, ErrNative
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || len(doc) != 2 || doc["Version"] == nil || doc["Statement"] == nil {
		return nil, ErrNative
	}
	var version string
	var statements []map[string]json.RawMessage
	if json.Unmarshal(doc["Version"], &version) != nil || version != "2012-10-17" || json.Unmarshal(doc["Statement"], &statements) != nil || len(statements) != 2 {
		return nil, ErrNative
	}
	admin, bucket := 0, 0
	stable := []json.RawMessage{}
	for _, s := range statements {
		if len(s) != 3 || s["Effect"] == nil || s["Action"] == nil || s["Resource"] == nil {
			return nil, ErrNative
		}
		var effect string
		var actions, resources []string
		if json.Unmarshal(s["Effect"], &effect) != nil || effect != "Allow" || json.Unmarshal(s["Action"], &actions) != nil || json.Unmarshal(s["Resource"], &resources) != nil {
			return nil, ErrNative
		}
		sort.Strings(actions)
		sort.Strings(resources)
		switch {
		case metadataReadbackStringsEqual(actions, []string{"admin:GetPolicy", "admin:GetUser", "admin:ServerInfo"}):
			if !metadataReadbackStringsEqual(resources, []string{"**"}) {
				return nil, ErrNative
			}
			admin++
			resources = []string{"*"}
		case metadataReadbackStringsEqual(actions, []string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}):
			if len(resources) < 1 || len(resources) > 16 {
				return nil, ErrNative
			}
			for i, r := range resources {
				if !metadataReadbackBucketARN.MatchString(r) || i > 0 && resources[i-1] == r {
					return nil, ErrNative
				}
			}
			bucket++
		default:
			return nil, ErrNative
		}
		s["Action"], _ = ce.Canonical(actions)
		s["Resource"], _ = ce.Canonical(resources)
		b, e := ce.Canonical(s)
		if e != nil {
			return nil, e
		}
		stable = append(stable, b)
	}
	if admin != 1 || bucket != 1 {
		return nil, ErrNative
	}
	sort.Slice(stable, func(i, j int) bool { return bytes.Compare(stable[i], stable[j]) < 0 })
	doc["Statement"], _ = ce.Canonical(stable)
	return ce.Canonical(doc)
}

var metadataReadbackBucketARN = regexp.MustCompile(`^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func metadataReadbackStringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Reject duplicate keys, trailing JSON and excessive nesting before map decode.
func metadataReadbackUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var read func(int) error
	read = func(depth int) error {
		nodes++
		if depth > 12 || nodes > 512 {
			return ErrNative
		}
		token, e := d.Token()
		if e != nil {
			return ErrNative
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, e := d.Token()
				if e != nil {
					return ErrNative
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return ErrNative
				}
				seen[key] = true
				if read(depth+1) != nil {
					return ErrNative
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrNative
			}
		case '[':
			for d.More() {
				if read(depth+1) != nil {
					return ErrNative
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrNative
			}
		default:
			return ErrNative
		}
		return nil
	}
	if read(0) != nil {
		return ErrNative
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrNative
	}
	return nil
}
