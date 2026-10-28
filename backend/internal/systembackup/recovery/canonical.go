// Package recovery implements the six-domain publication/catalog contract.
// It does not infer provider capabilities or turn a partial domain bundle into
// an acceptance artifact. Provider and journal adapters are explicit boundaries.
package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrContract = errors.New("recovery contract invalid")
var ErrUnavailable = errors.New("recovery dependency unavailable or unproved")
var ErrConflict = errors.New("recovery immutable object conflict")
var ErrTombstoned = errors.New("catalog registration tombstoned")

const MaxDocument = 4 << 20

// Canonical implements RFC 8785 for this closed contract's JSON subset: Unicode
// scalar strings, booleans, null, arrays, objects and safe integer numbers only.
// Decimal/exponent numbers are rejected by the schema rather than rounded.
func Canonical(raw []byte) ([]byte, error) {
	if len(raw) > MaxDocument || !utf8.Valid(raw) || !validEscapes(raw) {
		return nil, ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := parseValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrContract
	}
	var out bytes.Buffer
	if e = encodeCanonical(&out, v); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}
func validEscapes(b []byte) bool {
	inside := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		v, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inside
}
func parseValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrContract
	}
	t, e := d.Token()
	if e != nil {
		return nil, ErrContract
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok {
					return nil, ErrContract
				}
				if _, ok = m[s]; ok {
					return nil, ErrContract
				}
				m[s], e = parseValue(d, depth+1)
				if e != nil {
					return nil, e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrContract
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := parseValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrContract
			}
			return a, nil
		}
		return nil, ErrContract
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return nil, ErrContract
		}
		n, e := strconv.ParseInt(string(v), 10, 64)
		if e != nil || n > 9007199254740991 || n < -9007199254740991 {
			return nil, ErrContract
		}
		return n, nil
	case string, bool, nil:
		return v, nil
	}
	return nil, ErrContract
}
func quote(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 32 {
				const h = "0123456789abcdef"
				out.WriteString(`\u00`)
				out.WriteByte(h[r>>4])
				out.WriteByte(h[r&15])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
func encodeCanonical(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(x))
	case int64:
		out.WriteString(strconv.FormatInt(x, 10))
	case string:
		quote(out, x)
	case []any:
		out.WriteByte('[')
		for i, v := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if e := encodeCanonical(out, v); e != nil {
				return e
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for k := 0; k < len(a) && k < len(b); k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return len(a) < len(b)
		})
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			quote(out, k)
			out.WriteByte(':')
			if e := encodeCanonical(out, x[k]); e != nil {
				return e
			}
		}
		out.WriteByte('}')
	default:
		return ErrContract
	}
	return nil
}
func Marshal(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrContract
	}
	return Canonical(b)
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func decode(raw []byte, v any) error {
	b, e := Canonical(raw)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrContract
	}
	return nil
}
