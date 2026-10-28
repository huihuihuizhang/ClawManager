package systembackupskillhub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxObjectMetadataBytes = 16 * 1024

var ErrObjectMetadata = errors.New("skill hub object metadata invalid or mismatched")

// ObjectMetadata is the closed v12 restoration allowlist. Header values are
// preserved verbatim; absent values remain empty. User keys are lower-case
// HTTP tokens without the x-amz-meta- prefix.
type ObjectMetadata struct {
	ContentType, ContentEncoding, CacheControl   string
	ContentDisposition, ContentLanguage, Expires string
	UserMetadata                                 map[string]string
}

// Properties come from the same exact-version GET as the body. Omitted user
// metadata MUST become a disqualifying warning in the reviewed public adapter.
// The local count does not constitute a public warning code or acceptance.
type ObjectProperties struct {
	ETag, LastModified  string
	Metadata            ObjectMetadata
	OmittedUserMetadata int
}

func metadataValue(m ObjectMetadata) map[string]any {
	user := map[string]any{}
	for k, v := range m.UserMetadata {
		user[k] = v
	}
	return map[string]any{"cache_control": m.CacheControl, "content_disposition": m.ContentDisposition,
		"content_encoding": m.ContentEncoding, "content_language": m.ContentLanguage,
		"content_type": m.ContentType, "expires": m.Expires, "user_metadata_allowlist": user}
}

func metadataKey(key string) bool {
	if key == "" || key != strings.ToLower(key) {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func metadataText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c == 127 || c < 32 && c != '\t' {
			return false
		}
	}
	return true
}

// CanonicalObjectMetadata returns bounded JCS bytes, including empty fields.
// All object member names are ASCII, so byte order equals JCS UTF-16 order.
func CanonicalObjectMetadata(ctx context.Context, m ObjectMetadata) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(m.UserMetadata) > MaxObjectMetadataBytes {
		return nil, ErrCapacity
	}
	total := 0
	add := func(s string) bool {
		if len(s) > MaxObjectMetadataBytes-total {
			return false
		}
		total += len(s)
		return true
	}
	for _, s := range []string{m.ContentType, m.ContentEncoding, m.CacheControl, m.ContentDisposition, m.ContentLanguage, m.Expires} {
		if !add(s) {
			return nil, ErrCapacity
		}
		if !metadataText(s) {
			return nil, ErrObjectMetadata
		}
	}
	for k, v := range m.UserMetadata {
		if !add(k) || !add(v) {
			return nil, ErrCapacity
		}
		if !metadataKey(k) || !metadataText(v) {
			return nil, ErrObjectMetadata
		}
	}
	var out bytes.Buffer
	if _, err := canonicalObjectJSON(ctx, &out, metadataValue(m), MaxObjectMetadataBytes); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func cloneMetadata(m ObjectMetadata) ObjectMetadata {
	user := make(map[string]string, len(m.UserMetadata))
	for k, v := range m.UserMetadata {
		user[k] = v
	}
	m.UserMetadata = user
	return m
}
func cloneProperties(p *ObjectProperties) *ObjectProperties {
	if p == nil {
		return nil
	}
	out := *p
	out.Metadata = cloneMetadata(p.Metadata)
	return &out
}
func sameMetadata(a, b ObjectMetadata) bool {
	return reflect.DeepEqual(cloneMetadata(a), cloneMetadata(b))
}

func s3Metadata(ctx context.Context, headers http.Header, allow map[string]bool) (ObjectMetadata, int, error) {
	if len(headers) > MaxObjectMetadataBytes {
		return ObjectMetadata{}, 0, ErrCapacity
	}
	values := map[string]string{}
	user := map[string]string{}
	seen := map[string]bool{}
	omitted := 0
	for key, list := range headers {
		key = strings.ToLower(key)
		isUser := strings.HasPrefix(key, "x-amz-meta-")
		switch key {
		case "content-type", "content-encoding", "cache-control", "content-disposition", "content-language", "expires":
		default:
			if !isUser {
				continue
			}
		}
		if seen[key] || len(list) != 1 {
			return ObjectMetadata{}, 0, ErrObjectMetadata
		}
		seen[key] = true
		if isUser {
			name := strings.TrimPrefix(key, "x-amz-meta-")
			if !metadataKey(name) {
				return ObjectMetadata{}, 0, ErrObjectMetadata
			}
			if !allow[name] {
				omitted++
				continue
			}
			user[name] = list[0]
		} else {
			values[key] = list[0]
		}
	}
	m := ObjectMetadata{ContentType: values["content-type"], ContentEncoding: values["content-encoding"],
		CacheControl: values["cache-control"], ContentDisposition: values["content-disposition"],
		ContentLanguage: values["content-language"], Expires: values["expires"], UserMetadata: user}
	if _, err := CanonicalObjectMetadata(ctx, m); err != nil {
		return ObjectMetadata{}, 0, err
	}
	return m, omitted, nil
}

// Internal encoder for closed, string/integer-only local index records. Strings
// use JCS escaping, numbers are exact IEEE-754 integers, and keys are ASCII.
// The output budget is checked before each write. No whole-index buffer exists.
func canonicalObjectJSON(ctx context.Context, dst io.Writer, value any, max int64) (int64, error) {
	var n int64
	write := func(s string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(len(s)) > max-n {
			return ErrCapacity
		}
		for len(s) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			length := len(s)
			if length > 64*1024 {
				length = 64 * 1024
			}
			w, err := io.WriteString(dst, s[:length])
			n += int64(w)
			if err != nil || w != length {
				return objectIOError(ctx)
			}
			s = s[length:]
		}
		return nil
	}
	quote := func(s string) error {
		if !utf8.ValidString(s) {
			return ErrObjectMetadata
		}
		if err := write("\""); err != nil {
			return err
		}
		start := 0
		for i, r := range s {
			if i&16383 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if r >= 32 && r != '"' && r != '\\' {
				continue
			}
			if err := write(s[start:i]); err != nil {
				return err
			}
			escaped := ""
			switch r {
			case '"':
				escaped = `\"`
			case '\\':
				escaped = `\\`
			case '\b':
				escaped = `\b`
			case '\t':
				escaped = `\t`
			case '\n':
				escaped = `\n`
			case '\f':
				escaped = `\f`
			case '\r':
				escaped = `\r`
			default:
				escaped = `\u00` + string("0123456789abcdef"[r/16]) + string("0123456789abcdef"[r%16])
			}
			if err := write(escaped); err != nil {
				return err
			}
			start = i + 1
		}
		if err := write(s[start:]); err != nil {
			return err
		}
		return write("\"")
	}
	var encode func(any) error
	encode = func(value any) error {
		switch v := value.(type) {
		case string:
			return quote(v)
		case int64:
			if v < 0 || v > 9007199254740991 {
				return ErrObject
			}
			return write(strconv.FormatInt(v, 10))
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if err := write("{"); err != nil {
				return err
			}
			for i, k := range keys {
				if i > 0 {
					if err := write(","); err != nil {
						return err
					}
				}
				if err := quote(k); err != nil {
					return err
				}
				if err := write(":"); err != nil {
					return err
				}
				if err := encode(v[k]); err != nil {
					return err
				}
			}
			return write("}")
		default:
			return ErrObject
		}
	}
	if max < 0 {
		return 0, ErrCapacity
	}
	err := encode(value)
	return n, err
}
