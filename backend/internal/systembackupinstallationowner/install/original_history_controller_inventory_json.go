package install

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

// Validate complete JSON without float64 normalization or dropping unknown
// object fields. Duplicate keys, invalid UTF-8/surrogates and deep inputs fail.
func originalHistoryControllerJSON(raw []byte) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	inString := false
	for n := 0; n < len(raw); n++ {
		if raw[n] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[n] != '\\' {
			continue
		}
		n++
		if n >= len(raw) {
			return false
		}
		if raw[n] != 'u' {
			continue
		}
		if n+4 >= len(raw) {
			return false
		}
		first, e := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
		if e != nil {
			return false
		}
		n += 4
		if first >= 0xDC00 && first <= 0xDFFF {
			return false
		}
		if first >= 0xD800 && first <= 0xDBFF {
			if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
				return false
			}
			second, e := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
			if e != nil || second < 0xDC00 || second > 0xDFFF {
				return false
			}
			n += 6
		}
	}
	if inString {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return false
				}
				s, ok := key.(string)
				if !ok || keys[s] {
					return false
				}
				keys[s] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func originalHistoryControllerText(raw json.RawMessage, required bool) (string, bool) {
	if len(raw) == 0 {
		return "", !required
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || required && s == "" || len(s) > 8192 {
		return "", false
	}
	return s, true
}

func decodeOriginalHistoryControllerPage(raw []byte, source originalHistoryControllerResource, namespace string) (result []originalHistoryControllerDefinition, version, next string, err error) {
	if !originalHistoryControllerJSON(raw) {
		return nil, "", "", ErrInstall
	}
	var page map[string]json.RawMessage
	if json.Unmarshal(raw, &page) != nil || page == nil || len(page) != 4 {
		return nil, "", "", ErrInstall
	}
	api, ok := originalHistoryControllerText(page["apiVersion"], true)
	if !ok || api != source.apiVersion {
		return nil, "", "", ErrInstall
	}
	kind, ok := originalHistoryControllerText(page["kind"], true)
	if !ok || kind != source.kind+"List" {
		return nil, "", "", ErrInstall
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(page["metadata"], &metadata) != nil || metadata == nil {
		return nil, "", "", ErrInstall
	}
	for key := range metadata {
		if key != "resourceVersion" && key != "continue" && key != "remainingItemCount" && key != "selfLink" {
			return nil, "", "", ErrInstall
		}
	}
	version, ok = originalHistoryControllerText(metadata["resourceVersion"], true)
	if !ok {
		return nil, "", "", ErrInstall
	}
	next, ok = originalHistoryControllerText(metadata["continue"], false)
	if !ok {
		return nil, "", "", ErrInstall
	}
	if _, ok = originalHistoryControllerText(metadata["selfLink"], false); !ok {
		return nil, "", "", ErrInstall
	}
	if count := metadata["remainingItemCount"]; len(count) != 0 && string(count) != "null" {
		n, e := strconv.ParseUint(string(count), 10, 64)
		if e != nil || next == "" && n != 0 {
			return nil, "", "", ErrInstall
		}
	}
	var items []json.RawMessage
	if len(page["items"]) == 0 || page["items"][0] != '[' || json.Unmarshal(page["items"], &items) != nil || len(items) > 128 {
		return nil, "", "", ErrInstall
	}
	defer func() {
		if err != nil {
			for n := range result {
				clear(result[n].body)
			}
			result = nil
		}
	}()
	for _, body := range items {
		if len(body) == 0 || len(body) > 2<<20 {
			return result, "", "", ErrInstall
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(body, &object) != nil || object == nil {
			return result, "", "", ErrInstall
		}
		// Nested TypeMeta may be omitted by a typed LIST codec. The authenticated
		// code-owned endpoint/List kind fixes it; conflicting explicit values fail.
		if v, ok := originalHistoryControllerText(object["apiVersion"], false); !ok || v != "" && v != source.apiVersion {
			return result, "", "", ErrInstall
		}
		if v, ok := originalHistoryControllerText(object["kind"], false); !ok || v != "" && v != source.kind {
			return result, "", "", ErrInstall
		}
		var meta map[string]json.RawMessage
		if json.Unmarshal(object["metadata"], &meta) != nil || meta == nil || len(object["spec"]) == 0 || object["spec"][0] != '{' {
			return result, "", "", ErrInstall
		}
		ns, ok := originalHistoryControllerText(meta["namespace"], true)
		if !ok || ns != namespace {
			return result, "", "", ErrInstall
		}
		name, ok := originalHistoryControllerText(meta["name"], true)
		if !ok {
			return result, "", "", ErrInstall
		}
		uid, ok := originalHistoryControllerText(meta["uid"], true)
		if !ok {
			return result, "", "", ErrInstall
		}
		rv, ok := originalHistoryControllerText(meta["resourceVersion"], true)
		if !ok {
			return result, "", "", ErrInstall
		}
		owned := bytes.Clone(body)
		result = append(result, originalHistoryControllerDefinition{kind: source.kind, namespace: ns, name: name, uid: uid, version: rv, sha256: hash(owned), body: owned})
	}
	return result, version, next, nil
}
