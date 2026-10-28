package domain

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// JSONRule uses JSON pointer segments; "*" matches one map/array segment.
// Every leaf must match EXACTLY ONE rule. No fallback to preserve unknown keys.
// Shared owners provide rules for their versioned config/runtime schemas.
type JSONRule struct {
	Path     []string
	Action   string
	Required bool
}
type JSONRegistry map[string][]JSONRule // "table.column" or "runtime.file"

type drillStubKey struct{}

// WithDrillStubKey permits a separate read-only verifier to reproduce the exact
// nonfunctional values without exposing the original credentials. The key is
// the task-scoped data key, not a source application credential.
func WithDrillStubKey(ctx context.Context, key []byte) context.Context {
	return context.WithValue(ctx, drillStubKey{}, key)
}

func (r JSONRegistry) NormalizeConfig(ctx context.Context, table, column string, value Cell) (Cell, error) {
	return r.NormalizeJSON(ctx, table+"."+column, value)
}
func (r JSONRegistry) NormalizeJSON(ctx context.Context, field string, value Cell) (Cell, error) {
	rules, ok := r[field]
	if !ok || len(rules) == 0 || value.Null || len(value.Bytes) > 8<<20 {
		return Cell{}, ErrNormalization
	}
	if strictJSON(value.Bytes) != nil {
		return Cell{}, ErrNormalization
	}
	for _, rule := range rules {
		switch rule.Action {
		case "preserve", "stub", "disable", "disable-string":
		default:
			return Cell{}, ErrNormalization
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(value.Bytes))
	decoder.UseNumber()
	var doc any
	if decoder.Decode(&doc) != nil {
		return Cell{}, ErrNormalization
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Cell{}, ErrNormalization
	}
	counts := make([]int, len(rules))
	var walk func(any, []string) (any, error)
	walk = func(v any, p []string) (any, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch x := v.(type) {
		case map[string]any:
			if len(x) > 0 {
				for key, child := range x {
					n, e := walk(child, append(append([]string(nil), p...), key))
					if e != nil {
						return nil, e
					}
					x[key] = n
				}
				return x, nil
			}
		case []any:
			if len(x) > 0 {
				for i, child := range x {
					n, e := walk(child, append(append([]string(nil), p...), strconv.Itoa(i)))
					if e != nil {
						return nil, e
					}
					x[i] = n
				}
				return x, nil
			}
		}
		matched := -1
		for i, rule := range rules {
			if len(rule.Path) != len(p) {
				continue
			}
			matches := true
			for j, part := range rule.Path {
				if part != "*" && part != p[j] {
					matches = false
				}
			}
			if matches {
				if matched >= 0 {
					return nil, ErrNormalization
				}
				matched = i
			}
		}
		if matched < 0 {
			return nil, ErrNormalization
		}
		counts[matched]++
		switch rules[matched].Action {
		case "preserve":
			return v, nil
		case "disable":
			if _, ok := v.(bool); !ok {
				return nil, ErrNormalization
			}
			return false, nil
		case "disable-string":
			value, ok := v.(string)
			if !ok {
				return nil, ErrNormalization
			}
			switch value {
			case "0", "1":
				return "0", nil
			case "true", "false":
				return "false", nil
			case "yes", "no":
				return "no", nil
			case "enabled", "disabled":
				return "disabled", nil
			}
			return nil, ErrNormalization
		case "stub":
			if _, ok := v.(string); !ok {
				return nil, ErrNormalization
			}
			random := make([]byte, 32)
			if key, ok := ctx.Value(drillStubKey{}).([]byte); ok && len(key) == 32 {
				mac := hmac.New(sha256.New, key)
				raw, _ := json.Marshal([]any{"clawmanager/drill-config/v1", field, p})
				mac.Write(raw)
				copy(random, mac.Sum(nil))
			} else if _, e := rand.Read(random); e != nil {
				return nil, ErrNormalization
			}
			return "drill-disabled-" + hex.EncodeToString(random), nil
		}
		return nil, ErrNormalization
	}
	n, e := walk(doc, nil)
	if e != nil {
		return Cell{}, ErrNormalization
	}
	for i, rule := range rules {
		if rule.Required && counts[i] == 0 {
			return Cell{}, ErrNormalization
		}
	}
	b, e := json.Marshal(n)
	if e != nil {
		return Cell{}, ErrNormalization
	}
	return Cell{Bytes: b}, nil
}

// RulePointer is a convenience for explicit registry entries; it does not infer
// secret classification from key names. Invalid pointer escapes are rejected.
func RulePointer(pointer, action string, required bool) (JSONRule, error) {
	r := JSONRule{Action: action, Required: required}
	if pointer == "" {
		return r, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return JSONRule{}, ErrNormalization
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		for i := 0; i < len(part); i++ {
			if part[i] == '~' {
				if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
					return JSONRule{}, ErrNormalization
				}
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		r.Path = append(r.Path, part)
	}
	return r, nil
}
