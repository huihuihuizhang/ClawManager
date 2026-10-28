package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func ConfigFormatSupported(format string) bool {
	return format == "" || format == "json" || format == "yaml" || format == "toml" || format == "dotenv"
}

// NormalizeDocument uses the same exhaustive leaf policy for each format.
// Aliases/merge keys, duplicate keys, multi-document YAML, TOML date/time and
// shell interpolation are rejected. Source archives retain their original bytes.
func NormalizeDocument(ctx context.Context, format string, raw []byte, rules []JSONRule) (Cell, error) {
	if len(raw) > 8<<20 || len(rules) == 0 || !ConfigFormatSupported(format) {
		return Cell{}, ErrNormalization
	}
	registry := JSONRegistry{"document": rules}
	if format == "" || format == "json" {
		return registry.NormalizeJSON(ctx, "document", Cell{Bytes: raw})
	}
	var doc any
	switch format {
	case "yaml":
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		var root yaml.Node
		if decoder.Decode(&root) != nil {
			return Cell{}, ErrNormalization
		}
		var extra yaml.Node
		if decoder.Decode(&extra) != io.EOF {
			return Cell{}, ErrNormalization
		}
		count := 0
		if !validYAML(&root, 0, &count) || root.Decode(&doc) != nil {
			return Cell{}, ErrNormalization
		}
	case "toml":
		if toml.Unmarshal(raw, &doc) != nil {
			return Cell{}, ErrNormalization
		}
	case "dotenv":
		var e error
		doc, e = parseDotenv(raw)
		if e != nil {
			return Cell{}, e
		}
	}
	if !plainDocument(doc, 0) {
		return Cell{}, ErrNormalization
	}
	b, e := json.Marshal(doc)
	if e != nil {
		return Cell{}, ErrNormalization
	}
	defer clear(b)
	normalized, e := registry.NormalizeJSON(ctx, "document", Cell{Bytes: b})
	if e != nil {
		return Cell{}, e
	}
	defer clear(normalized.Bytes)
	decoder := json.NewDecoder(bytes.NewReader(normalized.Bytes))
	decoder.UseNumber()
	if decoder.Decode(&doc) != nil {
		return Cell{}, ErrNormalization
	}
	doc, e = numberValues(doc)
	if e != nil {
		return Cell{}, e
	}
	switch format {
	case "yaml":
		b, e = yaml.Marshal(doc)
	case "toml":
		b, e = toml.Marshal(doc)
	case "dotenv":
		b, e = marshalDotenv(doc)
	}
	if e != nil || len(b) > 8<<20 {
		return Cell{}, ErrNormalization
	}
	return Cell{Bytes: b}, nil
}
func validYAML(n *yaml.Node, depth int, count *int) bool {
	*count++
	if depth > 64 || *count > 100000 || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		if len(n.Content)%2 != 0 {
			return false
		}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
		}
	}
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return false
		}
	}
	for _, child := range n.Content {
		if !validYAML(child, depth+1, count) {
			return false
		}
	}
	return true
}
func plainDocument(v any, depth int) bool {
	if depth > 64 {
		return false
	}
	switch x := v.(type) {
	case nil, string, bool, int, int64, uint64:
		return true
	case float64:
		return !math.IsNaN(x) && !math.IsInf(x, 0)
	case map[string]any:
		for _, c := range x {
			if !plainDocument(c, depth+1) {
				return false
			}
		}
		return true
	case []any:
		for _, c := range x {
			if !plainDocument(c, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}
func numberValues(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		if !strings.ContainsAny(string(x), ".eE") {
			n, e := x.Int64()
			if e != nil {
				return nil, ErrNormalization
			}
			return n, nil
		}
		n, e := x.Float64()
		if e != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, ErrNormalization
		}
		return n, nil
	case map[string]any:
		for k, c := range x {
			n, e := numberValues(c)
			if e != nil {
				return nil, e
			}
			x[k] = n
		}
	case []any:
		for i, c := range x {
			n, e := numberValues(c)
			if e != nil {
				return nil, e
			}
			x[i] = n
		}
	}
	return v, nil
}

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func parseDotenv(raw []byte) (map[string]any, error) {
	values := map[string]any{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || !envKey.MatchString(key) || strings.ContainsAny(value, "$`\x00\r\n") {
			return nil, ErrNormalization
		}
		if _, exists := values[key]; exists {
			return nil, ErrNormalization
		}
		if strings.HasPrefix(value, "\"") {
			var e error
			value, e = strconv.Unquote(value)
			if e != nil {
				return nil, ErrNormalization
			}
		} else if strings.HasPrefix(value, "'") {
			if len(value) < 2 || value[len(value)-1] != '\'' || strings.Contains(value[1:len(value)-1], "'") {
				return nil, ErrNormalization
			}
			value = value[1 : len(value)-1]
		} else if strings.ContainsAny(value, "# \t\"'") {
			return nil, ErrNormalization
		}
		values[key] = value
	}
	return values, nil
}
func marshalDotenv(v any) ([]byte, error) {
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, ErrNormalization
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		if !envKey.MatchString(k) {
			return nil, ErrNormalization
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v, ok := doc[k].(string)
		if !ok || strings.ContainsAny(v, "$`\x00\r\n") {
			return nil, ErrNormalization
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(v))
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
