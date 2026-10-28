package systembackupproducer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type wireFixture struct {
	ID, Definition string
	Value          json.RawMessage
	Hashes         json.RawMessage
}
type fixtureSet struct {
	Positive, Commands, Records []wireFixture
	Negative                    []struct {
		ID, Source, Definition string
		Path                   []any
		Value                  json.RawMessage
		Remove                 bool
	}
	Encoding []struct {
		ID                  string
		Value               json.RawMessage
		Hex, Domain, SHA256 string
	}
}

func fixtures(t *testing.T) fixtureSet {
	t.Helper()
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var f fixtureSet
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func destination(name string) any {
	switch name {
	case "ResultRequest":
		return &ResultRequest{}
	case "CommandRequest":
		return &CommandRequest{}
	case "DomainRecord":
		return &DomainRecord{}
	case "GrantRecord":
		return &GrantRecord{}
	case "RunRecord":
		return &RunRecord{}
	case "TargetRecord":
		return &TargetRecord{}
	case "HistoricalBindingRecord":
		return &HistoricalBindingRecord{}
	case "ReceiptRecord":
		return &ReceiptRecord{}
	case "CommandReceiptRecord":
		return &CommandReceiptRecord{}
	case "ReferenceRecord":
		return &ReferenceRecord{}
	}
	panic("unknown test definition")
}
func TestC1Vectors(t *testing.T) {
	f := fixtures(t)
	for _, v := range append(append(append([]wireFixture{}, f.Positive...), f.Commands...), f.Records...) {
		t.Run(v.Definition+"/"+v.ID, func(t *testing.T) {
			out := destination(v.Definition)
			if e := DecodeRecord(v.Value, out); e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(out)
			if e != nil {
				t.Fatal(e)
			}
			want, e := CanonicalJSON(v.Value)
			if e != nil {
				t.Fatal(e)
			}
			got, e := CanonicalJSON(raw)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("typed roundtrip lost a field/null/byte", e)
			}
			switch r := out.(type) {
			case *ResultRequest:
				h, e := ResultHashes(*r)
				var want ResultDigests
				json.Unmarshal(v.Hashes, &want)
				if e != nil || h != want {
					t.Fatalf("hash parity: %v %+v != %+v", e, h, want)
				}
			case *CommandRequest:
				h, e := CommandHashes(*r)
				var want CommandDigests
				json.Unmarshal(v.Hashes, &want)
				if e != nil || h != want {
					t.Fatalf("hash parity: %v %+v != %+v", e, h, want)
				}
			}
		})
	}
	for _, v := range f.Negative {
		t.Run("reject/"+v.ID, func(t *testing.T) {
			var source json.RawMessage
			for _, p := range append(append([]wireFixture{}, f.Positive...), f.Commands...) {
				if p.ID == v.Source {
					source = p.Value
					break
				}
			}
			if len(source) == 0 {
				t.Fatal("missing source")
			}
			raw := patchJSON(t, source, v.Path, v.Value, v.Remove)
			if e := DecodeRecord(raw, destination(v.Definition)); !errors.Is(e, ErrInvalid) {
				t.Fatalf("expected invalid, got %v", e)
			}
		})
	}
}
func patchJSON(t *testing.T, raw json.RawMessage, path []any, value json.RawMessage, remove bool) json.RawMessage {
	t.Helper()
	if len(path) == 0 {
		return value
	}
	switch key := path[0].(type) {
	case string:
		var m map[string]json.RawMessage
		if e := json.Unmarshal(raw, &m); e != nil {
			t.Fatal(e)
		}
		if len(path) == 1 && remove {
			delete(m, key)
		} else {
			m[key] = patchJSON(t, m[key], path[1:], value, remove)
		}
		out, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		return out
	case float64:
		var a []json.RawMessage
		if e := json.Unmarshal(raw, &a); e != nil {
			t.Fatal(e)
		}
		a[int(key)] = patchJSON(t, a[int(key)], path[1:], value, remove)
		out, e := json.Marshal(a)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	t.Fatal("unsupported patch path")
	return nil
}
func TestRawDecoderRejectsAmbiguity(t *testing.T) {
	base := fixtures(t).Positive[0].Value
	for name, raw := range map[string][]byte{
		"duplicate_root":    append([]byte(`{"run_id":"duplicate",`), base[1:]...),
		"escaped_duplicate": append([]byte(`{"\u0072un_id":"duplicate",`), base[1:]...),
		"case_alias":        append([]byte(`{"Run_id":"duplicate",`), base[1:]...),
		"duplicate_nested":  bytes.Replace(base, []byte(`"database":`), []byte(`"database":"duplicate","database":`), 1),
		"multiple_values":   append(append([]byte{}, base...), []byte(` {}`)...),
		"lone_high":         bytes.Replace(base, []byte(`"provider-v1"`), []byte(`"\ud800"`), 1),
		"lone_low":          bytes.Replace(base, []byte(`"provider-v1"`), []byte(`"\udfff"`), 1),
		"invalid_utf8":      bytes.Replace(base, []byte(`"provider-v1"`), []byte{'"', 0xff, '"'}, 1),
		"numeric_json":      bytes.Replace(base, []byte(`"grant_generation": "1"`), []byte(`"grant_generation": 1`), 1),
		"depth":             []byte(strings.Repeat("[", 18) + "null" + strings.Repeat("]", 18)),
		"raw_size":          []byte(strings.Repeat(" ", MaxJSONBytes) + "{}"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeResult(raw); e == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
	good := bytes.Replace(base, []byte(`"provider-v1"`), []byte(`"\ud83d\ude00"`), 1)
	if _, e := DecodeResult(good); e != nil {
		t.Fatal("valid surrogate pair", e)
	}
	if _, e := CanonicalJSON([]byte(`"\\ud800"`)); e != nil {
		t.Fatal("literal backslash u is not surrogate", e)
	}
}
func TestFailureDoesNotMutateOutput(t *testing.T) {
	f := fixtures(t)
	for _, v := range append(append([]wireFixture{}, f.Records...), f.Positive[:1]...) {
		t.Run(v.Definition, func(t *testing.T) {
			out := destination(v.Definition)
			if e := DecodeRecord(v.Value, out); e != nil {
				t.Fatal(e)
			}
			before, _ := json.Marshal(out)
			var m map[string]json.RawMessage
			json.Unmarshal(v.Value, &m)
			for key := range m {
				raw := patchJSON(t, v.Value, []any{key}, nil, true)
				if DecodeRecord(raw, out) == nil {
					t.Fatal("missing field accepted", key)
				}
				after, _ := json.Marshal(out)
				if !bytes.Equal(before, after) {
					t.Fatal("partial destination mutation", key)
				}
			}
		})
	}
	var nilResult *ResultRequest
	if DecodeRecord([]byte(`{}`), nilResult) == nil {
		t.Fatal("nil destination")
	}
	var unknown struct{}
	if DecodeRecord([]byte(`{}`), &unknown) == nil {
		t.Fatal("unknown destination")
	}
}
func TestGoldenFraming(t *testing.T) {
	for raw, want := range map[string]string{`null`: "6e", `false`: "66", `true`: "74", `""`: "730000000000000000", `[]`: "610000000000000000", `{}`: "6f0000000000000000", `{"a":null}`: "6f0000000000000001730000000000000001616e", `"中"`: "730000000000000003e4b8ad"} {
		got, e := CanonicalJSON([]byte(raw))
		if e != nil || hex.EncodeToString(got) != want {
			t.Fatal(raw, e, hex.EncodeToString(got))
		}
	}
	for _, v := range fixtures(t).Encoding {
		tree, e := parseJSON(v.Value)
		if e != nil {
			t.Fatal(e)
		}
		got, e := canonicalTree(tree)
		if e != nil || hex.EncodeToString(got) != v.Hex {
			t.Fatal(v.ID, e)
		}
		h, e := hashTree(v.Domain, tree)
		if e != nil || string(h) != v.SHA256 {
			t.Fatal(v.ID, e, "hash mismatch")
		}
	}
}
func TestCounterAndTimeConversions(t *testing.T) {
	for _, s := range []string{"", "00", "01", "-1", "+1", "1.0", "18446744073709551616"} {
		if _, e := Counter(s).Uint64(); e == nil {
			t.Fatal("counter accepted", s)
		}
	}
	if v, e := Counter("18446744073709551615").Uint64(); e != nil || v != ^uint64(0) {
		t.Fatal(v, e)
	}
	if _, e := Counter("9223372036854775808").SQLInt64(); e == nil {
		t.Fatal("signed overflow")
	}
	if n, e := Counter("9223372036854775807").SQLInt64(); e != nil || n != 1<<63-1 {
		t.Fatal(n, e)
	}
	for _, s := range []string{"2026-02-30T01:00:00.000001Z", "2026-09-30T01:00:60.000001Z", "2026-09-30T01:00:00.000Z", "0999-09-30T01:00:00.000001Z", "2026-09-30T01:00:00.000001+00:00"} {
		if _, e := Timestamp(s).Time(); e == nil {
			t.Fatal("time accepted", s)
		}
	}
	r, e := DecodeResult(fixtures(t).Positive[0].Value)
	if e != nil {
		t.Fatal(e)
	}
	r.Target.RefVersion = ProviderVersion(string([]byte{0xff}))
	if _, e = ResultHashes(r); e == nil {
		t.Fatal("typed invalid UTF-8")
	}
}
func TestC1GoFieldParity(t *testing.T) {
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/producer-authority.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var schema struct {
		Defs map[string]struct {
			Required   []string
			Properties map[string]json.RawMessage
		} `json:"$defs"`
	}
	if e = json.Unmarshal(raw, &schema); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"ResultRequest", "CommandRequest", "DomainRecord", "GrantRecord", "RunRecord", "TargetRecord", "HistoricalBindingRecord", "ReceiptRecord", "CommandReceiptRecord", "ReferenceRecord"} {
		typ := reflect.TypeOf(destination(name)).Elem()
		def := schema.Defs[name]
		if typ.NumField() != len(def.Required) {
			t.Fatal(name, "field count")
		}
		for i := 0; i < typ.NumField(); i++ {
			key := typ.Field(i).Tag.Get("json")
			if _, ok := def.Properties[key]; !ok {
				t.Fatal(name, "unexpected", key)
			}
		}
	}
}
