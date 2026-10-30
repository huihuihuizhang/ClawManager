package systembackupkekcandidate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mapping(t *testing.T) UnadmittedMapping {
	t.Helper()
	v, e := DecodeMapping(fixture(t, "mapping"))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func retained(t *testing.T) UnadmittedRetained {
	t.Helper()
	v, e := DecodeRetained(fixture(t, "retained"))
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestIndependentJSGoldenAndDetachedOutputs(t *testing.T) {
	m := mapping(t)
	r := retained(t)
	// Checked-in files are canonical bytes generated independently in JS.
	if !bytes.Equal(m.CanonicalJSON(), fixture(t, "mapping")) || !bytes.Equal(r.CanonicalJSON(), fixture(t, "retained")) {
		t.Fatal("JCS mismatch")
	}
	x := m.Input()
	x.KeyBinding.ProviderVersion = "99"
	if m.Input().KeyBinding.ProviderVersion == "99" {
		t.Fatal("aliased mapping")
	}
	b := m.CanonicalJSON()
	b[0] = 'x'
	if m.CanonicalJSON()[0] != '{' {
		t.Fatal("aliased bytes")
	}
	y := r.Input()
	y.References[0].EnvelopeID = "changed"
	if r.Input().References[0].EnvelopeID == "changed" {
		t.Fatal("aliased retained")
	}
	input := fixture(t, "mapping")
	candidate, e := DecodeMapping(input)
	if e != nil {
		t.Fatal(e)
	}
	clear(input)
	if !bytes.Equal(candidate.CanonicalJSON(), m.CanonicalJSON()) {
		t.Fatal("borrowed caller bytes")
	}
}

func TestMappingSemanticsAndNonAuthorizingObservation(t *testing.T) {
	m := mapping(t)
	original := m.Input()
	if e := m.MatchObservation(original.InstallationID, original.ConfigSHA256, original.SourceRevision); e != nil {
		t.Fatal(e)
	}
	for _, p := range [][3]string{{"other", original.ConfigSHA256, original.SourceRevision}, {original.InstallationID, strings.Repeat("f", 64), original.SourceRevision}, {original.InstallationID, original.ConfigSHA256, "other"}} {
		if m.MatchObservation(p[0], p[1], p[2]) == nil {
			t.Fatal("matched wrong observation")
		}
	}
	for name, mutate := range map[string]func(*MappingInput){
		"wrong-purpose":                 func(v *MappingInput) { v.GenerateRef.Purpose = "kek_unwrap" },
		"wrong-capability":              func(v *MappingInput) { v.UnwrapRef.Capability = "generate_data_key" },
		"wrong-kind":                    func(v *MappingInput) { v.GenerateRef.Kind = "external_secret" },
		"wrong-provider-identity":       func(v *MappingInput) { v.UnwrapRef.ProviderIdentityHash = strings.Repeat("e", 64) },
		"wrong-scope":                   func(v *MappingInput) { v.GenerateRef.ScopeHash = strings.Repeat("e", 64) },
		"wrong-pin":                     func(v *MappingInput) { v.ConfigRef.IdentityHash = strings.Repeat("e", 64) },
		"wrong-pin-version":             func(v *MappingInput) { v.ConfigRef.Version = "other" },
		"latest":                        func(v *MappingInput) { v.KeyBinding.RegistryVersion = "latest"; v.ConfigRef.Version = "latest" },
		"provider-version-prefix":       func(v *MappingInput) { v.KeyBinding.ProviderVersion = "v3" },
		"provider-version-zero":         func(v *MappingInput) { v.KeyBinding.ProviderVersion = "0" },
		"provider-version-leading-zero": func(v *MappingInput) { v.KeyBinding.ProviderVersion = "03" },
		"wrong-schema":                  func(v *MappingInput) { v.SchemaVersion = "other" },
		"http":                          func(v *MappingInput) { v.Provider.Endpoint = "http://example.invalid" },
		"provider-missing-hostname":     func(v *MappingInput) { v.Provider.Endpoint = "https://:8200" },
		"provider-path":                 func(v *MappingInput) { v.Provider.Endpoint = "https://example.invalid/other" },
		"provider-empty-query":          func(v *MappingInput) { v.Provider.Endpoint = "https://example.invalid?" },
		"provider-empty-fragment":       func(v *MappingInput) { v.Provider.Endpoint = "https://example.invalid#" },
		"key-path":                      func(v *MappingInput) { v.Provider.KeyName = "../key" },
		"missing-ca-source":             func(v *MappingInput) { v.Provider.CASource = SourceRecord{} },
		"oversize-text":                 func(v *MappingInput) { v.InstallationID = strings.Repeat("中", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			v := original
			mutate(&v)
			if _, e := DecodeMapping(encoded(t, v)); e == nil {
				t.Fatal("accepted invalid candidate")
			}
		})
	}
	// The two operation refs deliberately have DIFFERENT original identities.
	if original.GenerateRef.IdentityHash == original.UnwrapRef.IdentityHash {
		t.Fatal("bad fixture")
	}
	if _, e := DecodeMapping(encoded(t, original)); e != nil {
		t.Fatal(e)
	}
}

func TestSameKeyRebindingVersusObservationChanges(t *testing.T) {
	m := mapping(t)
	v := m.Input()
	v.ConfigSHA256 = strings.Repeat("e", 64)
	v.SourceRevision = "source-r18"
	v.GenerateRef.Description = "updated redacted description"
	other, e := DecodeMapping(encoded(t, v))
	if e != nil || CheckSameKeyMapping(m, other) != nil {
		t.Fatal("config observation prevented key reuse", e)
	}
	for name, mutate := range map[string]func(*MappingInput){
		"key-id":            func(v *MappingInput) { v.KeyBinding.ProviderKeyID = "other-key" },
		"provider-version":  func(v *MappingInput) { v.KeyBinding.ProviderVersion = "4" },
		"endpoint":          func(v *MappingInput) { v.Provider.Endpoint = "https://other.invalid" },
		"provider-key-name": func(v *MappingInput) { v.Provider.KeyName = "other" },
		"ca":                func(v *MappingInput) { v.Provider.CAPEMSHA256 = strings.Repeat("f", 64) },
		"ca-record":         func(v *MappingInput) { v.Provider.CASource.RecordVersion = "next" },
		"generate-ref":      func(v *MappingInput) { v.GenerateRef.Version = "next" },
		"unwrap-ref":        func(v *MappingInput) { v.UnwrapRef.Version = "next" },
	} {
		t.Run(name, func(t *testing.T) {
			v := m.Input()
			mutate(&v)
			other, e := DecodeMapping(encoded(t, v))
			if e != nil {
				t.Fatal(e)
			}
			if !errors.Is(CheckSameKeyMapping(m, other), ErrRebinding) {
				t.Fatal("rebound immutable mapping")
			}
		})
	}
	v = m.Input()
	v.InstallationID = "other"
	other, e = DecodeMapping(encoded(t, v))
	if e != nil || !errors.Is(CheckSameKeyMapping(m, other), ErrMismatch) {
		t.Fatal("cross installation")
	}
	if CheckSameKeyMapping(UnadmittedMapping{}, m) == nil {
		t.Fatal("zero candidate")
	}
}

func TestRetainedRejectsChangedSetAndClaims(t *testing.T) {
	r := retained(t)
	for name, mutate := range map[string]func(*RetainedInput){
		"reorder":         func(v *RetainedInput) { v.References[0], v.References[1] = v.References[1], v.References[0] },
		"duplicate":       func(v *RetainedInput) { v.References = append(v.References, v.References[0]) },
		"drop-reference":  func(v *RetainedInput) { v.References = v.References[1:] },
		"wrong-binding":   func(v *RetainedInput) { v.References[0].KeyBinding.ProviderVersion = "4" },
		"binding-hash":    func(v *RetainedInput) { v.References[0].BindingSHA256 = strings.Repeat("d", 64) },
		"collection-hash": func(v *RetainedInput) { v.ReferencesSHA256 = strings.Repeat("d", 64) },
		"partition-count": func(v *RetainedInput) { v.Coverage.RetainedArtifacts.RecordCount++ },
		"partition-hash":  func(v *RetainedInput) { v.Coverage.RetainedArtifacts.RecordSetSHA256 = strings.Repeat("d", 64) },
		"partition-name":  func(v *RetainedInput) { v.References[0].Partition = "only_succeeded" },
		"empty-fence":     func(v *RetainedInput) { v.Coverage.RetainedArtifacts.FenceRevision = "" },
		"unknown-version": func(v *RetainedInput) { v.SchemaVersion = "next" },
		"mapping-source":  func(v *RetainedInput) { v.References[0].MappingSource.RecordVersion = "latest" },
		"missing-request": func(v *RetainedInput) { v.References[0].ExpectedRequestSource = SourceRecord{} },
		"invalid-attempt": func(v *RetainedInput) { v.References[0].AttemptNo = "01" },
		"invalid-time":    func(v *RetainedInput) { v.ObservedAt = "now" },
		"reversed-time":   func(v *RetainedInput) { v.ValidUntil = v.ObservedAt },
	} {
		t.Run(name, func(t *testing.T) {
			v := r.Input()
			mutate(&v)
			if _, e := DecodeRetained(encoded(t, v)); e == nil {
				t.Fatal("accepted changed set")
			}
		})
	}
	v := r.Input()
	now, _ := time.Parse(time.RFC3339Nano, v.ObservedAt)
	if r.MatchObservation(v.InstallationID, v.ConfigSHA256, v.SourceRevision, now) != nil {
		t.Fatal("valid observation")
	}
	expiry, _ := time.Parse(time.RFC3339Nano, v.ValidUntil)
	for _, clock := range []time.Time{time.Time{}, now.Add(-time.Nanosecond), expiry, expiry.Add(time.Hour)} {
		if r.MatchObservation(v.InstallationID, v.ConfigSHA256, v.SourceRevision, clock) == nil {
			t.Fatal("invalid clock")
		}
	}
	if r.MatchObservation("other", v.ConfigSHA256, v.SourceRevision, now) == nil || r.MatchObservation(v.InstallationID, "other", v.SourceRevision, now) == nil || r.MatchObservation(v.InstallationID, v.ConfigSHA256, "other", now) == nil {
		t.Fatal("wrong expected pins")
	}
	if (UnadmittedRetained{}).MatchObservation(v.InstallationID, v.ConfigSHA256, v.SourceRevision, now) == nil {
		t.Fatal("zero candidate")
	}
	// Null/missing history is not a known-empty candidate. Empty is structural
	// only and exposes no Complete/Authorize/Config method or retirement result.
	if _, e := DecodeRetained(fixture(t, "retained-empty")); e != nil {
		t.Fatal(e)
	}
}

// Every required field, including zero counts and nested source pointers, must
// be present and non-null; every object is closed. No reliance on Go zero values.
func TestRecursiveClosedRequiredFields(t *testing.T) {
	for _, name := range []string{"mapping", "retained"} {
		var root map[string]any
		if e := json.Unmarshal(fixture(t, name), &root); e != nil {
			t.Fatal(e)
		}
		var visit func(any, []any)
		visit = func(v any, path []any) {
			switch x := v.(type) {
			case map[string]any:
				for key, child := range x {
					for _, mode := range []string{"missing", "null"} {
						t.Run(name+"/"+pathName(path)+"/"+key+"/"+mode, func(t *testing.T) {
							var copy map[string]any
							_ = json.Unmarshal(fixture(t, name), &copy)
							dst := at(copy, path).(map[string]any)
							if mode == "missing" {
								delete(dst, key)
							} else {
								dst[key] = nil
							}
							reject(t, name, encoded(t, copy))
						})
					}
					visit(child, append(append([]any{}, path...), key))
				}
				t.Run(name+"/"+pathName(path)+"/extra", func(t *testing.T) {
					var copy map[string]any
					_ = json.Unmarshal(fixture(t, name), &copy)
					at(copy, path).(map[string]any)["complete"] = true
					reject(t, name, encoded(t, copy))
				})
			case []any:
				if len(x) > 0 {
					visit(x[0], append(append([]any{}, path...), 0))
				}
			}
		}
		visit(root, nil)
	}
}
func at(root any, path []any) any {
	for _, key := range path {
		switch k := key.(type) {
		case string:
			root = root.(map[string]any)[k]
		case int:
			root = root.([]any)[k]
		}
	}
	return root
}
func pathName(path []any) string { b, _ := json.Marshal(path); return string(b) }
func reject(t *testing.T, name string, b []byte) {
	t.Helper()
	var e error
	if name == "mapping" {
		_, e = DecodeMapping(b)
	} else {
		_, e = DecodeRetained(b)
	}
	if e == nil {
		t.Fatal("accepted malformed input")
	}
}

func TestMalformedJSONAndNumericBounds(t *testing.T) {
	m := fixture(t, "mapping")
	for name, raw := range map[string][]byte{
		"duplicate-root":   bytes.Replace(m, []byte(`"schema_version":`), []byte(`"schema_version":"duplicate","schema_version":`), 1),
		"duplicate-nested": bytes.Replace(m, []byte(`"provider_version":`), []byte(`"provider_version":"3","provider_version":`), 1),
		"surrogate":        bytes.Replace(m, []byte(`installation_synthetic`), []byte(`\ud800`), 1),
		"bad-utf8":         append([]byte{0xff}, m...), "trailing": append(bytes.Clone(m), []byte(` {}`)...), "null": []byte(`null`),
		"oversize": bytes.Repeat([]byte(" "), MaxMappingBytes+1), "depth": []byte(strings.Repeat("[", 34) + strings.Repeat("]", 34)),
	} {
		t.Run(name, func(t *testing.T) { reject(t, "mapping", raw) })
	}
	r := fixture(t, "retained-empty")
	for _, n := range []string{`"0"`, `-1`, `0.5`, `9007199254740992`, `1e999999999`, `0e999999999`, `0.00000000000000000000000001`} {
		t.Run(n, func(t *testing.T) {
			reject(t, "retained", bytes.Replace(r, []byte(`"record_count":0`), []byte(`"record_count":`+n), 1))
		})
	}
	// A mathematically exact integer spelling is valid JSON Schema/JCS input.
	if _, e := DecodeRetained(bytes.Replace(r, []byte(`"record_count":0`), []byte(`"record_count":0e1`), 1)); e != nil {
		t.Fatal(e)
	}
}

func TestUTF16OrderNotUTF8Order(t *testing.T) {
	if !lessUTF16("😀", "\ue000") {
		t.Fatal("expected UTF16 ordering")
	}
	r := retained(t).Input()
	var astral, bmp int = -1, -1
	for i, v := range r.References {
		if v.SourceRecordID == "😀" {
			astral = i
		}
		if v.SourceRecordID == "\ue000" {
			bmp = i
		}
	}
	if astral < 0 || bmp < 0 || astral >= bmp {
		t.Fatal("golden not ordered by UTF16")
	}
	r.References[astral], r.References[bmp] = r.References[bmp], r.References[astral]
	rehash(t, &r)
	if _, e := DecodeRetained(encoded(t, r)); e == nil {
		t.Fatal("accepted UTF8 order")
	}
}

func rehash(t *testing.T, r *RetainedInput) {
	t.Helper()
	for i := range r.References {
		b, e := canonical(r.References[i].KeyBinding)
		if e != nil {
			t.Fatal(e)
		}
		r.References[i].BindingSHA256 = hash(b)
	}
	parts := partitions(r.Coverage)
	for name, p := range parts {
		set := []RetainedReference{}
		for _, ref := range r.References {
			if ref.Partition == name {
				set = append(set, ref)
			}
		}
		b, e := canonical(set)
		if e != nil {
			t.Fatal(e)
		}
		p.RecordCount = int64(len(set))
		p.RecordSetSHA256 = hash(b)
		parts[name] = p
	}
	r.Coverage = Coverage{parts["retained_artifacts"], parts["inflight_and_unknown_writes"], parts["holds_and_catalog"], parts["restore_and_prune"]}
	b, e := canonical(r.References)
	if e != nil {
		t.Fatal(e)
	}
	r.ReferencesSHA256 = hash(b)
}

func TestConsistentHashesCannotRepairRebindingOrProveCompleteness(t *testing.T) {
	r := retained(t).Input()
	r.References[0].KeyBinding.ProviderVersion = "4"
	rehash(t, &r)
	if _, e := DecodeRetained(encoded(t, r)); !errors.Is(e, ErrRebinding) {
		t.Fatal("accepted same identity/version with conflicting bindings", e)
	}
	r = retained(t).Input()
	r.References = append([]RetainedReference{r.References[0]}, r.References...)
	rehash(t, &r)
	if _, e := DecodeRetained(encoded(t, r)); e == nil {
		t.Fatal("accepted duplicate tuple with recomputed hashes")
	}
	r = retained(t).Input()
	r.References = r.References[1:]
	rehash(t, &r)
	// A self-consistent SUBSET can pass pure structural checks. Only D's real
	// complete-source/fence can reject its omission; no completeness is claimed.
	if _, e := DecodeRetained(encoded(t, r)); e != nil {
		t.Fatal("structural parser pretended to know external set", e)
	}
}
