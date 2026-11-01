package systembackupcapturedescription

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// DATA only: the tiny JSON packets deliberately do not claim authentic worker
// semantics, source/SQL provenance, AEAD, key authorization or a signature.
func descriptionFixture(t *testing.T) Description {
	t.Helper()
	limit, err := Budget(1)
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Part: "business_sql", Operation: "capture-database", PartIndex: 3}
	inv := func(s Selection) Invocation {
		raw := []byte("{\"z\": 1, \"a\":2}")
		return Invocation{s, raw, SHA256(raw)}
	}
	candidate := []byte("{\"candidate\": {\"bytes\":0}, \"Authority\":{}}")
	source := []byte("{\"source\": 1}")
	return Description{Version: Version, Scope: Scope{InstallationID: "installation", TaskPublicID: "task", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), AttemptNo: 1, CaptureContextSHA256: strings.Repeat("b", 64)}, Seed: Seed{SeedVersion, []Selection{selection}, limit}, SourceInventoryJSON: source, SourceInventorySHA256: SHA256(source), Members: []Member{{Invocation: inv(selection), CandidateJSON: candidate, CandidateSHA256: SHA256(candidate), ResultSHA256: strings.Repeat("c", 64)}}, AdministrativeInvocations: []Invocation{inv(Selection{Part: Part, Operation: Operation, PartIndex: 0}), inv(Selection{Part: ControlPart, Operation: ControlOperation, PartIndex: 1}), inv(Selection{Part: ProofPart, Operation: ControlOperation, PartIndex: 2})}}
}

func TestDescriptionPreservesExactOriginalByteHashBoundaries(t *testing.T) {
	d := descriptionFixture(t)
	raw, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, d.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.SourceInventoryJSON, d.SourceInventoryJSON) || !bytes.Equal(decoded.Members[0].JSON, d.Members[0].JSON) || !bytes.Equal(decoded.Members[0].CandidateJSON, d.Members[0].CandidateJSON) {
		t.Fatal("original bytes reserialized")
	}
	var wrapper struct{ Candidate json.RawMessage }
	if json.Unmarshal(decoded.Members[0].CandidateJSON, &wrapper) != nil || SHA256(wrapper.Candidate) == decoded.Members[0].CandidateSHA256 {
		t.Fatal("candidate wrapper/inner digest conflated")
	}
	for _, v := range decoded.AdministrativeInvocations {
		if len(v.JSON) == 0 {
			t.Fatal("missing frozen administrative invocation")
		}
	}
	decoded.Clear()
	if bytes.Count(decoded.Members[0].CandidateJSON, []byte{0}) != len(decoded.Members[0].CandidateJSON) {
		t.Fatal("candidate buffer retained")
	}
}

func TestDescriptionRefusesMalformedAndSelfReferentialSets(t *testing.T) {
	cases := map[string]func(*Description){
		"wrong wrapper digest":    func(d *Description) { d.Members[0].CandidateSHA256 = SHA256([]byte(`{"bytes":0}`)) },
		"wrong invocation digest": func(d *Description) { d.Members[0].JSON = []byte(`{"a":2,"z":1}`) },
		"duplicate original property": func(d *Description) {
			raw := []byte(`{"x":1,"x":2}`)
			d.Members[0].JSON = raw
			d.Members[0].SHA256 = SHA256(raw)
		},
		"source digest":               func(d *Description) { d.SourceInventorySHA256 = strings.Repeat("d", 64) },
		"carrier in business set":     func(d *Description) { d.Seed.Members[0].Part = Part; d.Members[0].Part = Part },
		"control in business set":     func(d *Description) { d.Seed.Members[0].Part = ControlPart; d.Members[0].Part = ControlPart },
		"carrier operation disguised": func(d *Description) { d.Seed.Members[0].Operation = Operation; d.Members[0].Operation = Operation },
		"missing business":            func(d *Description) { d.Members = []Member{} },
		"duplicate index":             func(d *Description) { d.AdministrativeInvocations[0].PartIndex = 3 },
		"missing admin":               func(d *Description) { d.AdministrativeInvocations = d.AdministrativeInvocations[:2] },
		"wrong admin operation":       func(d *Description) { d.AdministrativeInvocations[0].Operation = "capture-secret-bundle" },
		"non-original budget":         func(d *Description) { d.Seed.MaxPlaintextBytes++ },
		"wrapper too large": func(d *Description) {
			raw := []byte(`{"x":"` + strings.Repeat("x", MaxCandidateBytes) + `"}`)
			d.Members[0].CandidateJSON = raw
			d.Members[0].CandidateSHA256 = SHA256(raw)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := descriptionFixture(t)
			mutate(&d)
			if _, err := Encode(d); err == nil {
				t.Fatal("invalid description accepted")
			}
		})
	}
}

func TestDescriptionClosedCanonicalTransport(t *testing.T) {
	d := descriptionFixture(t)
	raw, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), []byte(`{}`)...), append([]byte(`{"unknown":true,`), raw[1:]...), bytes.Replace(raw, []byte(`"schema_version":`), []byte(`"schema_version_alias":`), 1)} {
		if _, err := Decode(bad, d.Seed); err == nil {
			t.Fatal("nonclosed/noncanonical transport accepted")
		}
	}
	expected := d.Seed
	expected.Members = append([]Selection{}, expected.Members...)
	expected.Members[0].Part = "different_original_part"
	if _, err := Decode(raw, expected); err == nil {
		t.Fatal("caller seed replaced")
	}
}

func TestDescriptionBudgetIncludesFullBoundedWrapperCollection(t *testing.T) {
	for _, count := range []int{1, 8, 1000, MaxMembers} {
		budget, err := Budget(count)
		raw := int64(MaxOriginalPlanBytes) + int64(count)*MaxCandidateBytes
		if err != nil || budget < 4*((raw+2)/3)+int64(count)*1024 {
			t.Fatal("underbudget", count, budget, err)
		}
	}
	for _, count := range []int{-1, 0, 10000, int(^uint(0) >> 1)} {
		if _, err := Budget(count); err == nil {
			t.Fatal("unbounded count", count)
		}
	}
}
