package host

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/profile"
)

func TestDiagnosticsDoNotReadReferencesOrReflectSecrets(t *testing.T) {
	c := catalogConfigFixture()
	c.Catalogs[0].Provider.Endpoint = "https://canary-private.invalid"
	c.KeysFile = "/never-read/canary-private.json"
	raw, _ := json.Marshal(c)
	r := Diagnose(raw)
	if !r.StructureValid || r.RuntimeVerified || len(r.Findings) == 0 {
		t.Fatal(r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "canary-private") || strings.Contains(string(b), "never-read") {
		t.Fatal("diagnostic reflected configuration")
	}
}
func TestDiagnosticsCoverMissingPoliciesAndRejectAmbiguousJSON(t *testing.T) {
	c := catalogConfigFixture()
	c.Profiles = []Profile{{Config: profile.Config{Instances: []profile.Instance{{ID: 1, Policy: "private-unknown"}}}}}
	raw, _ := json.Marshal(c)
	r := Diagnose(raw)
	if r.StructureValid || len(r.Coverage) != 1 || r.Coverage[0].Covered != 0 || r.Coverage[0].Instances != 1 {
		t.Fatal(r)
	}
	found := false
	for _, f := range r.Findings {
		if f.Code == "runtime_policy_missing_or_invalid" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing policy not reported")
	}
	for _, b := range []string{`{"Owner":"one","Owner":"two"}`, `{"password":"canary"}`, `{}`} {
		r = Diagnose([]byte(b))
		if r.StructureValid {
			t.Fatal("invalid config passed", b)
		}
		raw, _ = json.Marshal(r)
		if strings.Contains(string(raw), "canary") {
			t.Fatal("leaked input")
		}
	}
}
