package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func maintenanceDigestVectors(t *testing.T) []struct {
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Canonical string          `json:"canonical_utf8"`
	Hash      string          `json:"sha256"`
} {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/evidence/a-config-canonical-maintenance-digest-vectors-20261015.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			Canonical string          `json:"canonical_utf8"`
			Hash      string          `json:"sha256"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &fixture) != nil || len(fixture.Vectors) != 6 {
		t.Fatal("missing accepted synthetic vectors")
	}
	return fixture.Vectors
}

func TestConfigMaintenanceDigestAcceptedVectorParity(t *testing.T) {
	for _, v := range maintenanceDigestVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			var input map[string]string
			var digest string
			var err error
			if strings.HasPrefix(v.Name, "actor") {
				if json.Unmarshal(v.Input, &input) != nil {
					t.Fatal("actor vector")
				}
				digest, err = ConfigMaintenanceActorSHA256(input["issuer"], input["subject"])
			} else if v.Name == "grant" {
				if json.Unmarshal(v.Input, &input) != nil {
					t.Fatal("grant vector")
				}
				digest, err = ConfigMaintenanceGrantIdentitySHA256(input["issuer"], input["grant_id"])
			} else {
				var canonical []byte
				canonical, digest, err = CanonicalConfigMaintenanceRequest(v.Input)
				if string(canonical) != v.Canonical {
					t.Fatal("JCS bytes differ from accepted profile")
				}
			}
			if err != nil || digest != v.Hash || registrationHash(v.Canonical) != digest {
				t.Fatal("accepted digest parity", err, digest)
			}
		})
	}
}

func TestConfigMaintenanceDigestRejectsAmbiguousRequest(t *testing.T) {
	base := maintenanceDigestVectors(t)[3].Input
	for _, name := range []string{"unknown", "missing", "null", "actor-case", "database-path", "server-case", "grant-version", "fractional", "unsafe-integer", "too-small", "too-large", "blank-reason", "long-reason", "duplicate", "escaped-duplicate", "surrogate", "bad-utf8", "trailing", "idempotency-key"} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]json.RawMessage
			if json.Unmarshal(base, &doc) != nil {
				t.Fatal("base request")
			}
			switch name {
			case "unknown":
				doc["proof"] = json.RawMessage(`"not-a-grant"`)
			case "missing":
				delete(doc, "expected_row_sha256")
			case "null":
				doc["reason"] = json.RawMessage(`null`)
			case "actor-case":
				doc["maintenance_actor_sha256"] = json.RawMessage(`"` + strings.Repeat("A", 64) + `"`)
			case "database-path":
				doc["target_database"] = json.RawMessage(`"../synthetic"`)
			case "server-case":
				doc["target_server_uuid"] = json.RawMessage(`"12345678-1234-1234-1234-123456789ABC"`)
			case "grant-version":
				doc["grant_version"] = json.RawMessage(`"version/2"`)
			case "fractional":
				doc["config_version"] = json.RawMessage(`1.5`)
			case "unsafe-integer":
				doc["config_version"] = json.RawMessage(`9007199254740992`)
			case "too-small":
				doc["original_config_size_bytes"] = json.RawMessage(`1`)
			case "too-large":
				doc["original_config_size_bytes"] = json.RawMessage(`262145`)
			case "blank-reason":
				doc["reason"] = json.RawMessage(`" \t "`)
			case "long-reason":
				doc["reason"], _ = json.Marshal(strings.Repeat("测", 171))
			case "idempotency-key":
				doc["idempotency_key"] = json.RawMessage(`"synthetic_key_0123456789"`)
			}
			raw, _ := json.Marshal(doc)
			switch name {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"reason":`), []byte(`"reason":"other","reason":`), 1)
			case "escaped-duplicate":
				raw = bytes.Replace(raw, []byte(`"reason":`), []byte(`"\u0072eason":"other","reason":`), 1)
			case "surrogate":
				raw = bytes.Replace(raw, doc["reason"], []byte(`"\ud800"`), 1)
			case "bad-utf8":
				raw = append(raw, 0xff)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			}
			if canonical, digest, err := CanonicalConfigMaintenanceRequest(raw); err != ErrConfigMutation || len(canonical) != 0 || digest != "" {
				t.Fatal("ambiguous request hashed", err)
			}
		})
	}
}

func TestConfigMaintenanceIdentityExactnessAndBudgets(t *testing.T) {
	for _, pair := range [][2]string{{"", "subject"}, {"issuer", " "}, {strings.Repeat("i", 2049), "subject"}, {"issuer", strings.Repeat("测", 86)}, {"issuer", string([]byte{0xff})}} {
		if _, err := ConfigMaintenanceActorSHA256(pair[0], pair[1]); err != ErrConfigMutation {
			t.Fatal("invalid actor hashed")
		}
	}
	for _, grant := range []string{"", "grant/id", strings.Repeat("g", 129), "授权"} {
		if _, err := ConfigMaintenanceGrantIdentitySHA256("issuer", grant); err != ErrConfigMutation {
			t.Fatal("invalid grant identity hashed")
		}
	}
	a, err := ConfigMaintenanceActorSHA256("issuer", "operator:测试")
	b, e := ConfigMaintenanceActorSHA256("issuer", "operator:测试 ")
	if err != nil || e != nil || a == b {
		t.Fatal("stable identity was silently trimmed")
	}
	if _, err := ConfigMaintenanceActorSHA256(strings.Repeat("i", 2048), strings.Repeat("s", 256)); err != nil {
		t.Fatal("valid maximum identity rejected", err)
	}
	if _, err := ConfigMaintenanceGrantIdentitySHA256("issuer", strings.Repeat("g", 128)); err != nil {
		t.Fatal("valid grant identity boundary", err)
	}
}
