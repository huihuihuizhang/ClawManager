package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func bootstrapFixture(t *testing.T) []byte {
	t.Helper()
	v := map[string]any{"enabled": false, "alert_profile": "development", "minimum_recovery_points": 1}
	for group, rules := range bootstrapNumberRules {
		members := map[string]any{}
		for name, rule := range rules {
			members[name] = json.Number(bootstrapDecimal(rule.Default, rule.Scale))
		}
		v[group] = members
	}
	registries := []BootstrapRegistryRef{}
	for _, kind := range bootstrapRegistryKinds {
		registries = append(registries, BootstrapRegistryRef{kind, "synthetic-v1", strings.Repeat("a", 64)})
	}
	refs := []BootstrapSecretRef{}
	for _, purpose := range bootstrapReferencePurposes {
		identity := strings.Repeat("b", 64)
		switch purpose {
		case "capture_signing":
			identity = strings.Repeat("c", 64)
		case "acceptance_signing":
			identity = strings.Repeat("d", 64)
		case "catalog_signing":
			identity = strings.Repeat("e", 64)
		}
		refs = append(refs, BootstrapSecretRef{purpose, identity, "synthetic-v1"})
	}
	v["registries"] = registries
	v["references"] = refs
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBootstrapRejectsSharedSigningReferenceIdentity(t *testing.T) {
	for _, pair := range [][2]string{{"capture_signing", "acceptance_signing"}, {"acceptance_signing", "catalog_signing"}, {"catalog_signing", "nonce_hmac"}} {
		t.Run(pair[0]+"-"+pair[1], func(t *testing.T) {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(bootstrapFixture(t), &doc); err != nil {
				t.Fatal(err)
			}
			var refs []BootstrapSecretRef
			if err := json.Unmarshal(doc["references"], &refs); err != nil {
				t.Fatal(err)
			}
			var identity string
			for _, ref := range refs {
				if ref.Purpose == pair[0] {
					identity = ref.IdentityHash
				}
			}
			for i := range refs {
				if refs[i].Purpose == pair[1] {
					refs[i].IdentityHash = identity
				}
			}
			doc["references"], _ = json.Marshal(refs)
			raw, _ := json.Marshal(doc)
			if _, err := DecodeBootstrapConfig(raw); err != ErrBootstrapConfig {
				t.Fatal("shared signing identity accepted", err)
			}
		})
	}
}
func TestBootstrapRulesMatchContract(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-resources.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if registrationHash(string(raw)) != bootstrapConfigSchemaSHA256 {
		t.Fatal("ConfigValues source changed: regenerate and review bootstrap rules")
	}
	var schema struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	type numberGroup struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Min     float64 `json:"minimum"`
			Max     float64 `json:"maximum"`
			Default float64 `json:"default"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &schema) != nil {
		t.Fatal("schema decode")
	}
	for group, def := range map[string]string{"durations": "DurationConfig", "capacity": "CapacityConfig", "concurrency": "ConcurrencyConfig", "preflight_limits": "PreflightLimits"} {
		var d numberGroup
		if json.Unmarshal(schema.Defs[def], &d) != nil {
			t.Fatal(group, "numeric schema decode")
		}
		rules := bootstrapNumberRules[group]
		if len(d.Required) != len(rules) || len(d.Properties) != len(rules) {
			t.Fatal(group, "field drift")
		}
		for name, r := range rules {
			p, ok := d.Properties[name]
			if !ok || !contains(d.Required, name) || float64(r.Min) != p.Min*float64(r.Scale) || float64(r.Max) != p.Max*float64(r.Scale) || float64(r.Default) != p.Default*float64(r.Scale) {
				t.Fatal(name, "bounds drift")
			}
		}
	}
}
func TestBootstrapCanonicalAndSQLSnapshot(t *testing.T) {
	raw := bootstrapFixture(t)
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	json.Indent(&pretty, raw, "", "  ")
	other, err := DecodeBootstrapConfig(pretty.Bytes())
	if err != nil || c.SHA256() != other.SHA256() {
		t.Fatal("whitespace changed identity", err)
	}
	exponent := bytes.Replace(raw, []byte(`"source_size_safety_factor":1.25`), []byte(`"source_size_safety_factor":125e-2`), 1)
	other, err = DecodeBootstrapConfig(exponent)
	if err != nil || c.SHA256() != other.SHA256() {
		t.Fatal("equivalent number changed identity", err)
	}
	copy := c.CanonicalJSON()
	copy[0] = 'x'
	if c.CanonicalJSON()[0] != '{' {
		t.Fatal("mutable config")
	}
	columns, args := c.sqlValues("installation_synthetic", "42", "test")
	if len(columns) != 132 || len(args) != len(columns) {
		t.Fatal("incomplete SQL snapshot", len(columns), len(args))
	}
	seen := map[string]bool{}
	for i, col := range columns {
		if seen[col] {
			t.Fatal("duplicate column", col)
		}
		seen[col] = true
		if col == "source_size_safety_factor" && args[i] != "1.25" {
			t.Fatal("decimal rounded")
		}
	}
	keys := make([]string, 0, len(c.numbers))
	for k := range c.numbers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(columns[9:9+len(keys)], keys) {
		t.Fatal("unstable SQL ordering")
	}
}
func TestBootstrapRejectsIncompleteAmbiguousAndUnsafeConfig(t *testing.T) {
	raw := string(bootstrapFixture(t))
	cases := map[string]string{
		"enabled":             strings.Replace(raw, `"enabled":false`, `"enabled":true`, 1),
		"alias":               strings.Replace(raw, `"enabled":false`, `"Enabled":false`, 1),
		"duplicate":           strings.Replace(raw, `"enabled":false`, `"enabled":false,"enabled":false`, 1),
		"missing":             strings.Replace(raw, `"enabled":false,`, "", 1),
		"null":                strings.Replace(raw, `"enabled":false`, `"enabled":null`, 1),
		"numeric-string":      strings.Replace(raw, `"controller_claim_ttl_seconds":30`, `"controller_claim_ttl_seconds":"30"`, 1),
		"numeric-null":        strings.Replace(raw, `"controller_claim_ttl_seconds":30`, `"controller_claim_ttl_seconds":null`, 1),
		"numeric-case":        strings.Replace(raw, `"controller_claim_ttl_seconds":30`, `"Controller_claim_ttl_seconds":30`, 1),
		"rounding":            strings.Replace(raw, `"source_size_safety_factor":1.25`, `"source_size_safety_factor":1.251`, 1),
		"huge-exponent":       strings.Replace(raw, `"redis_clock_skew_seconds":5`, `"redis_clock_skew_seconds":0e999999999`, 1),
		"heartbeat":           strings.Replace(raw, `"controller_claim_heartbeat_seconds":10`, `"controller_claim_heartbeat_seconds":11`, 1),
		"lock-ttl":            strings.Replace(raw, `"maintenance_lock_ttl_seconds":900`, `"maintenance_lock_ttl_seconds":65`, 1),
		"retention":           strings.Replace(raw, `"evidence_retention_seconds":2592000`, `"evidence_retention_seconds":86400`, 1),
		"staging":             strings.Replace(raw, `"staging_capacity_bytes":21474836480`, `"staging_capacity_bytes":1073741824`, 1),
		"certificate":         strings.Replace(raw, `"capture_certificate_ttl_seconds":28800`, `"capture_certificate_ttl_seconds":21600`, 1),
		"registry-duplicate":  strings.Replace(raw, `"registry_kind":"parts"`, `"registry_kind":"rbac_bindings"`, 1),
		"reference-duplicate": strings.Replace(raw, `"purpose":"artifact_write"`, `"purpose":"artifact_read"`, 1),
		"version-path":        strings.Replace(raw, `"version":"synthetic-v1"`, `"version":"../test"`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if body == raw {
				t.Fatal("test mutation absent")
			}
			if _, err := DecodeBootstrapConfig([]byte(body)); err != ErrBootstrapConfig {
				t.Fatal("unsafe config accepted", err)
			}
		})
	}
	var v map[string]json.RawMessage
	json.Unmarshal([]byte(raw), &v)
	var refs []BootstrapRegistryRef
	json.Unmarshal(v["registries"], &refs)
	v["registries"], _ = json.Marshal(refs[:3])
	incomplete, _ := json.Marshal(v)
	if _, err := DecodeBootstrapConfig(incomplete); err == nil {
		t.Fatal("3/9 registries admitted")
	}
}
