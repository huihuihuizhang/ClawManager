package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func mutationFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"expected_version": 3, "change_reason": nil, "config": json.RawMessage(bootstrapFixture(t))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestConfigMutationEnabledSnapshotAndMaterializedParity(t *testing.T) {
	raw := bytes.Replace(bootstrapFixture(t), []byte(`"enabled":false`), []byte(`"enabled":true`), 1)
	c, err := DecodeConfigValues(raw)
	if err != nil || !c.Enabled() {
		t.Fatal("enabled mutation rejected", err)
	}
	if _, err := DecodeBootstrapConfig(raw); err != ErrBootstrapConfig {
		t.Fatal("bootstrap enabled guard changed", err)
	}
	cols, args, err := c.sqlValues("installation_synthetic", "7", "test", 4)
	if err != nil || len(cols) != 133 || len(args) != len(cols) {
		t.Fatal("incomplete columns", len(cols), err)
	}
	values := map[string]any{}
	for i, k := range cols {
		values[k] = args[i]
	}
	if values["version"] != int64(4) || values["enabled"] != true || values["config_sha256"] != c.SHA256() || values["config_size_bytes"] != len(c.CanonicalJSON()) || !bytes.Equal(values["canonical_config_json"].([]byte), c.CanonicalJSON()) {
		t.Fatal("canonical/materialized identity drift")
	}
	if _, _, err := c.sqlValues("installation_synthetic", "7", "test", 0); err != ErrConfigMutation {
		t.Fatal("zero version accepted")
	}
	if _, _, err := (ConfigValues{}).sqlValues("installation_synthetic", "7", "test", 4); err != ErrConfigMutation {
		t.Fatal("zero config accepted")
	}
	args[len(args)-1].([]byte)[0] = 'x'
	copy := c.CanonicalJSON()
	copy[0] = 'x'
	refs := c.References()
	refs[0].Purpose = "changed"
	regs := c.Registries()
	regs[0].Kind = "changed"
	raw[0] = 'x'
	if c.CanonicalJSON()[0] != '{' || c.References()[0].Purpose == "changed" || c.Registries()[0].Kind == "changed" {
		t.Fatal("mutable snapshot")
	}
}

func TestConfigMutationRequestVectorsMatchA(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/evidence/a-config-canonical-request-vectors-20261014.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Input struct {
				Installation string          `json:"origin_installation_id"`
				ActorType    string          `json:"actor_type"`
				ActorID      string          `json:"actor_id"`
				Endpoint     string          `json:"endpoint"`
				Request      json.RawMessage `json:"request"`
			} `json:"input"`
			Canonical string `json:"canonical_utf8"`
			Hash      string `json:"request_sha256"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Vectors) != 2 {
		t.Fatal("missing A vectors")
	}
	for _, v := range vectors.Vectors {
		t.Run(v.Input.Endpoint, func(t *testing.T) {
			r, err := DecodeConfigMutationRequest(v.Input.Endpoint, v.Input.Request)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := r.RequestHash(v.Input.Installation, v.Input.ActorType, v.Input.ActorID)
			if err != nil || hash != v.Hash || registrationHash(v.Canonical) != hash {
				t.Fatal("A profile parity", hash, v.Hash, err)
			}
		})
	}
}

func TestConfigMutationNullableUnicodeReasonAndNormalization(t *testing.T) {
	base, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, mutationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if base.ChangeReason() != nil || !bytes.Contains(base.CanonicalJSON(), []byte(`"change_reason":null`)) {
		t.Fatal("null reason lost")
	}
	otherRaw := bytes.Replace(mutationFixture(t), []byte(`"expected_version":3`), []byte(`"expected_version":3e0`), 1)
	otherRaw = bytes.Replace(otherRaw, []byte(`"source_size_safety_factor":1.25`), []byte(`"source_size_safety_factor":125e-2`), 1)
	var pretty bytes.Buffer
	json.Indent(&pretty, otherRaw, "", " ")
	other, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, pretty.Bytes())
	if err != nil || !bytes.Equal(base.CanonicalJSON(), other.CanonicalJSON()) {
		t.Fatal("numeric/whitespace normalization", err)
	}
	unicodeRaw := bytes.Replace(mutationFixture(t), []byte(`"change_reason":null`), []byte(`"change_reason":"中文<>&\u2028\n😀"`), 1)
	r, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, unicodeRaw)
	if err != nil || !bytes.Contains(r.CanonicalJSON(), []byte("中文<>&\u2028")) {
		t.Fatal("JCS unicode escaped", err)
	}
	copy := r.ChangeReason()
	*copy = "changed"
	canonical := r.CanonicalJSON()
	canonical[0] = 'x'
	unicodeRaw[0] = 'x'
	if *r.ChangeReason() == "changed" || r.CanonicalJSON()[0] != '{' {
		t.Fatal("request aliases caller data")
	}
	emptyRaw := bytes.Replace(mutationFixture(t), []byte(`"change_reason":null`), []byte(`"change_reason":""`), 1)
	empty, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, emptyRaw)
	if err != nil || empty.ChangeReason() == nil || *empty.ChangeReason() != "" || bytes.Equal(base.CanonicalJSON(), empty.CanonicalJSON()) {
		t.Fatal("empty/null conflated")
	}
}

func TestConfigMutationStrictRequestBoundary(t *testing.T) {
	base := string(mutationFixture(t))
	cases := map[string]string{
		"proof":             strings.Replace(base, `"expected_version":3`, `"expected_version":3,"strong_auth_proof":"x"`, 1),
		"unknown":           strings.Replace(base, `"expected_version":3`, `"expected_version":3,"request_id":"x"`, 1),
		"alias":             strings.Replace(base, `"expected_version":3`, `"Expected_version":3`, 1),
		"duplicate":         strings.Replace(base, `"expected_version":3`, `"expected_version":3,"expected_version":3`, 1),
		"quoted":            strings.Replace(base, `"expected_version":3`, `"expected_version":"3"`, 1),
		"zero":              strings.Replace(base, `"expected_version":3`, `"expected_version":0`, 1),
		"fraction":          strings.Replace(base, `"expected_version":3`, `"expected_version":3.1`, 1),
		"unsafe":            strings.Replace(base, `"expected_version":3`, `"expected_version":9007199254740992`, 1),
		"null-version":      strings.Replace(base, `"expected_version":3`, `"expected_version":null`, 1),
		"missing":           strings.Replace(base, `"expected_version":3`, `"rollback_from_version":3`, 1),
		"reason-type":       strings.Replace(base, `"change_reason":null`, `"change_reason":[]`, 1),
		"utf8-budget":       strings.Replace(base, `"change_reason":null`, `"change_reason":"`+strings.Repeat("中", 171)+`"`, 1),
		"surrogate":         strings.Replace(base, `"change_reason":null`, `"change_reason":"\ud800"`, 1),
		"config-null":       `{"expected_version":3,"change_reason":null,"config":null}`,
		"config-incomplete": `{"expected_version":3,"change_reason":null,"config":{}}`,
		"trailing":          base + `{}`, "oversize": strings.Repeat(" ", 262145) + base,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, []byte(raw)); err != ErrConfigMutation {
				t.Fatal("invalid request accepted", err)
			}
		})
	}
	if _, err := DecodeConfigMutationRequest("bootstrapSystemBackupConfig", []byte(base)); err != ErrConfigMutation {
		t.Fatal("unknown endpoint")
	}
	rollback := `{"expected_version":3,"change_reason":null,"rollback_from_version":2}`
	r, err := DecodeConfigMutationRequest(ConfigRollbackEndpoint, []byte(rollback))
	if err != nil || r.ExpectedVersion() != 3 || r.RollbackFromVersion() != 2 {
		t.Fatal("rollback selector", err)
	}
	if _, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, []byte(rollback)); err != ErrConfigMutation {
		t.Fatal("cross endpoint accepted")
	}
}

func TestConfigMutationHashScopeAndOrder(t *testing.T) {
	r, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, mutationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := r.RequestHash("installation_synthetic", "admin", "7")
	for _, scope := range [][3]string{{"installation_other", "admin", "7"}, {"installation_synthetic", "admin", "8"}, {"installation_synthetic", "system", "system:controller"}} {
		h, err := r.RequestHash(scope[0], scope[1], scope[2])
		if err != nil || h == hash {
			t.Fatal("scope unbound", scope, err)
		}
	}
	for _, scope := range [][3]string{{"foreign", "admin", "7"}, {"installation_synthetic", "service", "7"}, {"installation_synthetic", "system", "7"}, {"installation_synthetic", "admin", "abc"}} {
		if _, err := r.RequestHash(scope[0], scope[1], scope[2]); err != ErrConfigMutation {
			t.Fatal("invalid actor scope", scope)
		}
	}
	if _, err := (ConfigMutationRequest{}).RequestHash("installation_synthetic", "admin", "7"); err != ErrConfigMutation {
		t.Fatal("zero request accepted")
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(mutationFixture(t), &doc)
	var config map[string]json.RawMessage
	json.Unmarshal(doc["config"], &config)
	var refs []BootstrapSecretRef
	json.Unmarshal(config["references"], &refs)
	refs[0], refs[1] = refs[1], refs[0]
	config["references"], _ = json.Marshal(refs)
	doc["config"], _ = json.Marshal(config)
	raw, _ := json.Marshal(doc)
	reordered, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
	if err != nil {
		t.Fatal(err)
	}
	reorderedHash, _ := reordered.RequestHash("installation_synthetic", "admin", "7")
	if reflect.DeepEqual(reordered.CanonicalJSON(), r.CanonicalJSON()) || reorderedHash == hash {
		t.Fatal("array order erased")
	}
}
