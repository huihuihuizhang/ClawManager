package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDisabledInitializationPlanIsDisabledCanonicalDataOnly(t *testing.T) {
	c, e := DecodeBootstrapConfig(bootstrapFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	g := OfflineBootstrapGrant{InstallationID: "installation_test", ServerUUID: "00000000-0000-4000-8000-000000000001", Database: "test", UserID: 7, Username: "admin", MatrixKey: "k8s-cluster", ConfigSHA256: c.SHA256(), IdempotencyKey: "disabled-original-key-1", ChangeReason: "explicit original initialization"}
	p, e := c.DisabledInitializationPlan(g)
	if e != nil {
		t.Fatal(e)
	}
	values := map[string]any{}
	for n, k := range p.Columns {
		values[k] = p.Values[n]
	}
	if values["enabled"] != false || values["version"] != int64(1) || values["config_sha256"] != c.SHA256() || !bytes.Equal(values["canonical_config_json"].([]byte), c.CanonicalJSON()) || p.CapacityBytes <= 0 || p.OperationDeadline <= 0 || p.Retention <= 0 {
		t.Fatal("lost complete disabled configuration")
	}
	for _, key := range []string{"canonical_config_json", "kek_identity_hash", "capture_signing_identity_hash"} {
		if _, exists := values[key]; !exists {
			t.Fatalf("missing original flattened field %s", key)
		}
	}
	bad := g
	bad.ConfigSHA256 = strings.Repeat("0", 64)
	if _, e = c.DisabledInitializationPlan(bad); e == nil {
		t.Fatal("foreign config accepted")
	}
	var doc map[string]any
	if json.Unmarshal(c.CanonicalJSON(), &doc) != nil {
		t.Fatal("fixture")
	}
	doc["enabled"] = true
	raw, _ := json.Marshal(doc)
	current, e := DecodeConfigValues(raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = current.snapshot.DisabledInitializationPlan(g); e == nil {
		t.Fatal("enabled config became initialization data")
	}
	if _, e = (BootstrapConfig{}).DisabledInitializationPlan(g); e == nil {
		t.Fatal("empty config accepted")
	}
}
