package systembackupkekadapter

import (
	ev "clawreef/internal/systembackupevidence"
	"strings"
	"testing"
)

func TestEvidenceReferenceUsesDedicatedWrapContextAndVersion(t *testing.T) {
	c := ev.TransitConfig{Installation: "installation_synthetic", KeyName: "evidence-only", Key: ev.KeyRef{Identity: strings.Repeat("a", 64), Version: "v1"}, KeyVersion: 7}
	wrap, e := EvidenceVaultRuntimeACL(c, ev.TransitWrap)
	if e != nil {
		t.Fatal(e)
	}
	context, e := ev.EvidenceTransitContext(c.Installation, c.Key)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(wrap, `transit/encrypt/evidence-only`) || !strings.Contains(wrap, context) || !strings.Contains(wrap, `"key_version" = ["7"]`) || strings.Contains(wrap, "datakey") {
		t.Fatal("wrong purpose or version")
	}
	unwrap, e := EvidenceVaultRuntimeACL(c, ev.TransitUnwrap)
	if e != nil || !strings.Contains(unwrap, `transit/decrypt/evidence-only`) || !strings.Contains(unwrap, context) || strings.Contains(unwrap, "plaintext") {
		t.Fatal("wrong unwrap ACL")
	}
	other := c
	other.Key.Version = "v2"
	changed, e := EvidenceVaultRuntimeACL(other, ev.TransitWrap)
	if e != nil || changed == wrap {
		t.Fatal("reference version omitted from context")
	}
	if _, e := EvidenceVaultRuntimeACL(c, ev.TransitOperation("generate")); e == nil {
		t.Fatal("capture operation accepted")
	}
}
