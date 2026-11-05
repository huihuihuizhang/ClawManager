package systembackupinstallationowner

import (
	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
	"strings"
	"testing"
)

// This exercises the actual whole-native-roster ACL classifier, not a supplied
// Passed field. Root additionally must run real Vault/Kube permission probes.
func TestInstalledArchiveUnwrapRequiresExplicitExactEvidenceRole(t *testing.T) {
	tr := ev.TransitConfig{Endpoint: "https://vault.example", Installation: "installation_model", KeyName: "evidence-model", Key: ev.KeyRef{Identity: strings.Repeat("a", 64), Version: "1"}, KeyVersion: 1, CAPEM: []byte("model-ca"), CASHA256: strings.Repeat("b", 64)}
	wrap := a.VaultPermissionRole{AuthMount: "jwt", Role: "evidence-wrap", Policy: "evidence-wrap", Audience: "evidence-wrap", Namespace: "system", ServiceAccountName: "controller", ServiceAccountUID: "sa-uid", PodUID: "pod-uid"}
	read := wrap
	read.Role = "evidence-read"
	read.Policy = "evidence-read"
	read.Audience = "evidence-read"
	cfg := InstalledVaultDependencyConfig{Endpoint: tr.Endpoint, CASHA256: tr.CASHA256, CAPEM: tr.CAPEM, PinnedKeyName: "backup-kek", TransitMount: "transit", JWTMount: "jwt", EvidenceWrap: &InstalledVaultEvidenceWrapProfile{Transit: tr, Role: wrap, ArchiveUnwrap: &read}}
	keys := []InstalledVaultKey{{Name: tr.KeyName, Type: "aes256-gcm96", Latest: 1, MinimumEncryption: 0, MinimumDecryption: 1, Versions: []InstalledVaultKeyVersion{{Version: "1"}}}}
	raw, e := a.VaultJWTAuthRole(read)
	if e != nil {
		t.Fatal(e)
	}
	acl, e := a.EvidenceVaultRuntimeACL(tr, ev.TransitUnwrap)
	if e != nil {
		t.Fatal(e)
	}
	if !installedEvidenceWrapMatches(cfg, read.Role, raw, acl, keys) {
		t.Fatal("exact explicit evidence read refused")
	}
	t.Run("no opt in", func(t *testing.T) {
		p := *cfg.EvidenceWrap
		p.ArchiveUnwrap = nil
		c := cfg
		c.EvidenceWrap = &p
		if installedEvidenceWrapMatches(c, read.Role, raw, acl, keys) {
			t.Fatal("unwrap admitted by wrap-only profile")
		}
	})
	t.Run("encrypt substituted", func(t *testing.T) {
		bad, _ := a.EvidenceVaultRuntimeACL(tr, ev.TransitWrap)
		if installedEvidenceWrapMatches(cfg, read.Role, raw, bad, keys) {
			t.Fatal("wrong crypto permission")
		}
	})
	t.Run("extra policy", func(t *testing.T) {
		if installedEvidenceWrapMatches(cfg, read.Role, raw, acl+"path \"transit/*\" { capabilities=[\"update\"] }", keys) {
			t.Fatal("expanded policy")
		}
	})
	t.Run("foreign role", func(t *testing.T) {
		if installedEvidenceWrapMatches(cfg, "foreign-read", raw, acl, keys) {
			t.Fatal("foreign role")
		}
	})
	t.Run("unbound reader", func(t *testing.T) {
		r := read
		r.PodUID = ""
		p := *cfg.EvidenceWrap
		p.ArchiveUnwrap = &r
		c := cfg
		c.EvidenceWrap = &p
		if validateInstalledEvidenceWrap(c) == nil {
			t.Fatal("unbound Pod")
		}
	})
	t.Run("backup key", func(t *testing.T) {
		p := *cfg.EvidenceWrap
		p.Transit.KeyName = cfg.PinnedKeyName
		c := cfg
		c.EvidenceWrap = &p
		if validateInstalledEvidenceWrap(c) == nil {
			t.Fatal("backup KEK substituted")
		}
	})
}
