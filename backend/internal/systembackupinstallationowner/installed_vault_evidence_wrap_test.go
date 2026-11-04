package systembackupinstallationowner

import (
	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
	"strings"
	"testing"
)

func TestInstalledEvidenceWrapIsExplicitAndCannotBecomeKMSOrUnwrap(t *testing.T) {
	transit := ev.TransitConfig{Endpoint: "https://vault.example", Installation: "installation_model", KeyName: "evidence-model", Key: ev.KeyRef{Identity: strings.Repeat("a", 64), Version: "1"}, KeyVersion: 1, CAPEM: []byte("model-ca"), CASHA256: strings.Repeat("b", 64)}
	role := a.VaultPermissionRole{AuthMount: "jwt", Role: "evidence-wrap", Policy: "evidence-wrap", Audience: "evidence-wrap", Namespace: "system", ServiceAccountName: "controller", ServiceAccountUID: "sa-uid", PodUID: "pod-uid"}
	cfg := InstalledVaultDependencyConfig{Endpoint: transit.Endpoint, CASHA256: transit.CASHA256, CAPEM: transit.CAPEM, PinnedKeyName: "backup-kek", TransitMount: "transit", JWTMount: "jwt", EvidenceWrap: &InstalledVaultEvidenceWrapProfile{Transit: transit, Role: role}}
	// Shape only; the full constructor still requires real PEM, Kube and JWT trust.
	if validateInstalledEvidenceWrap(cfg) != nil {
		t.Fatal("exact model profile refused")
	}
	cfg.EvidenceWrap.Transit.KeyName = cfg.PinnedKeyName
	if validateInstalledEvidenceWrap(cfg) == nil {
		t.Fatal("backup key reused")
	}
	cfg.EvidenceWrap.Transit.KeyName = "evidence-model"
	cfg.EvidenceWrap.Role.PodUID = ""
	if validateInstalledEvidenceWrap(cfg) == nil {
		t.Fatal("unbound Pod accepted")
	}
}
