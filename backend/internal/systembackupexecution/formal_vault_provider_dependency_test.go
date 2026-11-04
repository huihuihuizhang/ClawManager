package systembackupexecution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestFormalVaultCannotAlsoBeColdBusinessWriter(t *testing.T) {
	p := FormalVaultProviderDependency{Version: "formal-vault-provider-dependency.v1", Workload: install.VaultProviderWorkloadSelection{Deployment: "vault", DeploymentUID: "vault-uid", Container: "vault", ImageID: "image", Service: "vault", ServiceUID: "svc-uid", Claim: "private", ClaimUID: "claim-uid", DataMountPath: "/data"}, Observer: install.BootstrapSourceFilePin{File: filepath.Join(t.TempDir(), "observer.json"), SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	cfg := DeploymentConfig{CaptureScope: "six-part", FormalVerifier: &FormalVerifierReference{}, ProviderDependencies: []FormalVaultProviderDependency{p}}
	if validateFormalVaultDependencies(cfg) != nil {
		t.Fatal("separate syntax selection rejected")
	}
	for _, writer := range []PlatformDeployment{{Name: "vault", UID: "other"}, {Name: "other", UID: "vault-uid"}} {
		cfg.Writers = []PlatformDeployment{writer}
		if validateFormalVaultDependencies(cfg) == nil {
			t.Fatal("provider was also accepted as a stopped business source")
		}
	}
	cfg.Writers = nil
	cfg.Workspace.Claim = "private"
	if validateFormalVaultDependencies(cfg) == nil {
		t.Fatal("provider private claim aliased business workspace")
	}
	cfg.Workspace.Claim = ""
	cfg.ProviderDependencies = append(cfg.ProviderDependencies, p)
	if validateFormalVaultDependencies(cfg) == nil {
		t.Fatal("duplicate dependencies accepted")
	}
}

func TestFormalVaultRejectsOriginalRootTransport(t *testing.T) {
	file := filepath.Join(t.TempDir(), "original-observer.json")
	raw, _ := json.Marshal(owner.InstalledVaultDependencyConfig{IdentityMode: "original-owner-readonly"})
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if _, e := readFormalVaultObserver(install.BootstrapSourceFilePin{File: file, SHA256: hash(raw)}); e == nil {
		t.Fatal("original root credential path reached formal runtime")
	}
}
