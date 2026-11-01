package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginalCoreSetupAllowsOnlyDetachedPreSealPublicationDeclarations(t *testing.T) {
	core := runtimeDeploymentFixture(t)
	original, _ := json.Marshal(core)
	var retained *DeploymentConfig
	result, err := prepareDOriginalCore(core, func(proposed *DeploymentConfig) error {
		retained = proposed
		proposed.PublicationSigners = &PublicationSignerReference{Protocol: "original-signers", Path: "original-signers.json"}
		proposed.PublisherVerifier = &PublisherVerifierReference{Protocol: "original-verifier", Path: "original-verifier.json"}
		proposed.PublicationTarget = &PublicationTargetReference{Protocol: "original-target", Path: "original-target.json"}
		proposed.PublicationWorker = &PublicationWorkerReference{Protocol: "original-worker", ServiceAccountName: "publication", ServiceAccountUID: "original-publication-sa"}
		return nil
	})
	if err != nil || result.PublicationTarget == nil || result.PublicationWorker == nil {
		t.Fatal("original declaration preparation rejected", err)
	}
	retained.HoldSeconds++
	retained.PublicationTarget.Path = "changed-after-seal"
	retained.RuntimeSources.Supported = nil
	if result.HoldSeconds != core.HoldSeconds || result.PublicationTarget.Path != "original-target.json" || len(result.RuntimeSources.Supported) != len(core.RuntimeSources.Supported) {
		t.Fatal("callback retained mutable ownership of sealed core")
	}
	observed, _ := json.Marshal(core)
	if !bytes.Equal(original, observed) {
		t.Fatal("pre-seal callback changed original input by alias")
	}
	for _, field := range []string{"hold", "scope", "workspace", "runtime", "security", "source", "grant"} {
		_, err := prepareDOriginalCore(core, func(proposed *DeploymentConfig) error {
			switch field {
			case "hold":
				proposed.HoldSeconds++
			case "scope":
				proposed.CaptureScope = "other"
			case "workspace":
				proposed.Workspace.MaxFiles++
			case "runtime":
				proposed.RuntimeSources.Supported = nil
			case "security":
				proposed.Security.ServiceAccountName = "other"
			case "source":
				proposed.SourceDatabase = "other"
			case "grant":
				proposed.ForwardGrant.Path = "other.json"
			}
			return nil
		})
		if !errors.Is(err, errDOriginalCoreChanged) {
			t.Fatal("pre-seal publication setup changed protected capture field", field, err)
		}
	}
}

func TestOriginalCoreSetupRejectsMemoryFileAndDigestChangesAfterSeal(t *testing.T) {
	core := runtimeDeploymentFixture(t)
	raw, err := json.Marshal(core)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "core.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	service := &DeploymentService{Config: core, ConfigPath: path, ConfigDigest: hash(raw)}
	if checkDOriginalCoreUnchanged(service, raw) != nil {
		t.Fatal("original sealed core rejected")
	}
	service.Config.PublicationTarget = &PublicationTargetReference{Protocol: "late", Path: "late.json"}
	if checkDOriginalCoreUnchanged(service, raw) == nil {
		t.Fatal("late publication reference changed the original sealed core")
	}
	service.Config = core
	if err := os.WriteFile(path, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if checkDOriginalCoreUnchanged(service, raw) == nil {
		t.Fatal("core file was changed after signature")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	service.ConfigDigest = "changed"
	if checkDOriginalCoreUnchanged(service, raw) == nil {
		t.Fatal("caller replaced the core pin")
	}
}
