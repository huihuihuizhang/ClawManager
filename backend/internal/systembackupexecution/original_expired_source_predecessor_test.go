package systembackupexecution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestExpiredSourcePredecessorPreservesExactFactsAndScope(t *testing.T) {
	for _, mode := range []string{"valid", "live", "overlapping-window", "foreign-installation", "foreign-controller", "foreign-scope", "wrong-receipt-selection", "missing-native-registries", "changed-fact", "missing-fact", "same-directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, value any) install.BootstrapSourceFilePin {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(dir, name)
				if err = os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return install.BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
			}
			now := time.Now().UTC()
			core := DeploymentConfig{InstallationID: "installation", ApplicationScope: "scope", ControllerOwner: "controller"}
			controller := install.BootstrapSourceController{Namespace: "ns", NamespaceUID: "nsuid", Deployment: "controller", DeploymentUID: "duid", ServiceAccount: "sa", ServiceAccountUID: "sauid"}
			parts, writers, redis, policy := write("parts.json", map[string]string{"fact": "parts"}), write("writers.json", map[string]string{"fact": "writers"}), write("redis.json", map[string]string{"fact": "redis"}), write("policy.json", map[string]string{"policy": "secrets"})
			previous := install.BootstrapSourceAuthoringSelection{Version: install.BootstrapSourceAuthoringSelectionVersion, Deployment: write("core.json", core), MaterialsTemplate: write("materials.json", map[string]string{}), ExecutionProfile: write("profile.json", map[string]string{}), Controller: controller, ApplicationScope: core.ApplicationScope, PartsFile: parts.File, SourceWritersFile: writers.File, RedisSourcesFile: redis.File, NotBefore: now.Add(-time.Hour), Until: now.Add(-time.Minute)}
			if mode == "live" {
				previous.Until = now.Add(time.Minute)
			}
			selection := write("selection.json", previous)
			facts := BootstrapSourceRegistryFactsReceipt{Version: "original-source-registry-facts-receipt.v1", SelectionSHA256: selection.SHA256, PartsRegistry: parts, SourceWritersRegistry: writers, NativeRegistries: &BootstrapSourceNativeRegistryFiles{RedisSources: redis, SecretAllowlist: policy}}
			if mode == "wrong-receipt-selection" {
				facts.SelectionSHA256 = "other"
			}
			if mode == "missing-native-registries" {
				facts.NativeRegistries = nil
			}
			in := OriginalInitialSourceAuthorInputs{Deployment: core, Controller: controller, NotBefore: now, Until: now.Add(30 * time.Minute), ExpiredPredecessor: &OriginalExpiredSourcePredecessor{SourceSelection: selection, FactsReceipt: write("facts-receipt.json", facts)}}
			out := filepath.Join(dir, "successor")
			switch mode {
			case "overlapping-window":
				in.NotBefore = previous.Until.Add(-time.Second)
			case "foreign-installation":
				in.Deployment.InstallationID = "other"
			case "foreign-controller":
				in.Controller.ServiceAccountUID = "other"
			case "foreign-scope":
				in.Deployment.ApplicationScope = "other"
			case "changed-fact":
				if err := os.WriteFile(redis.File, []byte(`{"changed":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-fact":
				if err := os.Remove(writers.File); err != nil {
					t.Fatal(err)
				}
			case "same-directory":
				out = dir
			}
			err := checkOriginalExpiredSourcePredecessor(in, out, now)
			if (err == nil) != (mode == "valid") {
				t.Fatal("predecessor decision differs", mode, err)
			}
			if _, err := os.Stat(out); mode != "same-directory" && !os.IsNotExist(err) {
				t.Fatal("validation wrote new output")
			}
		})
	}
}
