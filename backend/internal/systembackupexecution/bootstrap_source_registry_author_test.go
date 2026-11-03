package systembackupexecution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Regression for the rejected v1 facts -> final metadata scope -> config ->
// facts hash fixed point. Fact codecs may contain actual source DATA, but not
// a digest of any final authority which will itself select these files.
func TestBootstrapSourceRegistryFactsHaveNoFinalAuthorityDependency(t *testing.T) {
	for _, value := range []any{bootstrapSourcePartsRegistry{SchemaVersion: bootstrapSourcePartsVersion, Installation: "original", Version: "parts-1"}, bootstrapSourceWritersRegistry{SchemaVersion: bootstrapSourceWritersVersion, Installation: "original", Version: "writers-1", ApplicationScope: "app"}} {
		raw, err := ce.Canonical(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("fact encoding")
		}
		for _, key := range []string{"MetadataScopeSHA256", "ConfigSHA256", "CaptureGrantSHA256", "MetadataGrantSHA256", "RegistrySHA256", "RecordSHA256"} {
			if _, ok := fields[key]; ok {
				t.Fatal("final authority dependency inside pre-capture facts", key)
			}
		}
		fields["MetadataScopeSHA256"] = json.RawMessage(`"legacy-cycle"`)
		legacy, err := ce.Canonical(fields)
		if err != nil {
			t.Fatal(err)
		}
		switch value.(type) {
		case bootstrapSourcePartsRegistry:
			var out bootstrapSourcePartsRegistry
			if strictBootstrapSourceJSON(legacy, &out) == nil {
				t.Fatal("silently upgraded cyclic part data")
			}
		case bootstrapSourceWritersRegistry:
			var out bootstrapSourceWritersRegistry
			if strictBootstrapSourceJSON(legacy, &out) == nil {
				t.Fatal("silently upgraded cyclic writer data")
			}
		}
	}
}

func TestBootstrapSourceFactOutputsAreStrictlyCreateOnly(t *testing.T) {
	dir := t.TempDir()
	parts, writers := filepath.Join(dir, "parts.json"), filepath.Join(dir, "writers.json")
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if checkBootstrapSourceFactOutputs(parts, writers) != nil {
		t.Fatal("new private outputs refused")
	}
	if runtime.GOOS == "linux" {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if checkBootstrapSourceFactOutputs(parts, writers) == nil {
			t.Fatal("public fact output directory accepted")
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if checkBootstrapSourceFactOutputs(parts, writers) != nil {
			t.Fatal("private baseline not restored before alias/file cases")
		}
	}
	if checkBootstrapSourceFactOutputs(parts, parts) == nil {
		t.Fatal("aliased outputs accepted")
	}
	if err := writeBootstrapSourceFactFile(parts, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if checkBootstrapSourceFactOutputs(parts, writers) == nil {
		t.Fatal("existing fact output accepted")
	}
	for _, raw := range [][]byte{[]byte("original"), []byte("changed")} {
		if writeBootstrapSourceFactFile(parts, raw) == nil {
			t.Fatal("existing file reused or overwritten")
		}
	}
	raw, err := os.ReadFile(parts)
	if err != nil || string(raw) != "original" {
		t.Fatal("original fact output changed", err)
	}
}

func TestBootstrapSourceFactProductionRequiresOriginalInstaller(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	selection := install.BootstrapSourceAuthoringSelection{Version: install.BootstrapSourceAuthoringSelectionVersion, PartsFile: filepath.Join(dir, "parts.json"), SourceWritersFile: filepath.Join(dir, "writers.json")}
	raw, err := ce.Canonical(selection)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "selection.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if checkBootstrapSourceFactOutputs(selection.PartsFile, selection.SourceWritersFile) != nil {
		t.Fatal("negative test did not reach original Installer boundary")
	}
	if _, err = ProduceOriginalBootstrapSourceRegistries(context.Background(), nil, nil, install.EnrollmentPin{}, file, hash(raw)); err == nil {
		t.Fatal("unauthenticated declarations produced facts")
	}
	for _, file := range []string{selection.PartsFile, selection.SourceWritersFile} {
		if _, err = os.Stat(file); !os.IsNotExist(err) {
			t.Fatal("untrusted selection wrote a registry")
		}
	}
}
