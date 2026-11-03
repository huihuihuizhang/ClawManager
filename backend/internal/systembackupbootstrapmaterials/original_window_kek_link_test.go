package systembackupbootstrapmaterials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Constructor/assembly only. Public source pins are declarations, not actual
// witness/adoption evidence. No successful PreparedAdmission is manufactured.
func TestOriginalWindowSQLKEKLinkUsesOneActualBridgeAndKeepsMissingOwners(t *testing.T) {
	directory := t.TempDir()
	raw, err := json.Marshal(originalKEKSourceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "original-kek-source.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	preparation, err := LoadOriginalSQLBootstrapKEKPreparation(file, pin)
	if err != nil || preparation == nil {
		t.Fatal("pinned concrete source constructor", err)
	}
	capture := install.NewCaptureSigningConsumer(filepath.Join(directory, "absent-capture-source"), filepath.Join(directory, "absent-capture-pin"))
	original, err := install.NewBootstrapTerminalOriginal(capture, install.BootstrapTerminalFiles{MappingSHA256: strings.Repeat("a", 64)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := original.Owners()
	if err != nil {
		t.Fatal(err)
	}
	window := install.BootstrapKEKWindowFiles{RecordFile: filepath.Join(directory, "absent-kek-window"), RecordSHA256: strings.Repeat("b", 64), SignatureFile: filepath.Join(directory, "absent-kek-signature")}
	owners, linked, err := LinkOriginalWindowSQLBootstrapKEK(original, file, pin, window)
	if err != nil || linked == nil || linked == original {
		t.Fatal("actual original terminal link", err)
	}
	bridge, ok := owners.KEK.(*install.OriginalWindowKEK)
	if !ok || owners.References["kek"] != bridge || owners.References["capture_signing"] != capture {
		t.Fatal("reference and independent preparation lost their exact single bridge/capture")
	}
	missing := sec.MissingBootstrapOwnerAdapters(before)
	wanted := make([]string, 0, len(missing))
	for _, name := range missing {
		if name != "reference:kek" {
			wanted = append(wanted, name)
		}
	}
	if !reflect.DeepEqual(wanted, sec.MissingBootstrapOwnerAdapters(owners)) || !reflect.DeepEqual(wanted, linked.MissingTerminalResources()) || len(original.MissingTerminalResources()) != len(missing) {
		t.Fatal("other missing owners changed or original terminal was mutated")
	}
	if prepared, err := bridge.PrepareTerminalResource(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil || prepared != nil {
		t.Fatal("absent actual original capture/window supplied a resource observation")
	}
	if admission, err := bridge.PrepareBootstrapKEK(context.Background(), nil, sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil || admission != nil {
		t.Fatal("assembly supplied independent source admission without a real attempt/database")
	}
	if _, _, err := LinkOriginalWindowSQLBootstrapKEK(linked, file, pin, window); err == nil {
		t.Fatal("existing KEK resource replaced")
	}
	if _, err := LoadOriginalSQLBootstrapKEKPreparation(file, strings.Repeat("f", 64)); err == nil {
		t.Fatal("source hash selected from unpinned content")
	}
}
