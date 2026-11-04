//go:build systembackup_runtime_release

package install

import (
	"context"
	"os"
	"testing"
)

// Actual built ELF/layer/manifest/config comparison DATA. This does not create
// a native peer or certify a deployed process, physical hold or page backup.
func TestActualSharedNativeTLSRuntimeReleaseInputs(t *testing.T) {
	file, pin := os.Getenv("SBK_ACTUAL_RUNTIME_IMAGE_INPUTS_FILE"), os.Getenv("SBK_ACTUAL_RUNTIME_IMAGE_INPUTS_SHA256")
	if file == "" || !digestPattern.MatchString(pin) {
		t.Fatal("explicit pinned actual release inputs required")
	}
	raw, err := os.ReadFile(file)
	if err != nil || len(raw) > 262144 || hash(raw) != pin {
		t.Fatal("actual release input file changed")
	}
	var document struct {
		Version string
		Images  []OriginalRuntimeStartupImageInput
	}
	if decodeExact(raw, &document) != nil || document.Version != "original-runtime-startup-image-inputs.v1" || len(document.Images) != 2 {
		t.Fatal("actual two-runtime input document required")
	}
	set, err := readOriginalRuntimeImageSet(context.Background(), document.Images)
	if err != nil || len(set) != 2 {
		t.Fatal("actual constructed image bytes rejected", err)
	}
	for _, input := range document.Images {
		image := set[input.Manifest.SHA256]
		if image == nil || image.runtime != "openclaw" && image.runtime != "hermes" {
			t.Fatal("actual runtime source missing")
		}
		t.Run(image.runtime, func(t *testing.T) {
			bad := input
			bad.Config.SHA256 = input.BaseConfig.SHA256
			if _, err := readOriginalRuntimeImage(context.Background(), bad); err == nil {
				t.Fatal("new manifest borrowed the base config")
			}
			bad = input
			bad.BaseManifest = document.Images[0].BaseManifest
			if image.runtime == "openclaw" {
				bad.BaseManifest = document.Images[1].BaseManifest
			}
			if _, err := readOriginalRuntimeImage(context.Background(), bad); err == nil {
				t.Fatal("cross-runtime base accepted")
			}
		})
	}
}
