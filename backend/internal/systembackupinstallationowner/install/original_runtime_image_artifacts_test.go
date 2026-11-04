//go:build systembackup_runtime_images

package install

import (
	"context"
	"os"
	"testing"
	"time"
)

// Optional qualification against REAL retained image artifacts. Missing inputs
// fail when explicitly enabled. This is not a Pod/mode/cap/hold qualification.
func TestOriginalRuntimeImageActualInputs(t *testing.T) {
	file, pin := os.Getenv("TEST_ORIGINAL_RUNTIME_STARTUP_IMAGES_FILE"), os.Getenv("TEST_ORIGINAL_RUNTIME_STARTUP_IMAGES_SHA256")
	if file == "" || pin == "" {
		t.Fatal("actual independently pinned image artifact input definition required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	inputs, e := loadOriginalRuntimeImageInputs(ctx, BootstrapSourceFilePin{File: file, SHA256: pin})
	if e != nil || len(inputs) != 2 {
		t.Fatal("both real runtime image inputs did not authenticate")
	}
	images, e := readOriginalRuntimeImageSet(ctx, inputs)
	if e != nil {
		t.Fatal("actual image input consistency")
	}
	kinds := map[string]bool{}
	for _, p := range images {
		kinds[p.runtime] = true
	}
	if !kinds["openclaw"] || !kinds["hermes"] {
		t.Fatal("both actual base families required")
	}
	t.Log("actual OCI input bytes/hash/preservation/managed-layer comparison qualified; no native Pod, mode, business ownership or hold claim")
}
