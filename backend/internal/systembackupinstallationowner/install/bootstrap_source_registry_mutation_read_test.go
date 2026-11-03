package install

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func TestSourceRegistryMutationReadCannotConvertEmptyOrCopiedSource(t *testing.T) {
	dir := t.TempDir()
	capture := NewCaptureSigningConsumer(filepath.Join(dir, "capture.json"), filepath.Join(dir, "capture.sha256"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	files := BootstrapSourceRegistryFiles{RecordFile: filepath.Join(dir, "source.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(dir, "source.sig")}
	mapping := BootstrapTerminalFiles{MappingFile: filepath.Join(dir, "mapping.json"), MappingSHA256: strings.Repeat("b", 64), SignatureFile: filepath.Join(dir, "mapping.sig")}
	if p, err := capture.PrepareSourceRegistryEnableOnlyRead(ctx, sec.ConfigMutationResourceInput{}, files, mapping, strings.Repeat("c", 64)); err == nil || p != nil {
		t.Fatal("empty snapshots converted original source into mutation permission")
	}
	original := &BootstrapSourceRegistryMutationRead{ctx: ctx, until: time.Now().Add(time.Second)}
	original.origin = original
	detached := &BootstrapSourceRegistryMutationRead{origin: original, ctx: ctx, until: original.until}
	if !detached.ValidUntil().IsZero() || !original.failed.Load() {
		t.Fatal("copied source getter did not poison original")
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("serialized original mutation read capability")
	}
	if original.Recheck(ctx, nil, time.Now()) == nil {
		t.Fatal("nil mutation SQL accepted")
	}
}
