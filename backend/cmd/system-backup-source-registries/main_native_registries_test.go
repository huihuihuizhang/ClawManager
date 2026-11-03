package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestSourceRegistryCLIFourExplicitNativeBindings(t *testing.T) {
	dir := t.TempDir()
	args := []string{"owner-bindings", "--capture-consumer-file", filepath.Join(dir, "capture.json"), "--capture-consumer-pin-file", filepath.Join(dir, "capture.sha256"), "--record-file", filepath.Join(dir, "source.json"), "--record-sha256", strings.Repeat("a", 64), "--signature-file", filepath.Join(dir, "source.sig")}
	if code := run(context.Background(), append(append([]string{}, args...), "--redis-sources-file", filepath.Join(dir, "redis.json")), &bytes.Buffer{}); code != 2 {
		t.Fatal("partial native registry binding accepted", code)
	}
	nativeArgs := append(append([]string{}, args...), "--redis-sources-file", filepath.Join(dir, "redis.json"), "--redis-sources-sha256", strings.Repeat("b", 64), "--secret-allowlist-file", filepath.Join(dir, "secrets.json"), "--secret-allowlist-sha256", strings.Repeat("c", 64))
	var out bytes.Buffer
	if code := run(context.Background(), nativeArgs, &out); code != 0 {
		t.Fatal("explicit four-slot composition refused", code)
	}
	var bindings []install.BootstrapOriginalOwnerBinding
	if json.Unmarshal(out.Bytes(), &bindings) != nil || len(bindings) != 4 {
		t.Fatal("four original owner bindings missing")
	}
	for _, binding := range bindings {
		if binding.SHA256 != bindings[0].SHA256 {
			t.Fatal("four-slot composition does not share original binding")
		}
	}
}
