package main

import (
	"bytes"
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSixReferenceCLIRefusesMissingAndForeignActionsBeforeInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"requirements"}, {"apply"}, {"issue"}, {"owner-binding"}, {"issue", "--approved"}, {"issue", "--force"}, {"owner-binding", "--issuer-private-file", "must-not-open"}, {"issue", "--record-file", "must-not-open"}, {"issue", "--task-id", "foreign-task"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("invalid/foreign authority flags reached material inputs", args, code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if run(ctx, []string{"issue"}, &bytes.Buffer{}) != 2 {
		t.Fatal("cancelled request reached material inputs")
	}
}

func TestSixReferenceCLIOutputsSixCompositionDataBindings(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	args := []string{"owner-binding", "--capture-consumer-file", filepath.Join(dir, "capture.json"), "--capture-consumer-pin-file", filepath.Join(dir, "capture.sha256"), "--record-file", filepath.Join(dir, "six.record.json"), "--record-sha256", strings.Repeat("a", 64), "--signature-file", filepath.Join(dir, "six.signature")}
	if code := run(context.Background(), args, &out); code != 0 {
		t.Fatal("DATA binding command", code)
	}
	var bindings []install.BootstrapOriginalOwnerBinding
	if json.Unmarshal(out.Bytes(), &bindings) != nil || len(bindings) != 6 {
		t.Fatal("six exact aliases missing")
	}
	seen := map[string]bool{}
	for _, b := range bindings {
		if seen[b.Key] || len(b.SHA256) != 64 || b.SHA256 != bindings[0].SHA256 {
			t.Fatal("composition data binding changed")
		}
		seen[b.Key] = true
	}
	for _, purpose := range []string{"artifact_upload_issuer", "evidence_store", "evidence_write", "evidence_read", "evidence_delete", "evidence_kek"} {
		if !seen["reference:"+purpose] {
			t.Fatal("missing purpose", purpose)
		}
	}
}
func TestSixReferenceCLIRefusesExistingOutputs(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if newOutput(dir) == nil {
			t.Fatal("public output directory accepted")
		}
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if newOutput(dir) != nil {
		t.Fatal("empty private output directory rejected")
	}
	path := filepath.Join(dir, "six-provider-references.signature")
	original := []byte("keep original")
	if e := os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	if newOutput(dir) == nil {
		t.Fatal("existing output accepted")
	}
	actual, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(actual, original) {
		t.Fatal("existing output changed")
	}
}
