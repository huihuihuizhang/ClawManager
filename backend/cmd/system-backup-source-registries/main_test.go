package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestSourceRegistryCLIRejectsMissingOrCrossActionInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"produce-facts"}, {"issue-v2"}, {"produce-facts", "--issuer-private-file", "not-accepted"}, {"issue-v2", "--source-selection-file", "not-accepted"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatal("invalid command admitted or emitted authority", args, code)
		}
	}
}

func TestProviderLocalForwardIsOptionalAndProviderOnly(t *testing.T) {
	common := []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "source-selection-file", "source-selection-sha256", "writer-selection-file", "writer-selection-sha256", "controller-container", "output-directory"}
	for _, action := range []string{"prepare-provider-materials", "prepare-redis-materials", "prepare-observer-materials"} {
		for _, forwarded := range []bool{false, true} {
			args := []string{action}
			for _, name := range common {
				args = append(args, "--"+name, "nonexistent-input")
			}
			if forwarded {
				args = append(args, "--provider-local-forward", "127.0.0.1:1234")
			}
			var out bytes.Buffer
			want := 1 // Accepted syntax must still fail closed on absent original authority.
			if forwarded && action != "prepare-provider-materials" {
				want = 2
			}
			if code := run(context.Background(), args, &out); code != want || out.Len() != 0 {
				t.Fatal(action, forwarded, code)
			}
		}
	}
}

func TestSourceRegistryCLIOwnerBindingsShareOriginalCapture(t *testing.T) {
	dir := t.TempDir()
	args := []string{"owner-bindings", "--capture-consumer-file", filepath.Join(dir, "capture.json"), "--capture-consumer-pin-file", filepath.Join(dir, "capture.sha256"), "--record-file", filepath.Join(dir, "source.record.json"), "--record-sha256", strings.Repeat("a", 64), "--signature-file", filepath.Join(dir, "source.signature")}
	var out bytes.Buffer
	if code := run(context.Background(), args, &out); code != 0 {
		t.Fatal("composition-only binding refused", code)
	}
	var bindings []install.BootstrapOriginalOwnerBinding
	if json.Unmarshal(out.Bytes(), &bindings) != nil || len(bindings) != 2 || bindings[0].Key != "registry:parts" || bindings[1].Key != "registry:source_writers" || bindings[0].SHA256 != bindings[1].SHA256 || len(bindings[0].SHA256) != 64 {
		t.Fatal("different pointer composition bindings")
	}
	// No input files were read or created by the constructor-only action.
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("binding computation performed file I/O")
	}
}

func TestSourceRegistryCLIFrozenOutputPreflight(t *testing.T) {
	dir := filepath.Clean(t.TempDir())
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if newV2Output(dir) != nil {
		t.Fatal("new private output refused")
	}
	if runtime.GOOS == "linux" {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if newV2Output(dir) == nil {
			t.Fatal("public output directory accepted")
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if newV2Output(dir) != nil {
			t.Fatal("private baseline not restored before existing-file cases")
		}
	}
	for _, name := range []string{"bootstrap-source-registries-v2.record.json", "bootstrap-source-registries-v2.signature", "bootstrap-source-registries-v2.sha256"} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		if newV2Output(dir) == nil {
			t.Fatal("existing frozen output accepted", name)
		}
		raw, err := os.ReadFile(file)
		if err != nil || string(raw) != "original" {
			t.Fatal("preflight changed output")
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMetadataReissueUsesOriginalInstallerWithoutExpiredSourceSelection(t *testing.T) {
	args := []string{"issue-provider-metadata"}
	for _, name := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "database-ca-file", "local-admin-password-file", "enrollment-pin-file", "enrollment-pin-sha256", "writer-selection-file", "writer-selection-sha256", "output-directory"} {
		args = append(args, "--"+name, "missing-authority")
	}
	var out bytes.Buffer
	if code := run(context.Background(), args, &out); code != 1 || out.Len() != 0 {
		t.Fatal("absent original authority admitted", code)
	}
	for _, extra := range []string{"source-selection-file", "issuer-private-file", "controller-container"} {
		if code := run(context.Background(), append(append([]string{}, args...), "--"+extra, "forbidden"), &out); code != 2 {
			t.Fatal("cross-action authority admitted", extra, code)
		}
	}
}
