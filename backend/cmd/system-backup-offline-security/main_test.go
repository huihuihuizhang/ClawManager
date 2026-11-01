package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	offline "clawreef/internal/systembackupoffline"
)

func TestOfflineCLIUnfilledTemplatesAndSanitizedFailure(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	paths := map[string]string{}
	for _, kind := range []string{"trust", "bundle"} {
		var out bytes.Buffer
		if run([]string{"--template", kind}, &out, now) != 0 {
			t.Fatal("template")
		}
		paths[kind] = filepath.Join(dir, kind+".json")
		if os.WriteFile(paths[kind], out.Bytes(), 0600) != nil {
			t.Fatal("write")
		}
	}
	var out bytes.Buffer
	if run([]string{"--trust", paths["trust"], "--bundle", paths["bundle"]}, &out, now) != 2 {
		t.Fatal(out.String())
	}
	var report offline.Report
	if json.Unmarshal(out.Bytes(), &report) != nil || report.ProductionReady || report.Status != "incomplete" {
		t.Fatal(out.String())
	}
	for _, args := range [][]string{{"--trust", filepath.Join(dir, "do-not-print-secret-path"), "--bundle", paths["bundle"]}, {"--apply"}, {"--trust", `\\server\share\credentials`, "--bundle", paths["bundle"]}} {
		out.Reset()
		if run(args, &out, now) != 1 || strings.Contains(out.String(), "do-not-print") || strings.Contains(out.String(), "server") {
			t.Fatal(out.String())
		}
	}
}
func TestOfflineCLIRefusesDuplicateUnknownAndSymlinkInput(t *testing.T) {
	dir := t.TempDir()
	trust, bundle := offline.Templates()
	a, _ := json.Marshal(trust)
	b, _ := json.Marshal(bundle)
	tp, bp := filepath.Join(dir, "trust.json"), filepath.Join(dir, "bundle.json")
	if os.WriteFile(tp, a, 0600) != nil || os.WriteFile(bp, b, 0600) != nil {
		t.Fatal("write")
	}
	for _, bad := range [][]byte{[]byte(`{"Protocol":"x","Protocol":"y"}`), []byte(`{"credential":"never-print-this"}`)} {
		if os.WriteFile(bp, bad, 0600) != nil {
			t.Fatal("write")
		}
		var out bytes.Buffer
		if run([]string{"--trust", tp, "--bundle", bp}, &out, time.Now()) != 1 || strings.Contains(out.String(), "never-print") {
			t.Fatal(out.String())
		}
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(tp, link); err == nil {
		if _, err = localRead(link); err == nil {
			t.Fatal("symlink read")
		}
	}
}
