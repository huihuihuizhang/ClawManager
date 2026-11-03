package main

import (
	"bytes"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalMappingActionsRequirePinnedSourceAndDistinctIssuanceMode(t *testing.T) {
	var out bytes.Buffer
	if runOriginalMappingAction(context.Background(), []string{"unknown"}, &out) == 0 || out.Len() != 0 {
		t.Fatal("unknown action accepted")
	}
	file := filepath.Join(t.TempDir(), "source.json")
	if os.WriteFile(file, []byte(`{"Passed":true}`), 0600) != nil {
		t.Fatal("source fixture")
	}
	for _, action := range []string{"catalog-owner-bindings", "issue-original-mapping"} {
		args := []string{action, "--source-file", file, "--source-sha256", strings.Repeat("0", 64)}
		if action == "issue-original-mapping" {
			args = append(args, "--output-directory", t.TempDir())
		}
		if runOriginalMappingAction(context.Background(), args, &out) == 0 || out.Len() != 0 {
			t.Fatal("untrusted original input accepted", action)
		}
	}
	if runEnrolled(context.Background(), []string{"catalog-owner-bindings", "--requirements"}, &out) == 0 {
		t.Fatal("constructor binding inherited unrelated authority action")
	}
}

func TestOriginalMappingActionsKeepExactLargeOriginalMetadataReadBound(t *testing.T) {
	file := filepath.Join(t.TempDir(), "actual-large-private-metadata.json")
	raw := []byte(`{"Payload":"` + strings.Repeat("x", 1<<20) + `"}`)
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("fixture")
	}
	sum := sha256.Sum256(raw)
	var data struct{ Payload string }
	if _, e := readEnrolledActionJSON(file, hex.EncodeToString(sum[:]), 8<<20, &data); e != nil || len(data.Payload) != 1<<20 {
		t.Fatal("original large contract refused before reads", e)
	}
	if _, e := readEnrolledActionBytes(file, 262144); e == nil {
		t.Fatal("unrelated private source bound widened")
	}
	if _, e := readEnrolledActionBytes(file, 9<<20); e == nil {
		t.Fatal("unreviewed larger bound accepted")
	}
	if _, e := readEnrolledActionJSON(file, strings.Repeat("0", 64), 8<<20, &data); e == nil {
		t.Fatal("large metadata SHA mismatch accepted")
	}
}

func TestOriginalMappingIssuanceRequiresCompleteOriginalBindingSetBeforeAuthorityIO(t *testing.T) {
	keys := sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{})
	full := []install.BootstrapOriginalOwnerBinding{}
	for _, key := range keys {
		full = append(full, install.BootstrapOriginalOwnerBinding{Key: key, SHA256: strings.Repeat("a", 64)})
	}
	if validateCompleteOriginalOwnerBindings(full) != nil {
		t.Fatal("complete association data refused")
	}
	withoutCapture := []install.BootstrapOriginalOwnerBinding{}
	for _, b := range full {
		if b.Key != "reference:capture_signing" {
			withoutCapture = append(withoutCapture, b)
		}
	}
	if validateCompleteOriginalOwnerBindings(withoutCapture) != nil {
		t.Fatal("original issuer capture hash insertion refused")
	}
	if validateCompleteOriginalOwnerBindings(nil) == nil || validateCompleteOriginalOwnerBindings(withoutCapture[1:]) == nil {
		t.Fatal("partial association accepted")
	}
	duplicate := append(append([]install.BootstrapOriginalOwnerBinding(nil), full...), full[0])
	if validateCompleteOriginalOwnerBindings(duplicate) == nil {
		t.Fatal("duplicate association accepted")
	}
	foreign := append([]install.BootstrapOriginalOwnerBinding(nil), full...)
	foreign[0].Key = "reference:unknown"
	if validateCompleteOriginalOwnerBindings(foreign) == nil {
		t.Fatal("unknown source accepted")
	}
}
