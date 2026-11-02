package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestOwnerAuthorityCLIGenerateIssuerLocalOnly(t *testing.T) {
	directory := t.TempDir()
	var out bytes.Buffer
	if run(context.Background(), []string{"generate-issuer", "--output-directory", directory}, &out) != 0 {
		t.Fatal("standalone generation required external inputs")
	}
	var result install.GeneratedIssuer
	if json.Unmarshal(out.Bytes(), &result) != nil || result.PrivateFile != filepath.Join(directory, "issuer.private") || result.PublicFile != filepath.Join(directory, "issuer.public") || len(result.PublicKeySHA256) != 64 || result.Status != "local_issuer_created_unenrolled" {
		t.Fatal("public generation receipt")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &fields) != nil || len(fields) != 4 {
		t.Fatal("unexpected material in public receipt")
	}
	out.Reset()
	if run(context.Background(), []string{"generate-issuer", "--output-directory", directory}, &out) != 1 || out.Len() != 0 {
		t.Fatal("existing key overwritten or successful receipt emitted")
	}
	for _, args := range [][]string{{"generate-issuer"}, {"generate-issuer", "--output-directory", directory, "--enroll"}, {"generate-issuer", "--output-directory", directory, "--issuer-private-file", "foreign"}} {
		if run(context.Background(), args, &out) != 2 || out.Len() != 0 {
			t.Fatal("generation accepted enrollment/import/key bypass")
		}
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) != 2 {
		t.Fatal("generation wrote extra files", e)
	}
}
