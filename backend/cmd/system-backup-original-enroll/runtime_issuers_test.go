package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeIssuerCLIRejectsMissingOriginalInputsBeforeOutput(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "not-created")
	if code := runRuntimeIssuers(context.Background(), []string{"--mode", "prepare", "--output-directory", dir}, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("missing original inputs created output")
	}
}
