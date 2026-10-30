package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectBeforeOpeningAuthorityDatabase(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown"}, {"extra"}, {"-installation-id", "x", "-server-uuid", "s", "-database", "d"}} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted incomplete owner input %v", args)
		}
	}
}
func TestOwnerFilesAreBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "signature")
	if err := os.WriteFile(p, make([]byte, 65), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := bounded(p, 64); err == nil {
		t.Fatal("oversized signature accepted")
	}
	if _, err := bounded("", 64); err == nil {
		t.Fatal("missing authority file accepted")
	}
}
