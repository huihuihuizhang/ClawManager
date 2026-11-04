package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginalReadproofPhasesRejectForeignDatabaseBeforeConnecting(t *testing.T) {
	directory := t.TempDir()
	inventory := filepath.Join(directory, "inventory.json")
	dsn := filepath.Join(directory, "dsn")
	if e := os.WriteFile(inventory, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"original-before", "original-after"} {
		for _, database := range []string{"cm_import_0123456789abcdef0123456789abcdef", "clawmanager_other"} {
			t.Run(phase+"/"+database, func(t *testing.T) {
				if e := os.WriteFile(dsn, []byte("root:TEST_ONLY@tcp(127.0.0.1:1)/"+database), 0600); e != nil {
					t.Fatal(e)
				}
				e := runPhase(context.Background(), dsn, inventory, phase, io.Discard)
				if e == nil || e.Error() != "legacy original readproof requires original database" {
					t.Fatal("foreign original target not rejected before native I/O", e)
				}
			})
		}
	}
}
