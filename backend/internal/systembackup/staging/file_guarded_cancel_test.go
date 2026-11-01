package staging

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

// Owned opaque DATA only. A claim callback is deliberately context-unaware;
// cancellation remains an independent requirement of the file API itself.
func TestSupervisorGuardedFileCannotIgnoreContextCancellation(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	body := bytes.Repeat([]byte("opaque existing C DATA"), 30000)
	receipt, err := WriteUnpublishedFile(context.Background(), root, "original.enc", func(dst io.Writer) error { _, e := dst.Write(body); return e })
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"before-entry", "during-hash"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "before-entry" {
				cancel()
			}
			checks := 0
			guard := func(context.Context) error {
				checks++
				if mode == "during-hash" && checks == 3 {
					cancel()
				}
				return nil
			}
			file, err := OpenFileGuarded(ctx, root, receipt, guard)
			if file != nil {
				file.Close()
			}
			if ctx.Err() == nil {
				t.Fatal("cancellation fault was not delivered")
			}
			if err == nil || file != nil {
				t.Fatalf("cancelled %s hash returned a usable pinned file, guard checks=%d", mode, checks)
			}
		})
	}
}
