package staging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestOpenFileGuardedStopsLargeHashAndRetainsExactHandle(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	body := bytes.Repeat([]byte("opaque C DATA"), 40000)
	receipt, err := WriteUnpublishedFile(context.Background(), root, "guarded.enc", func(dst io.Writer) error { _, err := dst.Write(body); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "revoked-in-hash", "revoked-at-end", "nil-guard", "cancelled-before", "cancelled-in-guard", "cancelled-in-hash", "cancelled-at-end"} {
		t.Run(mode, func(t *testing.T) {
			checks := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled-before" {
				cancel()
			}
			guard := func(context.Context) error {
				checks++
				if mode == "cancelled-in-guard" || mode == "cancelled-in-hash" && checks >= 3 || mode == "cancelled-at-end" && checks >= 7 {
					cancel()
				}
				if mode == "revoked-in-hash" && checks >= 3 {
					return errors.New("revoked")
				}
				if mode == "revoked-at-end" && checks >= 7 {
					return errors.New("revoked")
				}
				return nil
			}
			if mode == "nil-guard" {
				guard = nil
			}
			file, err := OpenFileGuarded(ctx, root, receipt, guard)
			if mode != "current" {
				if file != nil {
					file.Close()
					t.Fatal("revoked hash returned file")
				}
				if err == nil {
					t.Fatal("missing current check accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got, err := io.ReadAll(file)
			if err != nil || !bytes.Equal(body, got) || checks < 5 {
				t.Fatal("guarded pinned file lost bytes/checks", err, checks)
			}
		})
	}
}
