package install

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOriginalArchivePrivateInputActualReadAndBounds(t *testing.T) {
	for _, name := range []string{"provider-definition", "provider-recheck", "native-plan"} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), name+".json")
			body := []byte(`{"original":"private input"}`)
			if err := os.WriteFile(file, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadPrivateFile(file, 1<<20); err == nil {
				t.Fatal("old out-of-contract limit unexpectedly accepted")
			}
			actual, err := readOriginalArchivePrivateFile(file)
			if err != nil || !bytes.Equal(actual, body) {
				t.Fatal("actual private input still refused", err)
			}
			clear(actual)
		})
	}
	for _, size := range []int{0, 262144, 262145} {
		file := filepath.Join(t.TempDir(), "bounded-private-input")
		if err := os.WriteFile(file, bytes.Repeat([]byte{'x'}, size), 0600); err != nil {
			t.Fatal(err)
		}
		raw, err := readOriginalArchivePrivateFile(file)
		if size == 262144 {
			if err != nil || len(raw) != size {
				t.Fatal("exact original bound refused", err)
			}
		} else if err == nil || raw != nil {
			t.Fatal("empty/oversized file accepted")
		}
		clear(raw)
	}
}

func TestOriginalArchivePrivateInputKeepsOriginalRefusals(t *testing.T) {
	file := filepath.Join(t.TempDir(), "original-private-input")
	if err := os.WriteFile(file, []byte("private-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"relative-input", filepath.Join(t.TempDir(), "missing")} {
		if raw, err := readOriginalArchivePrivateFile(name); err == nil || raw != nil || strings.Contains(err.Error(), name) {
			t.Fatal("missing/relative input accepted or path leaked")
		}
	}
	if runtime.GOOS == "linux" {
		if os.Chmod(file, 0644) != nil {
			t.Fatal("chmod")
		}
		if raw, err := readOriginalArchivePrivateFile(file); err == nil || raw != nil {
			t.Fatal("public-readable private input accepted")
		}
		if os.Chmod(file, 0600) != nil {
			t.Fatal("chmod")
		}
		link := filepath.Join(t.TempDir(), "alias")
		if os.Symlink(file, link) != nil {
			t.Fatal("symlink fixture")
		}
		if raw, err := readOriginalArchivePrivateFile(link); err == nil || raw != nil {
			t.Fatal("symlink input accepted")
		}
	}
}
