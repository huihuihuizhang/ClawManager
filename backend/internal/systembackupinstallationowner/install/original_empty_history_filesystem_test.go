package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginalEmptyHistoryFilesystemActualEOFAndRecheck(t *testing.T) {
	path := t.TempDir()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	observed, err := observeEmptyOriginalHistoryRoot(context.Background(), root)
	if err != nil || observed.recheck(context.Background()) != nil {
		t.Fatal("actual empty EOF refused", err)
	}
	if _, err := json.Marshal(observed); err == nil {
		t.Fatal("filesystem capability serialized")
	}
	copy := *observed
	if copy.recheck(context.Background()) == nil {
		t.Fatal("copied opaque observation accepted")
	}
	if err = os.WriteFile(filepath.Join(path, "unknown-original-version"), []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if observed.recheck(context.Background()) == nil {
		t.Fatal("new historical member accepted as empty")
	}
	if err = os.Remove(filepath.Join(path, "unknown-original-version")); err != nil {
		t.Fatal(err)
	}
	if observed.recheck(context.Background()) == nil {
		t.Fatal("failed observation resurrected after removal")
	}
}

func TestOriginalEmptyHistoryFilesystemRejectsUnclassifiedEntries(t *testing.T) {
	for _, kind := range []string{"file", "directory", "control-looking-name"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			if kind == "directory" {
				if os.Mkdir(filepath.Join(path, "unknown"), 0700) != nil {
					t.Fatal("fixture mkdir")
				}
			} else {
				name := "unknown"
				if kind == "control-looking-name" {
					name = ".controller-seals"
				}
				if os.WriteFile(filepath.Join(path, name), nil, 0600) != nil {
					t.Fatal("fixture write")
				}
			}
			root, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if observed, err := observeEmptyOriginalHistoryRoot(context.Background(), root); err == nil || observed != nil {
				t.Fatal("unknown member ignored")
			}
		})
	}
}

func TestOriginalEmptyHistoryFilesystemRejectsMissingContextAndWrongRoot(t *testing.T) {
	if _, err := observeEmptyOriginalHistoryRoot(context.Background(), nil); err == nil {
		t.Fatal("missing root treated as empty")
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = observeEmptyOriginalHistoryRoot(nil, root); err == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = observeEmptyOriginalHistoryRoot(ctx, root); err == nil {
		t.Fatal("cancelled context")
	}
	observed, err := observeEmptyOriginalHistoryRoot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	observed.root = other
	if observed.recheck(context.Background()) == nil {
		t.Fatal("different root identity accepted")
	}
	other.Close()
	if _, err = observeEmptyOriginalHistoryRoot(context.Background(), other); err == nil {
		t.Fatal("closed root treated as empty")
	}
}
