//go:build linux

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
)

// Filesystem-only regression. This does not claim Installer authentication,
// native lifecycle, full holder, first adoption, or production SQL validation.
func TestOriginalWriterJournalActualWriteCloseReopen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("a", 32)
	inventory := strings.Repeat("b", 64)
	directoryIdentity, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	j := &originalWriterJournal{root: root, operation: op, inventory: inventory, directory: dir, directoryIdentity: directoryIdentity}
	s := flow.State{UID: "original-pod", Generation: 7, Running: true, Checkpoint: "original-checkpoint"}
	if err = j.append(ctx, "writer/1", "stop_send_unknown", &s, []byte(`actual-intent-only`)); err != nil {
		t.Fatal(err)
	}
	if err = j.append(ctx, "writer/1", "native_stopped", &s, struct{ Raw []byte }{[]byte(`actual-native-response`)}); err != nil {
		t.Fatal(err)
	}
	wantTail := j.tail
	if err = j.close(); err != nil {
		t.Fatal(err)
	}
	// New handle/process identity; no in-memory tail or original pointer reused.
	fresh, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	newJournal := &originalWriterJournal{root: fresh, directory: dir, directoryIdentity: directoryIdentity}
	got, err := newJournal.inspect(ctx, op, inventory)
	if err != nil || len(got.Records) != 2 || got.TailSHA256 != wantTail || got.Records[0].Action != "stop_send_unknown" || *got.Records[0].Original != s {
		t.Fatalf("real journal reopen: %v", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("original-writers-%s-%08d.json", op, 2))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record originalWriterJournalRecord
	if json.Unmarshal(original, &record) != nil {
		t.Fatal("fixture")
	}
	tests := map[string][]byte{
		"duplicate": bytes.Replace(original, []byte(`"Version":`), []byte(`"Action":"native_stopped","Version":`), 1),
		"unknown":   append(append([]byte(nil), original[:len(original)-1]...), []byte(`,"Unknown":true}`)...),
		"truncated": original[:len(original)-1],
		"reordered": append(append([]byte(`{"Action":"native_stopped",`), bytes.Replace(original[1:], []byte(`"Action":"native_stopped",`), nil, 1)...)),
	}
	broken := record
	broken.PreviousSHA256 = strings.Repeat("c", 64)
	tests["broken_chain"], _ = json.Marshal(broken)
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := newJournal.inspect(ctx, op, inventory); err == nil {
				t.Fatal("corrupted journal accepted")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, original, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("missing_sequence_retains_unknown", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		got, err := newJournal.inspect(ctx, op, inventory)
		if err != nil || len(got.Records) != 1 || got.Records[0].Action != "stop_send_unknown" {
			t.Fatal("unknown intent lost")
		}
		third := filepath.Join(dir, fmt.Sprintf("original-writers-%s-%08d.json", op, 3))
		if err := os.WriteFile(third, original, 0400); err != nil {
			t.Fatal(err)
		}
		if _, err := newJournal.inspect(ctx, op, inventory); err == nil {
			t.Fatal("gap accepted")
		}
	})
}
