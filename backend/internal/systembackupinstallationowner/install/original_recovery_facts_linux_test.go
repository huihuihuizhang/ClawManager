//go:build linux

package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Actual custody file operations; no SQL/Kube/native-process validation claim.
func TestOriginalRecoveryMutationClosureActualCustody(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	j := &originalWriterJournal{root: root, directory: dir, directoryIdentity: info, operation: strings.Repeat("a", 32), inventory: strings.Repeat("b", 64)}
	ctx := context.Background()
	sequence, digest, err := j.appendReceipt(ctx, "writer", "stop_send_unknown", nil, struct{ UID, RV string }{"actual-pod", "original-rv"})
	if err != nil || sequence != 1 {
		t.Fatal("durable intent", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("original-writers-%s-%08d.json", j.operation, sequence)))
	if err != nil || hash(raw) != digest {
		t.Fatal("receipt is not the actual file digest", err)
	}
	if err := j.append(ctx, "writer", "original_state_restored", nil, nil); err != nil {
		t.Fatal(err)
	}
	boundary, err := j.closeOriginalSourceMutations(ctx)
	if err != nil || boundary.lastMutation != 1 || boundary.sequence != 2 || boundary.recheckLocal() != nil {
		t.Fatal("closure", err)
	}
	for _, action := range []string{"scale_zero_send_unknown", "restore_replicas_send_unknown", "delete_original_pod_send_unknown", "create_original_pod_send_unknown", "cancel_delayed_pod_delete_send_unknown", "stop_send_unknown", "resume_send_unknown", "complete_send_unknown", "keep_stopped_complete_send_unknown", "source_binding_commit_unknown"} {
		t.Run(action, func(t *testing.T) {
			before := j.sequence
			if j.append(ctx, "writer", action, nil, nil) == nil || j.sequence != before || boundary.recheckLocal() != nil {
				t.Fatal("source dispatch crossed closure")
			}
		})
	}
	if err := j.append(ctx, "writer", "native_node_recovered", nil, struct{ ActualObservation string }{"bounded-native-receipt"}); err != nil {
		t.Fatal(err)
	}
	if boundary.recheckLocal() != nil {
		t.Fatal("read-only observation invalidated closure")
	}
	again, err := j.closeOriginalSourceMutations(ctx)
	if err != nil || again.epoch != boundary.epoch || again.lastMutation != boundary.lastMutation {
		t.Fatal("retry reopened mutation authority", err)
	}
	// Even after later immutable records, appendReceipt remains the first file's
	// exact digest rather than a mutable global 'tail' read after the call.
	if hash(raw) != digest || digest == j.tail {
		t.Fatal("receipt rebound to later record")
	}
	j.mu.Lock()
	j.lastSourceMutation++
	j.mu.Unlock()
	if boundary.recheckLocal() == nil {
		t.Fatal("local mutation sequence drift accepted")
	}
}

func TestOriginalRecoveryClosureRejectsActualJournalDrift(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("mode")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	j := &originalWriterJournal{root: root, directory: dir, directoryIdentity: info, operation: strings.Repeat("c", 32), inventory: strings.Repeat("d", 64)}
	ctx := context.Background()
	if j.append(ctx, "writer", "stop_send_unknown", nil, nil) != nil {
		t.Fatal("write")
	}
	file := filepath.Join(dir, fmt.Sprintf("original-writers-%s-%08d.json", j.operation, 1))
	if os.Chmod(file, 0600) != nil || os.WriteFile(file, []byte("truncated"), 0400) != nil || os.Chmod(file, 0400) != nil {
		t.Fatal("fixture corruption")
	}
	if boundary, err := j.closeOriginalSourceMutations(ctx); err == nil || boundary != nil || j.recoveryClosed {
		t.Fatal("corrupt custody minted closure")
	}
}
