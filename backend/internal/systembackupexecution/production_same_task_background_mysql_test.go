package systembackupexecution

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A separate observation negative, before this fixture task ever acquires its
// gate. Actual writers establish all counters; an actual file writer then runs
// again. Restoring its file bytes simulates ABA but cannot erase that write's
// monotonic counter. This does not mark a formal capture or held gate complete.
func TestOriginalBackgroundObservationRejectsActualWriteEvenAfterFileABA(t *testing.T) {
	f := newDOriginalSixPartTask(t)
	ctx, cancel := context.WithDeadline(context.Background(), f.input.Authority.DeadlineAt)
	defer cancel()
	f.startOriginalBackground(ctx, t)
	f.background.stopAll()
	if err := f.background.checkHeld(ctx); err != nil {
		t.Fatal("healthy stopped observation", err)
	}
	id := "d-original-7"
	path := f.background.sourceFile(id)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := f.background.counters[id].Load()
	f.background.start(id)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for f.background.counters[id].Load() == before {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("actual original file writer did not write")
		case <-tick.C:
		}
	}
	f.background.stop(id)
	changed, err := os.ReadFile(path)
	if err != nil || bytes.Equal(changed, original) || f.background.counters[id].Load() <= before {
		t.Fatal("no actual writer/file change observed", err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatal("ABA file bytes were not restored", err)
	}
	if err := f.background.checkHeld(ctx); err == nil || !strings.Contains(err.Error(), "successful write counter changed") {
		t.Fatal("actual write was hidden by ABA file bytes", err)
	}
}
