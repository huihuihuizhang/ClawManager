package install

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// A diagnostic can legitimately own prep.mu without set.mu (SQLCensus and
// CheckControls do so). Inspection must wait for that mutex before reading
// prep.used/context/cap through sourceSet.local. This fixture creates no genuine
// source/holder/coverage and only verifies the shared state synchronization.
func TestOriginalHistoryInspectionWaitsForPreparationMutex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prep := &PreparedOriginalAdoptionSQLCut{}
	set := &PreparedOriginalWriterSet{}
	hold := &OriginalWriterHold{set: set}
	sources := &originalHistorySourceSet{prep: prep}
	sources.origin = sources
	coverage := &PreparedOriginalAdoptionCoverage{hold: hold, sourceSet: sources}
	coverage.origin = coverage
	prep.mu.Lock()
	locked := true
	defer func() {
		if locked {
			prep.mu.Unlock()
		}
	}()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); _, err := coverage.OriginalHistoryInspection(ctx); done <- err }()
	<-started
	for {
		select {
		case <-done:
			t.Fatal("inspection returned without waiting for the preparation mutex")
		case <-ctx.Done():
			t.Fatal("inspection never acquired the original set mutex")
		default:
		}
		if !set.mu.TryLock() {
			break
		}
		set.mu.Unlock()
		runtime.Gosched()
	}
	select {
	case <-done:
		t.Fatal("inspection read preparation without taking its mutex")
	case <-time.After(20 * time.Millisecond):
	}
	prep.mu.Unlock()
	locked = false
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("zero owners produced an inspection")
		}
	case <-ctx.Done():
		t.Fatal("inspection did not resume after preparation unlock")
	}
}
