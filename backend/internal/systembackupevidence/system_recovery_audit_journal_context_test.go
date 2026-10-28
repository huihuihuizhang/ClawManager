package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Freeze the first successful context check so cancellation deterministically
// arrives after admission, before attempting the occupied writer lock.
type journalCheckedContext struct {
	context.Context
	once             sync.Once
	checked, release chan struct{}
}

func (c *journalCheckedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked); <-c.release })
	return err
}

type journalQueuedContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *journalQueuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func journalAuthorityRecord(n int) RecoveryAuthorityExternalAuditRecord {
	return RecoveryAuthorityExternalAuditRecord{Stage: "intent", DecisionSHA256: fmt.Sprintf("%064x", n+1), RequestHash: fmt.Sprintf("%064x", n+2), ManagerIdentityHash: fmt.Sprintf("%064x", n+3)}
}

func journalResultWhileLocked(t *testing.T, unlock func(), done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		// Always release and join the writer, including counterfactual runs.
		unlock()
		select {
		case err := <-done:
			t.Error("canceled/failed journal waited for another writer")
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("journal writer did not finish after release")
			return nil
		}
	}
}

func TestRecoveryAuditJournalCanceledQueue(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			storage := failureJournalFixture(t)
			j := storage.journal
			j.mu.Lock()
			var unlockOnce sync.Once
			unlock := func() { unlockOnce.Do(j.mu.Unlock) }
			defer unlock()
			var base context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				base, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
			} else {
				base, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			var ctx context.Context
			var waiting <-chan struct{}
			release := func() {}
			if mode == "deadline" {
				checked := &journalCheckedContext{Context: base, checked: make(chan struct{}), release: make(chan struct{})}
				ctx, waiting = checked, checked.checked
				release = func() { close(checked.release) }
			} else {
				queued := &journalQueuedContext{Context: base, waiting: make(chan struct{})}
				ctx, waiting = queued, queued.waiting
			}
			done := make(chan error, 1)
			go func() { done <- j.AppendRecoveryAuthorityAudit(ctx, journalAuthorityRecord(0)) }()
			select {
			case <-waiting:
			case <-time.After(time.Second):
				cancel()
				release()
				unlock()
				<-done
				t.Fatal("journal writer did not enter cancellable wait")
			}
			if mode == "deadline" {
				<-base.Done()
			} else {
				cancel()
			}
			release()
			if err := journalResultWhileLocked(t, unlock, done); err != ErrUnavailable {
				t.Fatal("canceled queue acknowledged a write", err)
			}
			if raw, err := os.ReadFile(storage.config.Path); err != nil || len(raw) != 0 {
				t.Fatal("canceled queued writer changed file", err)
			}
			unlock()
			// Abandoning a queue without touching IO does not damage a healthy
			// recovery audit journal. Failure wrappers retain their own latch.
			if err := j.AppendRecoveryAuthorityAudit(context.Background(), journalAuthorityRecord(1)); err != nil {
				t.Fatal("healthy writer could not continue", err)
			}
		})
	}
}

func TestFailureJournalsPoisonWithoutWaiting(t *testing.T) {
	for _, mode := range []string{"download_cancel", "download_private", "gc_cancel", "gc_private"} {
		t.Run(mode, func(t *testing.T) {
			storage := failureJournalFixture(t)
			j := storage.journal
			j.mu.Lock()
			var once sync.Once
			unlock := func() { once.Do(j.mu.Unlock) }
			defer unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "download_cancel" || mode == "gc_cancel" {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				if mode == "download_cancel" || mode == "download_private" {
					code := ErrUnavailable.Error()
					if mode == "download_private" {
						code = "PRIVATE provider error"
					}
					done <- storage.Append(ctx, journalEvidence, code)
				} else {
					gc := &gcFailureJournal{storage: storage, operation: "sop_11111111-2222-4333-8444-555555555555", principal: fmt.Sprintf("%064x", 1)}
					code := "evidence_incomplete"
					if mode == "gc_private" {
						code = "PRIVATE claim"
					}
					done <- gc.append(ctx, journalEvidence, code)
				}
			}()
			if err := journalResultWhileLocked(t, unlock, done); err != ErrUnavailable {
				t.Fatal("invalid failure acknowledged", err)
			}
			unlock()
			if storage.Check() == nil || storage.Append(context.Background(), journalEvidence, ErrUnavailable.Error()) == nil {
				t.Fatal("failure latch revived after writer released")
			}
			if raw, err := os.ReadFile(storage.config.Path); err != nil || len(raw) != 0 {
				t.Fatal("invalid/private failure reached file", err)
			}
		})
	}
}

func TestRecoveryAuditJournalConcurrentCompleteRecords(t *testing.T) {
	storage := failureJournalFixture(t)
	storage.journal.maxBytes = 16384
	const writers = 8
	results := make(chan error, writers)
	for n := 0; n < writers; n++ {
		go func(n int) {
			results <- storage.journal.AppendRecoveryAuthorityAudit(context.Background(), journalAuthorityRecord(n))
		}(n)
	}
	for n := 0; n < writers; n++ {
		if err := <-results; err != nil {
			t.Fatal("healthy concurrent write rejected", err)
		}
	}
	raw, err := os.ReadFile(storage.config.Path)
	if err != nil || bytes.Count(raw, []byte{'\n'}) != writers {
		t.Fatal("concurrent records lost framing", err)
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var entry recoveryAuditJournalEntry
		if json.Unmarshal(line, &entry) != nil || entry.Kind != "authority_change" || entry.Authority == nil || seen[entry.Authority.DecisionSHA256] {
			t.Fatal("lost, partial or duplicated concurrent record")
		}
		seen[entry.Authority.DecisionSHA256] = true
	}
	if len(seen) != writers || int64(len(raw)) != storage.journal.size {
		t.Fatal("journal size and complete records disagree")
	}
}

func TestRecoveryAuditJournalPoisonDeniesBeforeQueue(t *testing.T) {
	storage := failureJournalFixture(t)
	j := storage.journal
	j.mu.Lock()
	var once sync.Once
	unlock := func() { once.Do(j.mu.Unlock) }
	defer unlock()
	j.poisoned.Store(true)
	done := make(chan error, 1)
	go func() { done <- j.AppendRecoveryAuthorityAudit(context.Background(), journalAuthorityRecord(0)) }()
	if err := journalResultWhileLocked(t, unlock, done); err != ErrUnavailable {
		t.Fatal("poisoned queue accepted a writer", err)
	}
	if raw, err := os.ReadFile(storage.config.Path); err != nil || len(raw) != 0 {
		t.Fatal("poisoned journal changed file", err)
	}
}
