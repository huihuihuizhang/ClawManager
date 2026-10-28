package systembackupevidence

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type gcInputRegistry struct {
	ids    []string
	before func(int)
}

func (*gcInputRegistry) PersistPending(context.Context, Record) error { return ErrDenied }
func (r *gcInputRegistry) WithLocked(_ context.Context, id string, _ func(Locked) error) error {
	r.ids = append(r.ids, id)
	if r.before != nil {
		r.before(len(r.ids))
	}
	return ErrDenied
}

// Exercise the actual public batch entry, Service.GC/collect and real journal.
// Mutation is sequential, inside a callback: no concurrent slice access or
// driver/remote cleanup guarantee is implied by these tests.
func TestGCRuntimeFreezesBatchInputs(t *testing.T) {
	for _, channel := range []string{"callback", "journal"} {
		for _, mutation := range []string{"none", "valid_ids", "invalid_ids"} {
			t.Run(channel+"/"+mutation, func(t *testing.T) {
				original := []string{journalEvidence, "sev_22222222-3333-4444-8555-666666666666"}
				ids := append([]string(nil), original...)
				registry := &gcInputRegistry{}
				if mutation != "none" {
					registry.before = func(n int) {
						if n == 1 {
							ids[0], ids[1] = "sev_aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "sev_bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
							if mutation == "invalid_ids" {
								ids[0], ids[1] = "PRIVATE invalid first", "PRIVATE invalid second"
							}
						}
					}
				}
				var signals []string
				runtime := &GCRuntime{service: Service{Registry: registry, Store: &testStore{}, Failure: func(ctx context.Context, id, code string) {
					if ctx.Err() != nil || code != "evidence_incomplete" {
						t.Fatal("failure signal lost its independent budget or classification")
					}
					signals = append(signals, id)
				}}}
				var journalPath string
				if channel == "journal" {
					config := failureJournalConfig(t)
					storage, err := NewDownloadFailureJournal(config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { storage.Close() })
					journalPath = config.Path
					runtime.journal = &gcFailureJournal{storage: storage, operation: "sop_11111111-2222-4333-8444-555555555555", principal: strings.Repeat("a", 64)}
				}
				results := runtime.GC(context.Background(), ids)
				if !reflect.DeepEqual(results, []error{ErrDenied, ErrDenied}) || !reflect.DeepEqual(registry.ids, original) {
					t.Fatalf("callback replaced the selected batch: visited=%v results=%v", registry.ids, results)
				}
				if mutation != "none" && reflect.DeepEqual(ids, original) {
					t.Fatal("negative control did not mutate caller input")
				}
				if channel == "journal" {
					if len(signals) != 0 || runtime.CheckFailurePersistence() != nil {
						t.Fatal("journal path bypassed persistence or poisoned valid records")
					}
					raw, err := os.ReadFile(journalPath)
					if err != nil {
						t.Fatal(err)
					}
					for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
						var entry recoveryAuditJournalEntry
						if json.Unmarshal([]byte(line), &entry) != nil || entry.Kind != "evidence_gc_failure" || entry.GC == nil {
							t.Fatal("invalid durable GC failure")
						}
						signals = append(signals, entry.GC.EvidenceID)
					}
				}
				if !reflect.DeepEqual(signals, original) {
					t.Fatalf("failure signal rebound to caller's changed IDs: got=%v want=%v", signals, original)
				}
			})
		}
	}
}

func TestGCRuntimeFailureCallbackCannotReplaceLaterSignal(t *testing.T) {
	original := []string{journalEvidence, "sev_22222222-3333-4444-8555-666666666666"}
	ids := append([]string(nil), original...)
	registry := &gcInputRegistry{}
	var signals []string
	runtime := &GCRuntime{service: Service{Registry: registry, Store: &testStore{}, Failure: func(_ context.Context, id, _ string) {
		signals = append(signals, id)
		ids[1] = "sev_bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	}}}
	results := runtime.GC(context.Background(), ids)
	if !reflect.DeepEqual(results, []error{ErrDenied, ErrDenied}) || !reflect.DeepEqual(registry.ids, original) || !reflect.DeepEqual(signals, original) {
		t.Fatal("failure callback rebound a later result", registry.ids, signals, results)
	}
}
