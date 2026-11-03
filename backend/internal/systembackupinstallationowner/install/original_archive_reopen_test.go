package install

import (
	"encoding/json"
	"testing"
	"time"
)

func TestOriginalArchiveJournalRecoveryAcceptsExactFrozenWriterFormat(t *testing.T) {
	entry := originalArchiveJournalEntry{Version: originalArchiveJournalVersion, State: "send_unknown", Name: "original.enc", Until: time.Now().UTC().Truncate(time.Microsecond)}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var out originalArchiveJournalEntry
	if decodeOriginalArchiveRecord(raw, &out) != nil || out.State != "send_unknown" {
		t.Fatal("original json.Marshal record rejected")
	}
	if decodeExact(raw, &out) == nil {
		t.Fatal("fixture no longer exposes the frozen writer/JCS mismatch")
	}
	// Parsing never turns an unknown send into a confirmed copy.
	if out.Copy != nil {
		t.Fatal("unknown prefix synthesized copy")
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), ' '), append(raw, raw...), []byte(`{"Version":"x","Version":"y"}`), []byte(`{"unexpected":true}`), raw[:len(raw)-1]} {
		if decodeOriginalArchiveRecord(bad, &out) == nil {
			t.Fatal("ambiguous/rewritten/truncated record accepted")
		}
	}
}
func TestOriginalArchiveReopenRejectsFabricatedHandles(t *testing.T) {
	var r *ReopenedOriginalArchive
	if r.SnapshotRevision() != "" || !r.ValidUntil().IsZero() {
		t.Fatal("nil recovery handle has facts")
	}
	fake := &ReopenedOriginalArchive{}
	if fake.SnapshotRevision() != "" || !fake.ValidUntil().IsZero() {
		t.Fatal("fabricated recovery handle has facts")
	}
}
