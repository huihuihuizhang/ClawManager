package install

import (
	"bytes"
	"os"
	"testing"
)

// Linux native filesystem behavior only. No provider/admin/held-writer proof
// is faked by these IO tests, and no copy/adoption execution is asserted.
func TestOriginalArchiveJournalDurableAppendRefusesReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	names := originalArchiveJournalNames("0123456789abcdef0123456789abcdef")
	entry := originalArchiveJournalEntry{Version: originalArchiveJournalVersion, State: "reserved", Name: "original-ciphertext"}
	intent, err := appendOriginalArchiveJournal(root, names[0], entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = appendOriginalArchiveJournal(root, names[0], entry); err == nil {
		t.Fatal("a reserved operation must never overwrite its durable original intent")
	}
	entry.State, entry.PreviousSHA256 = "send_unknown", originalArchiveJournalHash(intent)
	send, err := appendOriginalArchiveJournal(root, names[1], entry)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := readOriginalArchiveJournal(root, names[0]); err != nil || !bytes.Equal(actual, intent) {
		t.Fatal("original intent changed", err)
	}
	if actual, err := readOriginalArchiveJournal(root, names[1]); err != nil || !bytes.Equal(actual, send) {
		t.Fatal("unknown send not independently readable", err)
	}
	if _, err = root.Stat(names[2]); !os.IsNotExist(err) {
		t.Fatal("unknown send must not create a copy-readback record", err)
	}
}

func TestOriginalArchiveJournalRejectsWritableReceipt(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	names := originalArchiveJournalNames("0123456789abcdef0123456789abcdef")
	if _, err = appendOriginalArchiveJournal(root, names[0], originalArchiveJournalEntry{Version: originalArchiveJournalVersion}); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory+string(os.PathSeparator)+names[0], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readOriginalArchiveJournal(root, names[0]); err == nil {
		t.Fatal("writable receipt accepted")
	}
}
