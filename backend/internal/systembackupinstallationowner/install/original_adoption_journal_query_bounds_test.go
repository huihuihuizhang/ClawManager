package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOriginalAdoptionJournalQueryRetainsTwoMiBBound(t *testing.T) {
	for _, size := range []int{300000, (2 << 20) + 1} {
		name := "above_generic_input_limit"
		if size > 2<<20 {
			name = "above_original_journal_limit"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			op := strings.Repeat("a", 32)
			data, _ := json.Marshal(strings.Repeat("x", size))
			first := originalWriterJournalRecord{Version: originalWriterJournalVersion, Operation: op, InventorySHA256: strings.Repeat("b", 64), Sequence: 1, Data: data}
			raw, _ := json.Marshal(first)
			if err := os.WriteFile(filepath.Join(directory, "original-writers-"+op+"-00000001.json"), raw, 0400); err != nil {
				t.Fatal(err)
			}
			got, _, err := originalJournalCoordinates(directory)
			if size == 300000 {
				if len(raw) <= 262144 || err != nil || got != op {
					t.Fatal("valid original journal above generic input limit rejected")
				}
			} else if err == nil {
				t.Fatal("oversized original journal accepted")
			}
		})
	}
}

func TestOriginalAdoptionJournalQueryRejectsForeignFirstFormat(t *testing.T) {
	for _, fault := range []string{"version", "sequence"} {
		t.Run(fault, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			op := strings.Repeat("a", 32)
			record := originalWriterJournalRecord{Version: originalWriterJournalVersion, Operation: op, InventorySHA256: strings.Repeat("b", 64), Sequence: 1}
			if fault == "version" {
				record.Version = "foreign"
			} else {
				record.Sequence = 2
			}
			b, _ := json.Marshal(record)
			if err := os.WriteFile(filepath.Join(d, "original-writers-"+op+"-00000001.json"), b, 0400); err != nil {
				t.Fatal(err)
			}
			if _, _, err := originalJournalCoordinates(d); err == nil {
				t.Fatal("foreign journal first record accepted")
			}
		})
	}
}

func TestOriginalAdoptionJournalQueryRejectsLinkedFirstRecord(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux link and file ownership")
	}
	d := t.TempDir()
	outside := t.TempDir()
	op := strings.Repeat("a", 32)
	record := originalWriterJournalRecord{Version: originalWriterJournalVersion, Operation: op, InventorySHA256: strings.Repeat("b", 64), Sequence: 1}
	b, _ := json.Marshal(record)
	source := filepath.Join(outside, "first.json")
	if err := os.WriteFile(source, b, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, filepath.Join(d, "original-writers-"+op+"-00000001.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := originalJournalCoordinates(d); err == nil {
		t.Fatal("linked first record accepted")
	}
}
