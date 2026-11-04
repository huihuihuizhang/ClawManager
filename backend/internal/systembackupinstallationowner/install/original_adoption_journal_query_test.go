package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reg "clawreef/internal/systembackupkekregistry"
)

func TestOriginalAdoptionJournalQueryExpectations(t *testing.T) {
	pin := BootstrapSourceFilePin{File: "/private/original-selection.json", SHA256: strings.Repeat("a", 64)}
	for _, fault := range []string{"none", "foreign_selection", "duplicate_commit", "wrong_operation", "wrong_epoch", "missing_control_row", "wrong_database"} {
		t.Run(fault, func(t *testing.T) {
			expected := originalAdoptionCommitExpected{Version: "original-adoption-commit-expectation.v1", Operation: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64), InstallationID: "original", ServerUUID: "server", Database: "clawmanager", OldEpoch: 3, NewEpoch: 4, Sources: make([]reg.CoverageSource, 4), References: []reg.Reference{}, Bindings: []reg.BindingFacts{}, ControlRows: map[string]string{}}
			for n := 0; n < 17; n++ {
				expected.ControlRows[fmt.Sprint(n)] = strings.Repeat("d", 64)
			}
			journal := OriginalWriterJournalInspection{Operation: expected.Operation, InventorySHA256: expected.InventorySHA256}
			selected := pin
			switch fault {
			case "foreign_selection":
				selected.SHA256 = strings.Repeat("e", 64)
			case "wrong_operation":
				expected.Operation = strings.Repeat("f", 32)
			case "wrong_epoch":
				expected.NewEpoch++
			case "missing_control_row":
				delete(expected.ControlRows, "0")
			case "wrong_database":
				expected.Database = "foreign"
			}
			prepared, _ := json.Marshal(struct{ Selection BootstrapSourceFilePin }{selected})
			commit, _ := json.Marshal(expected)
			journal.Records = []originalWriterJournalRecord{{Action: "prepared_original_complete_set", Data: prepared}, {Action: "adoption_commit_send_unknown", Data: commit}}
			if fault == "duplicate_commit" {
				journal.Records = append(journal.Records, journal.Records[1])
			}
			got, err := originalJournalCommitExpected(journal, pin, "original", "server", "clawmanager")
			if fault == "none" {
				if err != nil || got.Operation != journal.Operation {
					t.Fatal("original expectation refused")
				}
			} else if err == nil {
				t.Fatal("foreign or incomplete expectation admitted")
			}
		})
	}
}

func TestOriginalAdoptionJournalQueryFindsOnlyOneRetainedOperation(t *testing.T) {
	for _, fault := range []string{"none", "multiple_operations", "malformed_first_record", "no_original_first_record"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			operation := strings.Repeat("a", 32)
			first := originalWriterJournalRecord{Version: originalWriterJournalVersion, Operation: operation, InventorySHA256: strings.Repeat("b", 64), Sequence: 1}
			raw, _ := json.Marshal(first)
			name := "original-writers-" + operation + "-00000001.json"
			if fault == "malformed_first_record" {
				raw = []byte("{partial")
			}
			if fault == "no_original_first_record" {
				name = "ordinary-output.json"
			}
			if err := os.WriteFile(filepath.Join(directory, name), raw, 0400); err != nil {
				t.Fatal(err)
			}
			if fault == "multiple_operations" {
				if err := os.WriteFile(filepath.Join(directory, "original-writers-"+strings.Repeat("c", 32)+"-00000001.json"), raw, 0400); err != nil {
					t.Fatal(err)
				}
			}
			got, inventory, err := originalJournalCoordinates(directory)
			if fault == "none" {
				if err != nil || got != operation || inventory != first.InventorySHA256 {
					t.Fatal("retained operation not derived")
				}
			} else if err == nil {
				t.Fatal("ambiguous or incomplete journal admitted")
			}
		})
	}
}
