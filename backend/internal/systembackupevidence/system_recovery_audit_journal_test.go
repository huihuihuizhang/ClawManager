package systembackupevidence

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryAuditJournalRequiresProvisionedFileAndFailsAtCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "independent-audit.jsonl")
	if _, err := NewRecoveryAuditJournal(path, 4096); !errors.Is(err, ErrDenied) {
		t.Fatal("missing journal was created", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := NewRecoveryAuditJournal(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	manager := RecoveryManagerExternalAuditRecord{Stage: "intent", GrantID: "first-manager-20261010",
		GrantSHA256: strings.Repeat("a", 64), BootstrapIdentityHash: strings.Repeat("b", 64),
		ManagerIdentityHash: strings.Repeat("c", 64), ScopeKeySHA256: strings.Repeat("d", 64)}
	if err := j.AppendRecoveryManagerAudit(context.Background(), manager); err != nil {
		t.Fatal("manager intent was not synced", err)
	}
	authority := RecoveryAuthorityExternalAuditRecord{Stage: "result_prepared", DecisionSHA256: strings.Repeat("e", 64),
		RequestHash: strings.Repeat("f", 64), ManagerIdentityHash: manager.ManagerIdentityHash}
	if err := j.AppendRecoveryAuthorityAudit(context.Background(), authority); err != nil {
		t.Fatal("authority prepared-result was not synced", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	var kinds []string
	for scanner.Scan() {
		var record recoveryAuditJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal("invalid durable audit line", err)
		}
		kinds = append(kinds, record.Kind)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if len(kinds) != 2 || kinds[0] != "manager_bootstrap" || kinds[1] != "authority_change" {
		t.Fatalf("unexpected durable audit sequence: %v", kinds)
	}
	for i := 0; i < 20; i++ {
		if err := j.AppendRecoveryAuthorityAudit(context.Background(), authority); err != nil {
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("capacity failure had wrong error", err)
			}
			if err := j.AppendRecoveryManagerAudit(context.Background(), manager); !errors.Is(err, ErrUnavailable) {
				t.Fatal("poisoned journal resumed after capacity failure", err)
			}
			return
		}
	}
	t.Fatal("journal exceeded reserved logical capacity")
}

func TestRecoveryAuditJournalRejectsExternalSizeDrift(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(string) error
	}{
		{"truncate", func(path string) error { return os.Truncate(path, 0) }},
		{"append", func(path string) error {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, writeErr := f.Write([]byte("untrusted\n"))
			closeErr := f.Close()
			if writeErr != nil {
				return writeErr
			}
			return closeErr
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			journal, err := NewRecoveryAuditJournal(path, 4096)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { journal.Close() })
			record := RecoveryAuthorityExternalAuditRecord{Stage: "intent", DecisionSHA256: strings.Repeat("a", 64),
				RequestHash: strings.Repeat("b", 64), ManagerIdentityHash: strings.Repeat("c", 64)}
			if err := journal.AppendRecoveryAuthorityAudit(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if err := change.edit(path); err != nil {
				t.Fatal(err)
			}
			if err := journal.AppendRecoveryAuthorityAudit(context.Background(), record); !errors.Is(err, ErrUnavailable) {
				t.Fatal("externally changed journal remained writable", err)
			}
			if err := journal.AppendRecoveryAuthorityAudit(context.Background(), record); !errors.Is(err, ErrUnavailable) {
				t.Fatal("poisoned journal resumed", err)
			}
		})
	}
}
