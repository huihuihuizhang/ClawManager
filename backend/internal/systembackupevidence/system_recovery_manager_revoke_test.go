package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryManagerRevocationGrantIsPinnedAndExact(t *testing.T) {
	_, _, config := systemPeerFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	doc := recoveryManagerRevocationDocument{SchemaVersion: recoveryManagerRevocationVersion,
		GrantID: "superior-revoke-20261012", Scope: config.Scope,
		SuperiorIdentityHash: strings.Repeat("a", 64), ManagerIdentityHash: strings.Repeat("b", 64),
		ReasonHash: strings.Repeat("c", 64), ExpectedRowVersion: 7,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "revocation-grant.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	grant, err := ReadRecoveryManagerRevocationGrant(path, pin)
	if err != nil || grant.document != doc || grant.path != path || grant.digest != pin {
		t.Fatal("valid superior grant rejected", err)
	}
	if _, err := ReadRecoveryManagerRevocationGrant(path, strings.Repeat("0", 64)); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong pin accepted", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecoveryManagerRevocationGrant(path, pin); !errors.Is(err, ErrDenied) {
		t.Fatal("changed grant accepted under original pin", err)
	}
	if validRecoveryManagerRevocation(recoveryManagerRevocationDocument{SchemaVersion: recoveryManagerRevocationVersion}) {
		t.Fatal("incomplete superior grant accepted")
	}
	journalPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(journalPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := NewRecoveryAuditJournal(journalPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	record := RecoveryManagerRevocationExternalAuditRecord{Stage: "intent", GrantID: doc.GrantID, GrantSHA256: pin,
		SuperiorIdentityHash: doc.SuperiorIdentityHash, ManagerIdentityHash: doc.ManagerIdentityHash,
		ScopeKeySHA256: strings.Repeat("d", 64)}
	if err := j.AppendRecoveryManagerRevocationAudit(context.Background(), record); err != nil {
		t.Fatal("revocation intent audit rejected", err)
	}
	lines, err := os.ReadFile(journalPath)
	if err != nil || !strings.Contains(string(lines), `"kind":"manager_revocation"`) {
		t.Fatal("revocation intent not durably recorded", err)
	}
}
