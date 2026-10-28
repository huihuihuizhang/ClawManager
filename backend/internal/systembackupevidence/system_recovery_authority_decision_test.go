package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type recoveryDecisionAuditProbe struct {
	records []RecoveryAuthorityExternalAuditRecord
	fail    bool
}

func (a *recoveryDecisionAuditProbe) AppendRecoveryAuthorityAudit(_ context.Context, record RecoveryAuthorityExternalAuditRecord) error {
	a.records = append(a.records, record)
	if a.fail {
		return errors.New("injected independent audit failure")
	}
	return nil
}

func TestPinnedRecoveryAuthorityDecisionBindsExactRequestAndLiveFile(t *testing.T) {
	_, _, config := systemPeerFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{
		Scope: config.Scope, Operation: "register", IdentityHash: pd.Hash(strings.Repeat("a", 64)),
		ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(strings.Repeat("b", 64)),
	}, ExpectedDeploymentVersion: "0", Nonce: "manager-decision-register-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	requestHash, err := pd.RecoveryAuthorityHash(r)
	if err != nil {
		t.Fatal(err)
	}
	proposal := pd.RecoveryDeploymentProposal{
		WorkloadIdentityHash: r.Fence.IdentityHash, IssuerIdentityHash: pd.Hash(strings.Repeat("c", 64)),
		SubjectHash: pd.Hash(strings.Repeat("d", 64)), ManagementIssuerHash: pd.Hash(strings.Repeat("e", 64)),
		ActorIdentityHash: pd.Hash(strings.Repeat("f", 64)), AdmissionHash: pd.Hash(strings.Repeat("1", 64)),
		ClientCASHA256: pd.Hash(strings.Repeat("2", 64)), CertificateSHA256: pd.Hash(strings.Repeat("3", 64)),
		StatProfileHash: pd.Hash(strings.Repeat("4", 64)), Enabled: true, Epoch: "1", RowVersion: "1",
		AuthorizedUntil: systemPublicationTimestamp(now.Add(time.Minute)),
	}
	facts := RecoveryManagerPeerFacts{Scope: config.Scope, IdentityHash: strings.Repeat("5", 64),
		IssuerIdentityHash: string(proposal.ManagementIssuerHash), ExpiresAt: now.Add(time.Hour)}
	doc := recoveryAuthorityDecisionDocument{SchemaVersion: recoveryAuthorityDecisionVersion, Scope: config.Scope,
		RequestHash: string(requestHash), ManagerIdentityHash: facts.IdentityHash, ManagerIssuerHash: facts.IssuerIdentityHash,
		Next: proposal, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment-decision.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	audit := &recoveryDecisionAuditProbe{fail: true}
	decision, err := NewPinnedRecoveryAuthorityDecision(config.Scope, path, pin, audit)
	if err != nil {
		t.Fatal(err)
	}
	var missingAudit *recoveryDecisionAuditProbe
	if _, err := NewPinnedRecoveryAuthorityDecision(config.Scope, path, pin, missingAudit); !errors.Is(err, ErrDenied) {
		t.Fatal("typed-nil external audit accepted", err)
	}
	scripted := &authorityDB{t: t, plan: []authorityQuery{{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{now}}}}
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	next, err := decision.NextDeployment(context.Background(), historicalSQLFixture{db: db}, r, nil, facts)
	if err != nil || next != proposal {
		t.Fatal("exact pinned proposal rejected", err)
	}
	if err := decision.RecheckDecision(context.Background(), r, facts, now); err != nil {
		t.Fatal("unchanged decision rejected", err)
	}
	if err := decision.Audit(context.Background(), historicalSQLFixture{db: db}, r, "intent"); !errors.Is(err, ErrUnavailable) || len(audit.records) != 1 || audit.records[0].RequestHash != string(requestHash) {
		t.Fatal("independent audit failure did not fail closed", err)
	}
	changed := r
	changed.Nonce = "manager-decision-register-2"
	if err := decision.RecheckDecision(context.Background(), changed, facts, now); !errors.Is(err, ErrDenied) {
		t.Fatal("different request reused deployment decision", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := decision.RecheckDecision(context.Background(), r, facts, now); !errors.Is(err, ErrDenied) {
		t.Fatal("changed decision file accepted at final guard", err)
	}
	if _, err := NewPinnedRecoveryAuthorityDecision(config.Scope, path, pin, audit); !errors.Is(err, ErrDenied) {
		t.Fatal("changed file accepted under old pin", err)
	}
}
