package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	"clawreef/internal/systembackupsecurity"
)

func TestSystemPreparationCallsActualDLifecycleAndAbsentEvidence(t *testing.T) {
	f := newDIntegrationFixture(t)
	x, simulated := systemExecutionFixture(t, "")
	c := simulated.c
	c.Scope, c.RunID = f.history.Scope, f.history.RunID
	c.InputHash = string(f.history.InputHash)
	c.SubjectIdentityHash = string(f.command.ActorIdentityHash)
	var domain pd.DomainRecord
	f.load("system_backup_producer_domains", &domain)
	c.IssuerIdentityHash = string(domain.IssuerIdentityHash)
	c.Identity = f.prepared.Manifest().Identity
	c.Content.Installation, c.Content.EvidenceID, c.Content.Classification = c.Identity.Installation, c.Identity.ID, c.Identity.Classification
	c.Content.Role = string(f.command.Target.Role)
	c.Content.ProviderIdentity = string(f.command.Target.IdentityHash)
	c.Content.ProviderVersion = string(f.command.Target.RefVersion)
	c.Content.ScopeHash = string(f.command.Target.ProbeScopeHash)
	c.EvaluatorProfileHash = string(f.command.Target.EvaluatorProfileHash)
	c.Content.ValidUntil, _ = f.history.ObservationExpiresAt.Time()
	c.Wrap.Transit.Installation = c.Identity.Installation
	var document systembackupsecurity.CapabilityEvidence
	if err := json.Unmarshal(x.body, &document); err != nil {
		t.Fatal(err)
	}
	document.Role, document.IdentityHash, document.RefVersion, document.ScopeHash = c.Content.Role, c.Content.ProviderIdentity, c.Content.ProviderVersion, c.Content.ScopeHash
	for n := range document.Capabilities {
		if n == 0 {
			document.Capabilities[n].Code = "conditional_create"
		} else {
			document.Capabilities[n].Code = "checksum_bound_request"
		}
		document.Capabilities[n].RequestScopeHash = c.Content.ScopeHash
		document.Capabilities[n].ExpiresAt = c.Content.ValidUntil.Add(-10 * time.Second).UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	c.Identity.ContentHash, c.Identity.ContentSize = hash(body), int64(len(body))
	f.policy = pd.Hash(SystemExecutionPreparationPolicyHash(c))
	env, err := NewSystemPreparationCallEnvironment(&dIntegrationExecution{f}, c)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := pd.NewExecution(f.lifecycle, env)
	if err != nil {
		t.Fatal(err)
	}
	preparer, err := NewSystemExecutionPreparer(context.Background(), execution, f.handle, c)
	if err != nil {
		t.Fatal("D content_read/wrap snapshots", err)
	}
	defer preparer.Close()
	var ciphertext bytes.Buffer
	prepared, err := preparer.Prepare(context.Background(), c.Identity, source(body), &ciphertext)
	if err != nil || prepared.Manifest().Identity != c.Identity || ciphertext.Len() == 0 || bytes.Contains(ciphertext.Bytes(), body) {
		t.Fatal("actual D calls through A absence lock and Transit preparation", err)
	}
	if f.d.row != nil {
		t.Fatal("preparation call wrote evidence before pending")
	}
	// A newly present row makes a fresh content call fail at L8 even while the
	// original D run remains acquired and the identity authority still approves.
	f.d.row = map[string]driver.Value{"id": int64(41), "public_id": string(f.history.Evidence.EvidenceID)}
	request := pd.CallRequest{Purpose: "content_read", EvidenceID: f.history.Evidence.EvidenceID, RefIdentityHash: pd.Hash(c.Content.ProviderIdentity), RefVersion: pd.ProviderVersion(c.Content.ProviderVersion), PolicyHash: f.policy, BudgetUntil: systemExecutionStamp(time.Now().Add(15 * time.Second))}
	if snapshot, err := execution.BeginCall(context.Background(), f.handle, request, nil); err == nil || snapshot != nil {
		t.Fatal("existing A row admitted as reserved evidence")
	}
	f.d.row = nil
	f.fail = "preparation_insert_at_guard"
	if snapshot, err := execution.BeginCall(context.Background(), f.handle, request, nil); err == nil || snapshot != nil || f.d.row != nil {
		t.Fatal("A row inserted after L8 escaped final guard or rollback")
	}
}
