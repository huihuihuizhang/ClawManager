package systembackupexecution

import (
	"bytes"
	"context"

	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// This actual production sink runs AFTER Ready's transaction has returned and
// BEFORE applyOriginalPublicationTerminal acquires its final SQL locks/CAS.
// The original publisher owns the sibling .controller-seals root; worker Pods
// never mount it. Exact report name is stable across claim renewal/restart.
func (s *DeploymentService) persistOriginalBusinessContentReport(ctx context.Context, ready *publicationTerminalReady) (staging.Receipt, error) {
	var zero staging.Receipt
	if s == nil || ready == nil || ready.decision == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Staging == nil {
		return zero, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(ready.decision.registered)
	if proof == nil || proof.service != s || proof.claim != ready.facts.Claim || proof.access == nil {
		return zero, c.ErrExecutionAuthority
	}
	// WriteBusinessContentReport performs current scope + independent short SQL
	// Ready recheck and closes that transaction BEFORE emitting these bytes.
	var output bytes.Buffer
	if err := ready.WriteBusinessContentReport(ctx, &output); err != nil {
		return zero, err
	}
	identity, err := ce.Canonical([]any{"private-business-content-report.v1", ready.facts.Installation, ready.facts.Backup, ready.facts.Attempt, ready.facts.ConfigSHA256, ready.facts.Manifest.SHA256, ready.facts.ContentSamplesSHA256})
	if err != nil {
		return zero, err
	}
	root, err := staging.OpenSealCustody(s.Runtime.Owner.Staging)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	policy := staging.CustodyPolicy{Installation: s.Config.InstallationID, MaxBytes: s.Runtime.Owner.SealCustodyMaxBytes}
	return staging.StorePrivateReport(ctx, root, policy, "report-"+hash(identity)+".json", output.Bytes(), proof.access.Check)
}
