package systembackupexecution

import (
	"context"
	"database/sql"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// This joins D's opaque, authenticated original physical recovery handle to
// this exact C artifact. Facts are comparison data; they cannot construct D's
// handle or turn a historical capture grant into current publisher authority.
func publicationSourceRecoveryFacts(proof *publicationFinalVerification, source *c.PublisherSourceRecovery) (c.PublisherSourceRecoveryFacts, error) {
	var zero c.PublisherSourceRecoveryFacts
	if proof == nil || source == nil || !proof.cleanup.ready() || proof.access == nil {
		return zero, c.ErrExecutionAuthority
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	facts := source.Facts()
	if !capture.checked() || facts.Scope != (ce.Scope{Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo}) || facts.Scope.Installation != proof.target.InstallationID || facts.Scope.Backup != proof.claim.Target.PublicID || facts.Scope.Attempt != proof.attempt || facts.SourceSHA256 != capture.Input.SourceSHA256 || facts.PlanSHA256 != capture.PlanSHA256 || facts.CaptureResultSHA256 != capture.CaptureResultSHA256 || facts.CaptureEpoch != capture.Input.CaptureEpoch || facts.WriterCount < 1 || facts.ObservedAt.IsZero() || facts.Root.PublicID == "" || !formalCandidateDigest(facts.Root.SHA256) || !formalCandidateDigest(facts.FrozenControlSHA256) || !formalCandidateDigest(facts.RegistrySHA256) {
		return zero, c.ErrExecutionRecord
	}
	return facts, nil
}

// SQL only: the complete source record/family and current publisher guard are
// re-read by D in the caller's transaction. There is no nested transaction,
// network request, runtime restart, old grant check or new physical witness.
func recheckPublicationSourceRecoveryTx(ctx context.Context, tx *sql.Tx, proof *publicationFinalVerification, source *c.PublisherSourceRecovery) error {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return c.ErrExecutionAuthority
	}
	if _, err := publicationSourceRecoveryFacts(proof, source); err != nil {
		return err
	}
	return source.RecheckTx(ctx, tx, proof.access)
}

// Called after the final explicit renewal/history check. A's factory owns both
// the concrete current authority and original Records reader; its controlled
// bridge returns the SAME authority used to authenticate D's physical proof.
// No renewal or journal-authority replacement may follow this attachment.
func (proof *publicationFinalVerification) openSourceRecovery(ctx context.Context) error {
	if proof == nil || proof.service == nil || proof.service.publisherVerifierFactory == nil || proof.access == nil || !proof.cleanup.ready() || proof.sourceRecovery != nil {
		return c.ErrExecutionAuthority
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	found := false
	for _, part := range capture.Parts {
		if part.Part == ce.Part {
			if found {
				return c.ErrExecutionRecord
			}
			found = true
		}
	}
	if !found {
		return c.ErrExecutionRecord
	}
	scope := security.PublisherCaptureScope{BackupPublicID: proof.claim.Target.PublicID, Claim: security.SQLSigningClaim{ControllerOwner: proof.claim.Owner, RowVersion: proof.claim.RowVersion}, CaptureAttemptNo: proof.attempt, Part: ce.Part}
	source, access, err := proof.service.publisherVerifierFactory.OpenSourceRecovery(ctx, scope)
	if err != nil {
		return err
	}
	if source == nil || access == nil || access.Scope() != scope || access.Deployment() != proof.access.Deployment() {
		return c.ErrExecutionAuthority
	}
	proof.access, proof.sourceRecovery = access, source
	if _, err = publicationSourceRecoveryFacts(proof, source); err != nil {
		return err
	}
	return access.Check(ctx)
}
