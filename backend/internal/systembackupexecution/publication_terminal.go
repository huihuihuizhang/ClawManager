package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// These are observations of the actual terminal transaction, never input
// permission or an alternative Ready constructor. Unknown forbids old Release
// even when the independent readback cannot establish the committed outcome.
type publicationTerminalProgress struct {
	committed, commitUnknown bool
}

// Complete the first-forward artifact already authenticated by C. The fresh
// decision initializer is reachable only from this caller's acknowledged new
// material path. Reopened material never makes SQL absence proof of first use.
func (s *DeploymentService) completeOriginalPublicationTerminal(ctx context.Context, claim c.ClaimToken, attempt uint64, proof *publicationFinalVerification, firstDecision bool, progress *publicationTerminalProgress) error {
	if s == nil || ctx == nil || ctx.Err() != nil || progress == nil || progress.committed || progress.commitUnknown || proof == nil || proof.service != s || proof.claim != claim || proof.attempt != attempt || proof.access == nil {
		return c.ErrExecutionAuthority
	}
	// No renewal after source-recovery attachment. Every remaining operation
	// must fit the same authority's original absolute deadline or stop.
	bounded, cancel := context.WithDeadline(ctx, proof.access.ValidUntil())
	defer cancel()
	accepted, err := s.completeOriginalPublicationAcceptance(bounded, proof)
	if err != nil {
		return err
	}
	registered, err := s.completeOriginalPublicationCatalog(bounded, accepted)
	if err != nil {
		return err
	}
	var decision *publicationDecisionEvidence
	if firstDecision {
		prepared, prepareErr := s.prepareOriginalPublicationDecision(bounded, registered)
		if prepareErr != nil {
			return prepareErr
		}
		decision, err = prepared.Persist(bounded)
		if errors.Is(err, c.ErrExecutionCommitUnknown) {
			// Retain THIS handle/preimage. Only query, never reconstruct an
			// initializer or change the original SQL decision clock on uncertainty.
			unknown := err
			decision, err = prepared.Query(bounded)
			if err != nil {
				return errors.Join(unknown, err)
			}
		}
	} else {
		decision, err = s.queryOriginalPublicationDecision(bounded, registered)
	}
	if err != nil {
		return err
	}
	ready, err := s.completeOriginalPublicationReady(bounded, decision)
	if err != nil {
		return err
	}
	if _, err = s.persistOriginalBusinessContentReport(bounded, ready); err != nil {
		return err
	}
	err = s.applyOriginalPublicationTerminal(bounded, claim, attempt, ready)
	if err == nil {
		progress.committed = true
		return nil
	}
	if !errors.Is(err, c.ErrExecutionCommitUnknown) {
		return err
	}
	progress.commitUnknown = true // Set BEFORE any observation or return.
	// This is a new independently authorized READ, not an extension of the
	// expired/canceled task permission. It can never send, CAS or advance sequence.
	observeCtx, observeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer observeCancel()
	if observeErr := s.observeOriginalPublicationTerminal(observeCtx, claim, attempt, ready); observeErr != nil {
		return errors.Join(err, observeErr)
	}
	progress.committed = true
	return nil
}

func (s *DeploymentService) publicationTerminalScope(claim c.ClaimToken, attempt uint64, ready *publicationTerminalReady) (publicationTerminalFacts, error) {
	var zero publicationTerminalFacts
	if s == nil || s.publisherVerifierDB == nil || ready == nil || ready.decision == nil || !formalCandidateDigest(ready.sha256) || claim.Target.Kind != c.TargetBackup || claim.Owner != s.PublisherOwner || claim.RowVersion == 0 || claim.RowVersion == ^uint64(0) {
		return zero, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(ready.decision.registered)
	facts := ready.Facts()
	if !manifestOneOf(facts.Purpose, "acceptance", "functional_test") || !publicationDecisionReasonsValid(facts.Eligible, strings.Split(facts.QualificationReasons, ",")) || facts.Eligible != (facts.Purpose == "acceptance") {
		return zero, c.ErrExecutionRecord
	}
	if proof == nil || proof.service != s || proof.claim != claim || proof.attempt != attempt || facts.Installation != s.Config.InstallationID || facts.Backup != claim.Target.PublicID || facts.Claim != claim || facts.Attempt != attempt || facts.ConfigVersion == 0 || !formalCandidateDigest(facts.ConfigSHA256) || facts.Artifact != facts.Manifest || facts.ArtifactBytes < 1 || facts.Until.IsZero() || facts.DecisionAt.IsZero() || facts.VerifiedAt.IsZero() || !facts.DecisionAt.Equal(facts.DecisionAt.Truncate(time.Microsecond)) || !facts.VerifiedAt.Equal(facts.VerifiedAt.Truncate(time.Microsecond)) {
		return zero, c.ErrExecutionAuthority
	}
	return facts, nil
}

// The existing controller helper owns the SAME task/event/sequence transaction.
// All authority and complete artifact checks precede the sole terminal UPDATE.
// Nothing after the UPDATE calls a publishing guard or changes another task.
func (s *DeploymentService) applyOriginalPublicationTerminal(ctx context.Context, claim c.ClaimToken, attempt uint64, ready *publicationTerminalReady) error {
	if ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	facts, err := s.publicationTerminalScope(claim, attempt, ready)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithDeadline(ctx, facts.Until)
	defer cancel()
	return c.ApplyAcceptanceTerminalWithSequence(bounded, s.publisherVerifierDB, facts.Installation, facts.ConfigVersion, claim.Target, claim.RowVersion,
		c.AcceptanceTerminalOutcome{TaskType: c.TargetBackup, Purpose: facts.Purpose, Status: "succeeded", EligibilityDecided: true, Eligible: facts.Eligible},
		func(txCtx context.Context, executor c.Executor) (sql.Result, error) {
			tx, ok := executor.(*sql.Tx)
			if !ok || tx == nil {
				return nil, c.ErrExecutionAuthority
			}
			if err := ready.recheckTx(txCtx, tx); err != nil {
				return nil, err
			}
			// artifact is the exact manifest compatibility alias. Existing holds,
			// target class/risks/failure domain and maintenance fences are preserved.
			return tx.ExecContext(txCtx, `UPDATE system_backup_v2_backups SET
status='succeeded',finished_at=UTC_TIMESTAMP(6),failure_category='none',failure_message=NULL,retryable=FALSE,
pending_reason='none',attention_reason='none',can_cancel=FALSE,
artifact_uri=?,artifact_immutable_version=?,artifact_checksum=?,
manifest_uri=?,manifest_immutable_version=?,manifest_checksum=?,
index_uri=?,index_immutable_version=?,index_checksum=?,
marker_uri=?,marker_immutable_version=?,marker_checksum=?,
acceptance_uri=?,acceptance_immutable_version=?,acceptance_checksum=?,
artifact_state='committed',artifact_committed_at=COALESCE(artifact_committed_at,?),artifact_usable=TRUE,
artifact_unusable_reason='none',artifact_last_health_at=?,artifact_bytes=?,
artifact_registration_id=?,artifact_registration_hash=?,consistency='strong',acceptance_eligible=?,
eligibility_reason_codes=?,eligibility_decision_hash=?,eligibility_decided_at=?,
capture_certificate_sha256=?,capture_checkpoint_sha256=?,
controller_owner=NULL,controller_lease_expires_at=NULL,next_reconcile_at=NULL,row_version=row_version+1
WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=?
AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) AND UTC_TIMESTAMP(6)<?
AND status='publishing' AND task_purpose=? AND config_version=? AND config_snapshot_sha256=?
AND requested_parts=? AND commit_started_at IS NOT NULL AND can_cancel=FALSE
AND artifact_state IN ('staging','committed') AND (consistency IS NULL OR consistency='strong')
AND target_class=? AND target_risks=? AND target_failure_domain_id=?
AND failure_category='none' AND failure_message IS NULL AND retryable=FALSE
AND (artifact_committed_at IS NULL OR artifact_committed_at<=?)`,
				facts.Manifest.URI, facts.Manifest.Version, facts.Manifest.SHA256,
				facts.Manifest.URI, facts.Manifest.Version, facts.Manifest.SHA256,
				facts.Index.URI, facts.Index.Version, facts.Index.SHA256,
				facts.Marker.URI, facts.Marker.Version, facts.Marker.SHA256,
				facts.Acceptance.URI, facts.Acceptance.Version, facts.Acceptance.SHA256,
				facts.VerifiedAt, facts.VerifiedAt, facts.ArtifactBytes,
				facts.RegistrationID, facts.RegistrationSHA256, facts.Eligible, facts.QualificationReasons, facts.Decision.SHA256, facts.DecisionAt,
				facts.CaptureCertificateSHA256, facts.CaptureCheckpointsSHA256,
				facts.Installation, facts.Backup, claim.Owner, claim.RowVersion, facts.Until,
				facts.Purpose, facts.ConfigVersion, facts.ConfigSHA256, facts.RequestedParts, facts.TargetClass, facts.TargetRisks, facts.FailureDomain, facts.VerifiedAt)
		})
}

// Reconstruct only the independently pinned DEPLOYMENT/workload read scope.
// This does not select a task, revive an expired task claim, authorize Unwrap,
// call the provider factory's capability preparation, or write SQL.
func (s *DeploymentService) publicationTerminalObservationConfig(ctx context.Context, ready *publicationTerminalReady) (security.PublisherCaptureAuthorityConfig, error) {
	var zero security.PublisherCaptureAuthorityConfig
	if s == nil || ready == nil || ready.decision == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.publisherVerifier == nil || s.publisherVerifierDB == nil || s.checkPublisherVerifierBinding(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(ready.decision.registered)
	if proof == nil || proof.service != s || proof.access == nil {
		return zero, c.ErrExecutionAuthority
	}
	p := s.publisherVerifier
	w := p.Workload
	deployment := proof.access.Deployment()
	if (deploymentAuthorization{Service: s}).CheckPublisherVerifierDeployment(ctx, deployment) != nil {
		return zero, c.ErrExecutionAuthority
	}
	cfg := security.PublisherCaptureAuthorityConfig{DB: s.publisherVerifierDB, Kubernetes: s.Runtime.Owner.Client, Deployment: deployment,
		Workload: security.PublisherCaptureWorkload{Namespace: w.Namespace, NamespaceUID: p.KubernetesReads.NamespaceUID, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, PublisherOwner: w.ControllerOwner, GrantSHA256: w.GrantSHA256}, GrantMount: p.Grant}
	if p.KubernetesReads.Check(ctx, cfg.Kubernetes, w) != nil || security.CheckPublisherCaptureDeploymentWorkload(ctx, cfg) != nil {
		return zero, c.ErrExecutionAuthority
	}
	return cfg, nil
}

func checkPublicationTerminalObservationTx(ctx context.Context, tx *sql.Tx, cfg security.PublisherCaptureAuthorityConfig) error {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return c.ErrExecutionAuthority
	}
	grant, err := security.CheckPublisherCaptureDeploymentGrant(ctx, cfg)
	if err != nil {
		return err
	}
	var account, server, database string
	var now time.Time
	d := cfg.Deployment
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&account, &server, &database, &now) != nil || account != d.DatabaseAccount || server != d.ServerUUID || database != d.Database || now.Before(d.NotBefore) || !now.Before(d.Until) || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return c.ErrExecutionAuthority
	}
	return nil
}

// Observe an unknown terminal COMMIT using only independent deployment READ
// authority. It NEVER invokes Ready.recheckTx/access.Bind: the successful task
// is no longer publishing and its old claim has been cleared. The exact task
// at expected+1 and immutable artifact/decision facts identify the original
// transaction. Its event/sequence committed atomically by the existing helper;
// another task may legitimately advance the global anomaly sequence afterward.
func (s *DeploymentService) observeOriginalPublicationTerminal(ctx context.Context, claim c.ClaimToken, attempt uint64, ready *publicationTerminalReady) error {
	if ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	facts, err := s.publicationTerminalScope(claim, attempt, ready)
	if err != nil {
		return err
	}
	cfg, err := s.publicationTerminalObservationConfig(ctx, ready)
	if err != nil {
		return err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkPublicationTerminalObservationTx(ctx, tx, cfg); err != nil {
		return err
	}
	var backup string
	err = tx.QueryRowContext(ctx, `SELECT public_id FROM system_backup_v2_backups
WHERE origin_installation_id=? AND public_id=? AND row_version=? AND task_type='backup'
AND status='succeeded' AND task_purpose=? AND config_version=? AND config_snapshot_sha256=? AND requested_parts=?
AND controller_owner IS NULL AND controller_lease_expires_at IS NULL AND next_reconcile_at IS NULL
AND finished_at>=? AND finished_at>=? AND commit_started_at IS NOT NULL AND can_cancel=FALSE
AND pending_reason='none' AND attention_reason='none' AND failure_category='none' AND failure_message IS NULL AND retryable=FALSE
AND artifact_state='committed' AND artifact_usable=TRUE AND artifact_unusable_reason='none'
AND artifact_committed_at IS NOT NULL AND artifact_committed_at<=? AND artifact_last_health_at=? AND artifact_bytes=?
AND target_class=? AND target_risks=? AND target_failure_domain_id=? AND consistency='strong'
AND acceptance_eligible=? AND eligibility_reason_codes=? AND eligibility_decision_hash=? AND eligibility_decided_at=?
AND artifact_registration_id=? AND artifact_registration_hash=? AND capture_certificate_sha256=? AND capture_checkpoint_sha256=?
AND artifact_uri=? AND artifact_immutable_version=? AND artifact_checksum=?
AND manifest_uri=? AND manifest_immutable_version=? AND manifest_checksum=?
AND index_uri=? AND index_immutable_version=? AND index_checksum=?
AND marker_uri=? AND marker_immutable_version=? AND marker_checksum=?
AND acceptance_uri=? AND acceptance_immutable_version=? AND acceptance_checksum=?`,
		facts.Installation, facts.Backup, claim.RowVersion+1, facts.Purpose, facts.ConfigVersion, facts.ConfigSHA256, facts.RequestedParts,
		facts.DecisionAt, facts.VerifiedAt, facts.VerifiedAt, facts.VerifiedAt, facts.ArtifactBytes,
		facts.TargetClass, facts.TargetRisks, facts.FailureDomain, facts.Eligible, facts.QualificationReasons, facts.Decision.SHA256, facts.DecisionAt, facts.RegistrationID, facts.RegistrationSHA256, facts.CaptureCertificateSHA256, facts.CaptureCheckpointsSHA256,
		facts.Manifest.URI, facts.Manifest.Version, facts.Manifest.SHA256,
		facts.Manifest.URI, facts.Manifest.Version, facts.Manifest.SHA256,
		facts.Index.URI, facts.Index.Version, facts.Index.SHA256,
		facts.Marker.URI, facts.Marker.Version, facts.Marker.SHA256,
		facts.Acceptance.URI, facts.Acceptance.Version, facts.Acceptance.SHA256).Scan(&backup)
	if err != nil || backup != facts.Backup {
		return errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	// This is the original task's terminal event, not a global sequence count.
	var events uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_events e JOIN system_backup_v2_backups b ON b.origin_installation_id=e.origin_installation_id AND b.public_id=e.target_public_id WHERE e.origin_installation_id=? AND e.target_type='backup' AND e.target_public_id=? AND e.event_type='task_status_changed' AND e.task_status='succeeded' AND e.detail_previous_status='publishing' AND e.detail_current_status='succeeded' AND e.request_id=b.request_id`, facts.Installation, facts.Backup).Scan(&events) != nil || events != 1 {
		return c.ErrExecutionCommitUnknown
	}
	return checkPublicationTerminalObservationTx(ctx, tx, cfg)
}
