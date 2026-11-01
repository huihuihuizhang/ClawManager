package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// First-forward selection uses the SAME original backup and common claim
// receipt. Query-only 102 recovery remains first in RunPublicationPass. This
// path prepares complete MF and activates the original upload-only Job.
// Native fixed-version C readback and finalization remain independent steps.
func (s *DeploymentService) runPublicationForwardPreparation(ctx context.Context, store *nativePublicationS3) (resultErr error) {
	if err := s.CheckPublisherVerifierReadiness(ctx); err != nil {
		return err
	}
	var backup string
	var version, attempt uint64
	var ttl, heartbeat, reconcile int64
	err := s.publisherVerifierDB.QueryRowContext(ctx, `SELECT b.public_id,b.row_version,a.attempt_no,cfg.controller_claim_ttl_seconds,cfg.controller_claim_heartbeat_seconds,cfg.controller_reconcile_interval_seconds FROM system_backup_v2_backups b JOIN system_backup_v2_configs cfg ON cfg.origin_installation_id=b.origin_installation_id AND cfg.version=b.config_version AND cfg.config_sha256=b.config_snapshot_sha256 JOIN system_backup_v2_attempts a ON a.target_type='backup' AND a.target_public_id=b.public_id AND a.phase='capture' AND a.status='sealed' WHERE b.origin_installation_id=? AND b.status='validating' AND b.commit_started_at IS NULL AND b.deadline_at>UTC_TIMESTAMP(6) AND (b.next_reconcile_at IS NULL OR b.next_reconcile_at<=UTC_TIMESTAMP(6)) AND (b.controller_owner IS NULL OR b.controller_lease_expires_at<=UTC_TIMESTAMP(6)) AND a.attempt_no=(SELECT MAX(a2.attempt_no) FROM system_backup_v2_attempts a2 WHERE a2.target_type='backup' AND a2.target_public_id=b.public_id AND a2.phase='capture') AND NOT EXISTS(SELECT 1 FROM system_backup_v2_external_actions x WHERE x.origin_installation_id=b.origin_installation_id AND x.target_type='backup' AND x.target_public_id=b.public_id) ORDER BY b.id LIMIT 1`, s.Config.InstallationID).Scan(&backup, &version, &attempt, &ttl, &heartbeat, &reconcile)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errPublicationUnavailable
	}
	policy := c.LeasePolicy{TTL: time.Duration(ttl) * time.Second, HeartbeatInterval: time.Duration(heartbeat) * time.Second, ReconcileInterval: time.Duration(reconcile) * time.Second}
	if policy.Validate() != nil {
		return c.ErrExecutionAuthority
	}
	claim, err := (c.SQLTaskClaimStore{DB: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: backup}, s.PublisherOwner, version, policy)
	if err != nil {
		return err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Release(releaseCtx, claim, policy.ReconcileInterval)
		if resultErr == nil && err != nil {
			resultErr = err
		}
	}()
	// Durable upload material is a query/reopen boundary. Do not rerun capture,
	// mint another certificate clock or regenerate expired upload grants when
	// any original material intent already exists.
	if _, err := s.loadPublicationMaterialIntent(ctx, claim, attempt); err == nil {
		if err := s.startAndAwaitOriginalPublicationUpload(ctx, claim, attempt, store.config, PublicationUploadRequest{}, policy.ReconcileInterval); err != nil {
			return err
		}
		_, err := s.completeOriginalPublicationThroughNativeCleanup(ctx, &claim, attempt, policy, store, publicationVerifiedCapture{})
		return err
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	capture, err := s.verifyOriginalPublicationCaptureMode(ctx, &claim, attempt, policy, true)
	if err != nil {
		return err
	}
	request, err := s.prepareOriginalForwardRequest(ctx, &claim, attempt, policy, capture, store.config)
	if err != nil {
		return err
	}
	if err = s.renewFreshOriginalPublicationPreparation(ctx, &claim, attempt, policy, store.config, request); err != nil {
		return err
	}
	// Actual native CreatePublishJob stays behind the original durable private
	// material/104 intent and 121 one-send boundary. Activation and 107 result
	// delivery are reused; Job success alone cannot commit the artifact.
	if err := s.startAndAwaitOriginalPublicationUpload(ctx, claim, attempt, store.config, request, policy.ReconcileInterval); err != nil {
		return err
	}
	_, err = s.completeOriginalPublicationThroughNativeCleanup(ctx, &claim, attempt, policy, store, capture)
	return err
}
