package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// RunPublicationPass is the actual service's query-only finalization recovery
// pass. It acquires the SAME v2 backup via the common durable claim receipt.
// Original request_sent/provider_unreachable actions are never sent again,
// never regenerated, rewrapped, re-signed, or given a new dispatch deadline.
// Confirmation advances only that action; complete artifact verification and
// acceptance/catalog finalization remain mandatory before terminal success.
func (d *DeploymentService) RunPublicationPass(ctx context.Context) (resultErr error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	if !d.ForwardEnabled || d.Config.PublicationTarget == nil {
		return nil
	}
	if d.CheckPublisherVerifierReadiness(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	store, err := d.publicationStore(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	db := d.publisherVerifierDB
	var backup string
	var version, attempt uint64
	var ttl, heartbeat, reconcile int64
	err = db.QueryRowContext(ctx, `SELECT b.public_id,b.row_version,a.attempt_no,cfg.controller_claim_ttl_seconds,cfg.controller_claim_heartbeat_seconds,cfg.controller_reconcile_interval_seconds FROM system_backup_v2_backups b JOIN system_backup_v2_configs cfg ON cfg.origin_installation_id=b.origin_installation_id AND cfg.version=b.config_version AND cfg.config_sha256=b.config_snapshot_sha256 JOIN system_backup_v2_attempts a ON a.target_type='backup' AND a.target_public_id=b.public_id AND a.phase='capture' AND a.status='sealed' WHERE b.origin_installation_id=? AND b.status IN ('publishing','finalization_unknown') AND b.deadline_at>UTC_TIMESTAMP(6) AND (b.next_reconcile_at IS NULL OR b.next_reconcile_at<=UTC_TIMESTAMP(6)) AND (b.controller_owner IS NULL OR b.controller_lease_expires_at<=UTC_TIMESTAMP(6)) AND a.attempt_no=(SELECT MAX(a2.attempt_no) FROM system_backup_v2_attempts a2 WHERE a2.target_type='backup' AND a2.target_public_id=b.public_id AND a2.phase='capture') AND EXISTS(SELECT 1 FROM system_backup_v2_external_actions x WHERE x.origin_installation_id=b.origin_installation_id AND x.target_type='backup' AND x.target_public_id=b.public_id AND x.state IN ('request_sent','provider_unreachable')) ORDER BY b.id LIMIT 1`, d.Config.InstallationID).Scan(&backup, &version, &attempt, &ttl, &heartbeat, &reconcile)
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
	claim, err := (c.SQLTaskClaimStore{DB: db, InstallationID: d.Config.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: backup}, d.PublisherOwner, version, policy)
	if err != nil {
		return err
	}
	defer func() {
		// Release only the exact acquired/explicitly renewed token. A lost ACK or
		// concurrent takeover cannot be replaced with a synthesized current token.
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, releaseErr := (c.ClaimCoordinator{Executor: db, InstallationID: d.Config.InstallationID}).Release(releaseCtx, claim, policy.ReconcileInterval)
		if resultErr == nil && releaseErr != nil {
			resultErr = releaseErr
		}
	}()
	// Renew at this stage boundary via the real CAS. No old verifier, DEK,
	// access object or dispatch request exists across this explicit transition.
	renewed, err := (c.ClaimCoordinator{Executor: db, InstallationID: d.Config.InstallationID}).Renew(ctx, claim, policy)
	if err != nil {
		return err
	}
	claim = renewed
	access, err := d.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return errPublicationUnavailable
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	if err = d.checkPublicationTargetTx(ctx, tx, guard.Facts(), store.config); err != nil {
		return err
	}
	action, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND state IN ('request_sent','provider_unreachable') ORDER BY id LIMIT 1 FOR SHARE", d.Config.InstallationID, backup))
	if err != nil || guard.RecheckTx(ctx, tx) != nil {
		return errPublicationUnavailable
	}
	originalIntent := publicationJSONIntent{Kind: action.Kind, Key: action.Key, Payload: action.Payload, Deadline: action.Deadline}
	if originalIntent.validate(store.config) != nil || action.ActionKey != publicationActionKey(backup, attempt, action.Kind) || action.LogicalSHA != publicationLogicalHash(d.Config.InstallationID, backup, attempt, originalIntent) {
		return errPublicationUnavailable
	}
	if tx.Rollback() != nil {
		return errPublicationUnavailable
	}
	object, _, observationErr := readPublicationJSON(ctx, store, action, access.ValidUntil())
	if access.Check(ctx) != nil {
		return c.ErrClaimLost
	}
	currentStore, err := d.publicationStore(ctx)
	if err != nil {
		return err
	}
	currentStore.Close()
	return d.recordPublicationObservation(ctx, claim, attempt, action, object, observationErr)
}
