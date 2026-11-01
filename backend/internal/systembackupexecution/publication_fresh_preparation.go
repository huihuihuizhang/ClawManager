package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

var errOriginalPublicationPreparationExists = errors.New("original publication preparation exists; observation required")

// The original coordinator must own its transaction and SQL-clock CAS. This
// private DB wrapper adds restrictive checks inside that SAME transaction,
// before returning its real *sql.Tx. It accepts no passed-authority callback.
// Holding the original task lock closes the check-to-Renew race with every
// original candidate/material/send constructor, which binds that same row.
type publicationFreshRenewalDB struct {
	*sql.DB
	service  *DeploymentService
	access   *security.SQLPublisherCaptureAuthority
	claim    c.ClaimToken
	attempt  uint64
	policy   c.LeasePolicy
	target   PublicationTargetMaterials
	request  *PublicationUploadRequest
	inputSHA string
}

func (d *publicationFreshRenewalDB) BeginTx(ctx context.Context, options *sql.TxOptions) (_ *sql.Tx, resultErr error) {
	if d == nil || d.DB == nil || d.service == nil || d.access == nil || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := d.DB.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			tx.Rollback()
		}
	}()
	var version uint64
	err = tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status='validating' AND can_cancel=TRUE AND commit_started_at IS NULL AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR UPDATE`, d.service.Config.InstallationID, d.claim.Target.PublicID, d.claim.Owner, d.claim.RowVersion).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, c.ErrClaimLost
	}
	if err != nil {
		return nil, err
	}
	if version != d.claim.RowVersion {
		return nil, c.ErrClaimLost
	}
	guard, err := d.access.Bind(ctx, tx)
	if err != nil {
		return nil, err
	}
	facts := guard.Facts()
	if facts.Status != "validating" || facts.CaptureAttemptNo != d.attempt || d.request != nil && d.request.Deadline.After(facts.TaskDeadline) || d.service.checkPublicationTargetTx(ctx, tx, facts, d.target) != nil {
		return nil, c.ErrExecutionAuthority
	}
	var ttl, heartbeat, reconcile int64
	err = tx.QueryRowContext(ctx, `SELECT controller_claim_ttl_seconds,controller_claim_heartbeat_seconds,controller_reconcile_interval_seconds FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256).Scan(&ttl, &heartbeat, &reconcile)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 || heartbeat <= 0 || reconcile <= 0 || int64(d.policy.TTL/time.Second) != ttl || d.policy.TTL%time.Second != 0 || int64(d.policy.HeartbeatInterval/time.Second) != heartbeat || d.policy.HeartbeatInterval%time.Second != 0 || int64(d.policy.ReconcileInterval/time.Second) != reconcile || d.policy.ReconcileInterval%time.Second != 0 {
		return nil, c.ErrExecutionAuthority
	}
	if err := originalPublicationPreparationAbsentTx(ctx, tx, facts.InstallationID, facts.BackupPublicID); err != nil {
		return nil, err
	}
	if d.request != nil {
		again, err := json.Marshal(d.request)
		if err != nil || hash(again) != d.inputSHA {
			return nil, c.ErrExecutionAuthority
		}
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return tx, nil
}

// Original SQL facts only. In particular a preexisting104 without a material
// capsule can already mean a delegated PUT grant was issued. Never refresh it.
// Capture-side container plans/certificate facts are not upload delegations.
func originalPublicationPreparationAbsentTx(ctx context.Context, tx *sql.Tx, installation, backup string) error {
	if ctx == nil || tx == nil {
		return c.ErrExecutionAuthority
	}
	checks := []string{
		`SELECT public_id FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND resource_type='remote_manifest_candidate' LIMIT 1 FOR SHARE`,
		`SELECT public_id FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND (public_id LIKE 'sev!_pub!_material!_%' ESCAPE '!' OR public_id LIKE 'sev!_pub!_upload!_%' ESCAPE '!') LIMIT 1 FOR SHARE`,
		`SELECT job_unit_key FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' LIMIT 1 FOR SHARE`,
		`SELECT job_unit_key FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND phase='publish' LIMIT 1 FOR SHARE`,
		`SELECT public_id FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? LIMIT 1 FOR SHARE`,
	}
	for i, query := range checks {
		args := []any{installation, backup}
		if i == 1 {
			args = []any{backup}
		}
		var id string
		err := tx.QueryRowContext(ctx, query, args...).Scan(&id)
		if err == nil {
			return errors.Join(errOriginalPublicationPreparationExists, ErrJobUncertain)
		}
		if err != sql.ErrNoRows {
			return err
		}
	}
	return nil
}

// Renew only a current preparation claim BEFORE the first104/grant/material/
// 121/107 exists. No signer, provider, credential mint, native request or old
// intent adoption is reachable here. Unknown commits retain the old token.
func (s *DeploymentService) renewFreshOriginalPublicationPreparation(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, target PublicationTargetMaterials, request PublicationUploadRequest) error {
	if s == nil || ctx == nil || ctx.Err() != nil || claim == nil || !s.ForwardEnabled || s.publisherVerifierDB == nil || policy.Validate() != nil || claim.Target.Kind != c.TargetBackup || attempt != 1 || request.Version != publicationPresignedUploadVersion || request.CredentialHash != "" || request.CandidateOwnerHMAC != "" || request.Installation != s.Config.InstallationID || request.Installation != target.InstallationID || request.Backup != claim.Target.PublicID || request.Attempt != attempt || request.Endpoint != target.Endpoint || request.Region != target.Region || request.Bucket != target.Bucket || request.ArtifactRoot != target.Root || request.RemoteStagingRoot != target.RemoteStagingRoot || request.CAHash != target.CASHA256 {
		return c.ErrExecutionAuthority
	}
	if _, _, err := request.validate(); err != nil {
		return err
	}
	current, err := s.publicationStore(ctx)
	if err != nil {
		return err
	}
	same := current.config == target
	current.Close()
	if !same {
		return c.ErrExecutionAuthority
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return c.ErrExecutionRecord
	}
	return s.renewOriginalPublicationPreparationClaim(ctx, claim, attempt, policy, target, &request, hash(raw))
}

// All pre-first-upload renewal sites use this same restrictive transaction.
// A nil request means MF is still being assembled, never an old delegation.
func (s *DeploymentService) renewOriginalPublicationPreparationClaim(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, target PublicationTargetMaterials, request *PublicationUploadRequest, inputSHA string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || claim == nil || !s.ForwardEnabled || s.publisherVerifierDB == nil || policy.Validate() != nil || claim.Target.Kind != c.TargetBackup || attempt < 1 {
		return c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, *claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return c.ErrClaimLost
	}
	bounded, cancel := context.WithDeadline(ctx, access.ValidUntil())
	defer cancel()
	db := &publicationFreshRenewalDB{DB: s.publisherVerifierDB, service: s, access: access, claim: *claim, attempt: attempt, policy: policy, target: target, request: request, inputSHA: inputSHA}
	fresh, err := (c.ClaimCoordinator{Executor: db, InstallationID: s.Config.InstallationID}).Renew(bounded, *claim, policy)
	if err != nil {
		return err
	}
	*claim = fresh // only the original coordinator's acknowledged SQL token
	return nil
}

func (s *DeploymentService) renewOriginalPublicationAssemblyClaim(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	current, err := s.publicationStore(ctx)
	if err != nil {
		return err
	}
	target := current.config
	current.Close()
	return s.renewOriginalPublicationPreparationClaim(ctx, claim, attempt, policy, target, nil, "")
}
