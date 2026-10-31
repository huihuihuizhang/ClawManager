package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
)

func loadFinalizedControlSourceSQL(ctx context.Context, tx *sql.Tx, seed ce.CaptureLocator) (ce.PreparedSource, []ce.RegisteredEvidence, error) {
	id, err := ce.FinalizedSourceEvidenceID(seed)
	if err != nil {
		return ce.PreparedSource{}, nil, err
	}
	var checksum string
	if err = tx.QueryRowContext(ctx, `SELECT content_checksum FROM system_backup_v2_evidence WHERE public_id=? FOR SHARE`, id).Scan(&checksum); err != nil {
		return ce.PreparedSource{}, nil, err
	}
	seal, err := ce.LoadRegisteredSQL(ctx, tx, seed.Expected.Scope, ce.EvidenceRef{PublicID: id, SHA256: checksum})
	if err != nil {
		return ce.PreparedSource{}, nil, err
	}
	refs, err := ce.FinalizedSourceReferences(seed, seal)
	if err != nil {
		return ce.PreparedSource{}, nil, err
	}
	chunks := []ce.RegisteredEvidence{}
	for _, ref := range refs {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, seed.Expected.Scope, ref)
		if err != nil {
			return ce.PreparedSource{}, nil, err
		}
		chunks = append(chunks, entry)
	}
	final, err := ce.ReadFinalizedSourceSeal(seed, seal, chunks...)
	if err != nil {
		return ce.PreparedSource{}, nil, err
	}
	entries := make([]ce.RegisteredEvidence, 0, len(final.Evidence))
	for _, ref := range final.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, seed.Expected.Scope, ref)
		if err != nil {
			return ce.PreparedSource{}, nil, err
		}
		entries = append(entries, entry)
	}
	prepared, err := ce.VerifyFinalized(ctx, seed, final, entries)
	if err == nil {
		err = recheckFinalizedBusinessSQL(ctx, tx, seed, prepared)
	}
	if err != nil {
		clear(prepared.SidecarJSON)
		clear(prepared.ProofsJSON)
		return ce.PreparedSource{}, nil, err
	}
	return prepared, append(chunks, seal), err
}

func recheckFinalizedBusinessSQL(ctx context.Context, tx *sql.Tx, seed ce.CaptureLocator, prepared ce.PreparedSource) error {
	basis, err := ce.OriginalOwnedBasis(ctx, seed, prepared)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT observed_uid,key_use_json,candidate_sha256,result_sha256,revoked,lifecycle,stopped_at FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' FOR SHARE`, seed.Expected.Backup, seed.Expected.Attempt)
	if err != nil {
		return err
	}
	type current struct {
		uid               string
		use               worker.KeyUseLease
		candidate, result sql.NullString
		revoked           bool
		lifecycle         string
		stopped           sql.NullTime
	}
	byInvocation := map[string]current{}
	for rows.Next() {
		var got current
		var raw []byte
		if rows.Scan(&got.uid, &raw, &got.candidate, &got.result, &got.revoked, &got.lifecycle, &got.stopped) != nil {
			rows.Close()
			return c.ErrExecutionRecord
		}
		if len(raw) == 0 {
			continue
		}
		if decodeProviderDeploymentJSON(raw, &got.use) != nil {
			rows.Close()
			return c.ErrExecutionRecord
		}
		id := got.use.Identity.InvocationSHA256
		if _, exists := byInvocation[id]; exists {
			rows.Close()
			return c.ErrExecutionRecord
		}
		byInvocation[id] = got
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, part := range basis.Parts {
		got, ok := byInvocation[part.InvocationSHA256]
		if !ok || got.uid == "" || got.uid != got.use.Identity.JobUID || got.use.State != "finished" || got.use.Access.Request.Context.BackupPublicID != seed.Expected.Backup || got.use.Access.Request.Context.Part != part.Part || got.revoked || got.lifecycle != "ready" || got.stopped.Valid || !got.candidate.Valid || !got.result.Valid || got.candidate.String != part.CandidateSHA256 || got.result.String != part.ResultSHA256 {
			return c.ErrExecutionRecord
		}
		var checksum string
		if tx.QueryRowContext(ctx, `SELECT content_checksum FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='backup' AND owner_target_public_id=? AND evidence_type='diagnostic' AND storage_state='inline' AND observed_health='healthy' AND evidence_failure_code='none' AND expires_at>UTC_TIMESTAMP(6) FOR SHARE`, part.ResultEvidenceRef, seed.Expected.Backup).Scan(&checksum) != nil || checksum != part.ResultSHA256 {
			return c.ErrExecutionRecord
		}
	}
	return nil
}

// Admit seals BEFORE dispatching any CE Job or reserving/using its Generate.
// The one immutable final
// source seal belongs in original evidence, not a second task state/cache.
// Workload/provider reads complete before its final original SQL transaction.
func (s *DeploymentService) prepareFinalizedControlSource(ctx context.Context, in d.Input, seed ce.CaptureLocator) error {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || seed.Validate() != nil || seed.Finalization == nil || s.checkProductionCaptureMaterials() != nil {
		return c.ErrExecutionAuthority
	}
	o := s.Runtime.Owner
	wrapper, ok := o.Gate.Authority.Authorization.(deploymentAuthorization)
	if !ok || wrapper.Service != s || s.Forward.CheckDeployment(ctx, o.Gate.Authority.DB) != nil {
		return c.ErrExecutionAuthority
	}
	if s.captureMaterials == nil || s.captureMaterials.ControlEvidenceSource == nil {
		return c.ErrExecutionAuthority
	}
	mount := *s.captureMaterials.ControlEvidenceSource
	// This static source-owner delegation predates a CE Job. It grants no Job
	// identity: the actual current controller/claim and per-part Unwrap above
	// remain independent mandatory authorities.
	sourceIdentity := k.JobIdentity{Namespace: o.Namespace, ServiceAccountUID: o.Security.ServiceAccountUID}
	firstGrant, err := worker.ReadControlEvidenceSourceGrant(ctx, mount, seed.Expected, sourceIdentity, true)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	bounded, cancel := context.WithDeadline(ctx, firstGrant.Until)
	defer cancel()
	ctx = bounded
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	guard, err := o.Gate.Authority.Bind(ctx, tx, in.Authority)
	if err != nil {
		tx.Rollback()
		return err
	}
	existing, _, existingErr := loadFinalizedControlSourceSQL(ctx, tx, seed)
	if existingErr == nil {
		clear(existing.SidecarJSON)
		clear(existing.ProofsJSON)
		finalGrant, grantErr := worker.ReadControlEvidenceSourceGrant(ctx, mount, seed.Expected, sourceIdentity, true)
		err = guard.Recheck(ctx, tx)
		if grantErr != nil || finalGrant != firstGrant {
			err = c.ErrExecutionAuthority
		}
		tx.Rollback()
		return err
	}
	if !errors.Is(existingErr, sql.ErrNoRows) {
		tx.Rollback()
		return existingErr
	}
	baseLocator, err := seed.BaseSnapshot()
	if err != nil {
		tx.Rollback()
		return err
	}
	baseEntries := []ce.RegisteredEvidence{}
	for _, ref := range baseLocator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, seed.Expected.Scope, ref)
		if err != nil {
			tx.Rollback()
			return err
		}
		baseEntries = append(baseEntries, entry)
	}
	if err = guard.Recheck(ctx, tx); err != nil {
		tx.Rollback()
		return err
	}
	if err = tx.Rollback(); err != nil {
		return err
	}
	base, err := ce.Rebuild(ctx, baseLocator, baseEntries)
	if err != nil {
		return err
	}
	defer clear(base.SidecarJSON)
	defer clear(base.ProofsJSON)
	owners, parts, err := s.deriveOriginalOwnedReports(ctx, in, seed)
	if err != nil {
		return err
	}
	var generated time.Time
	if o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&generated) != nil {
		return c.ErrExecutionAuthority
	}
	proposal, err := ce.AssembleFinalized(ctx, seed, base, generated, owners)
	if err != nil {
		return err
	}
	defer clear(proposal.Prepared.SidecarJSON)
	defer clear(proposal.Prepared.ProofsJSON)
	seal, err := ce.SealFinalizedSource(ctx, seed, proposal.Prepared.Locator, proposal.Evidence)
	if err != nil {
		return err
	}
	entries := append(append([]ce.RegisteredEvidence{}, proposal.Evidence...), seal.LocatorChunks...)
	entries = append(entries, seal.Seal)
	// Final exact snapshot: original claim/plan/result identities, actual role,
	// immutable registered bodies and current physical metadata capacity. No
	// Kubernetes/provider call occurs while these original locks are held.
	tx, err = o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	guard, err = o.Gate.Authority.Bind(ctx, tx, in.Authority)
	if err != nil {
		return err
	}
	if err = recheckOriginalOwnedParts(ctx, tx, in, parts); err != nil {
		return err
	}
	current, _, currentErr := loadFinalizedControlSourceSQL(ctx, tx, seed)
	if currentErr == nil {
		clear(current.SidecarJSON)
		clear(current.ProofsJSON)
		finalGrant, grantErr := worker.ReadControlEvidenceSourceGrant(ctx, mount, seed.Expected, sourceIdentity, true)
		if grantErr != nil || finalGrant != firstGrant || s.checkProductionCaptureMaterials() != nil {
			return c.ErrExecutionAuthority
		}
		return guard.Recheck(ctx, tx)
	}
	if !errors.Is(currentErr, sql.ErrNoRows) {
		return currentErr
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE`, in.Authority.InstallationID, in.Authority.ConfigVersion).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return c.ErrExecutionAuthority
	}
	until := now.Add(time.Duration(retention) * time.Second).UTC().Truncate(time.Microsecond)
	if !until.After(in.Authority.DeadlineAt) {
		return c.ErrExecutionAuthority
	}
	total := 0
	baseRefs := map[string]bool{}
	for _, ref := range baseLocator.Evidence {
		baseRefs[ref.PublicID] = true
	}
	for _, entry := range entries {
		if !baseRefs[entry.PublicID] {
			total += len(entry.Payload)
		}
	}
	if (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, total) != nil {
		return c.ErrExecutionAuthority
	}
	if err = ce.RegisterSQL(ctx, tx, seed.Expected.Scope, entries, until); err != nil {
		return err
	}
	readback, _, err := loadFinalizedControlSourceSQL(ctx, tx, seed)
	if err != nil {
		return err
	}
	defer clear(readback.SidecarJSON)
	defer clear(readback.ProofsJSON)
	if readback.SidecarSHA256 != proposal.Prepared.SidecarSHA256 || readback.ProofsSHA256 != proposal.Prepared.ProofsSHA256 || s.checkProductionCaptureMaterials() != nil || guard.Recheck(ctx, tx) != nil {
		return c.ErrExecutionAuthority
	}
	finalGrant, grantErr := worker.ReadControlEvidenceSourceGrant(ctx, mount, seed.Expected, sourceIdentity, true)
	if grantErr != nil || finalGrant != firstGrant {
		return c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

type deploymentControlAuthorizer struct {
	service *DeploymentService
	owner   *PublicJobOwner
}

func (a deploymentControlAuthorizer) Authorize(ctx context.Context, peer string, request worker.ControlRequest) (worker.Lease, error) {
	lease, err := a.owner.Authorize(ctx, peer, request)
	if err != nil {
		return lease, err
	}
	seed := request.Invocation.Request.ControlEvidence
	if seed == nil || seed.Finalization == nil || request.Action != "ready" {
		return lease, nil
	}
	if a.service == nil || a.service.Runtime == nil || a.service.Runtime.Owner != a.owner || request.Invocation.ProviderKey == nil || seed.Finalization.CaptureContextSHA256 != request.Invocation.ProviderKey.Request.Context.CaptureContextHash {
		return worker.Lease{}, worker.ErrExecution
	}
	bounded, cancel := context.WithDeadline(ctx, lease.ExpiresAt)
	defer cancel()
	authority := d.Authority{InstallationID: seed.Expected.Installation, TaskPublicID: seed.Expected.Backup, TaskType: "backup", Phase: "capture", AttemptNo: seed.Expected.Attempt, MaintenanceOwner: seed.Expected.Backup}
	if a.owner.Gate.Authority.DB.QueryRowContext(bounded, `SELECT controller_owner,row_version,request_id,config_version,config_snapshot_sha256,deadline_at,maintenance_fencing_token FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, authority.InstallationID, authority.TaskPublicID).Scan(&authority.ClaimOwner, &authority.ClaimRowVersion, &authority.RequestID, &authority.ConfigVersion, &authority.ConfigSHA256, &authority.DeadlineAt, &authority.MaintenanceFencingToken) != nil {
		return worker.Lease{}, worker.ErrExecution
	}
	in, _, discovery, err := a.owner.input(bounded, authority, false)
	if err != nil {
		return worker.Lease{}, worker.ErrExecution
	}
	pod, ok := boundPod(bounded)
	if !ok || a.service.captureMaterials == nil || a.service.captureMaterials.ControlEvidenceSource == nil || request.Invocation.FormalCapture == nil || request.Invocation.FormalCapture.PermitDelivery == nil {
		return worker.Lease{}, worker.ErrExecution
	}
	mount := *a.service.captureMaterials.ControlEvidenceSource
	if mount.Endpoint != a.service.Config.ControlURL || bytes.Equal(mount.Issuer, request.Invocation.FormalCapture.PermitDelivery.Issuer) {
		return worker.Lease{}, worker.ErrExecution
	}
	var jobUID string
	for _, part := range discovery.Parts {
		if part.InvocationSHA256 == request.InvocationSHA256 {
			if a.owner.Gate.Authority.DB.QueryRowContext(bounded, `SELECT observed_uid FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND revoked=FALSE AND lifecycle='ready' AND stopped_at IS NULL`, authority.TaskPublicID, authority.AttemptNo, part.Intent.Namespace, part.Intent.Name).Scan(&jobUID) != nil {
				return worker.Lease{}, worker.ErrExecution
			}
		}
	}
	if jobUID == "" {
		return worker.Lease{}, worker.ErrExecution
	}
	identity := k.JobIdentity{Namespace: pod.Namespace, PodUID: pod.UID, ServiceAccountUID: pod.ServiceAccountUID, JobUID: jobUID, InvocationSHA256: request.InvocationSHA256, ExecutionGrantSHA256: a.owner.Identity.GrantSHA256()}
	firstGrant, err := worker.ReadControlEvidenceSourceGrant(bounded, mount, seed.Expected, identity, true)
	if err != nil {
		return worker.Lease{}, worker.ErrExecution
	}
	if _, err = a.owner.finalizedControlLocator(bounded, in.Authority, *seed); err != nil {
		return worker.Lease{}, worker.ErrNotReady
	}
	last, err := a.owner.Authorize(bounded, peer, request)
	if err != nil || last.InvocationSHA256 != lease.InvocationSHA256 || a.owner.Gate.Check(bounded, authority) != nil {
		return worker.Lease{}, worker.ErrExecution
	}
	finalGrant, err := worker.ReadControlEvidenceSourceGrant(bounded, mount, seed.Expected, identity, true)
	if err != nil || finalGrant != firstGrant {
		return worker.Lease{}, worker.ErrExecution
	}
	return last, nil
}

var _ worker.Authorizer = deploymentControlAuthorizer{}

// Heavy work belongs to the existing controller capture/heartbeat context,
// before CE identity/Job dispatch. No short worker Ready RPC recalculates it.
func (o *PublicJobOwner) prepareControlEvidenceDispatch(ctx context.Context, in d.Input, part b.JobPart) error {
	var inv worker.Invocation
	if decodeProviderDeploymentJSON(part.InvocationJSON, &inv) != nil {
		return c.ErrExecutionRecord
	}
	if inv.Request.ControlEvidence == nil || inv.Request.ControlEvidence.Finalization == nil {
		return nil
	}
	wrapper, ok := o.Gate.Authority.Authorization.(deploymentAuthorization)
	if !ok || wrapper.Service == nil || wrapper.Service.Runtime == nil || wrapper.Service.Runtime.Owner != o || inv.ProviderKey == nil || inv.Request.ControlEvidence.Finalization.CaptureContextSHA256 != inv.ProviderKey.Request.Context.CaptureContextHash {
		return c.ErrExecutionAuthority
	}
	until := inv.Request.Deadline
	if in.Authority.DeadlineAt.Before(until) {
		until = in.Authority.DeadlineAt
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	return wrapper.Service.prepareFinalizedControlSource(bounded, in, *inv.Request.ControlEvidence)
}

func (o *PublicJobOwner) finalizedControlLocator(ctx context.Context, authority d.Authority, seed ce.CaptureLocator) (ce.CaptureLocator, error) {
	if o == nil || seed.Expected.Backup != authority.TaskPublicID || seed.Expected.Attempt != authority.AttemptNo || seed.Expected.ConfigSHA256 != authority.ConfigSHA256 {
		return ce.CaptureLocator{}, c.ErrExecutionAuthority
	}
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ce.CaptureLocator{}, err
	}
	defer tx.Rollback()
	guard, err := o.Gate.Authority.Bind(ctx, tx, authority)
	if err != nil {
		return ce.CaptureLocator{}, err
	}
	prepared, _, err := loadFinalizedControlSourceSQL(ctx, tx, seed)
	if err != nil {
		return ce.CaptureLocator{}, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	if guard.Recheck(ctx, tx) != nil {
		return ce.CaptureLocator{}, c.ErrExecutionAuthority
	}
	return prepared.Locator, nil
}
