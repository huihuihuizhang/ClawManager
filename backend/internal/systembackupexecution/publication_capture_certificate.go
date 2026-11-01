package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

type publicationCertificateJob struct {
	UID        string `json:"uid"`
	Generation uint64 `json:"generation"`
	Phase      string `json:"phase"`
}
type publicationCertificateCheckpoint struct {
	Part   string `json:"part"`
	SHA256 string `json:"checkpoint_hash"`
}
type publicationCertificateStage struct {
	UID      string `json:"uid"`
	Location string `json:"location_hash"`
}
type publicationCaptureCertificatePayload struct {
	Version      string                             `json:"schema_version"`
	Installation string                             `json:"origin_installation_id"`
	Backup       string                             `json:"backup_public_id"`
	Attempt      uint64                             `json:"attempt_no"`
	Fence        string                             `json:"fencing_token"`
	Context      string                             `json:"capture_context_hash"`
	Jobs         []publicationCertificateJob        `json:"jobs"`
	Checkpoints  []publicationCertificateCheckpoint `json:"checkpoints"`
	Stages       []publicationCertificateStage      `json:"staging_resources"`
	CompletedAt  time.Time                          `json:"capture_completed_at"`
	IssuedAt     time.Time                          `json:"issued_at"`
	ExpiresAt    time.Time                          `json:"expires_at"`
	SigningKey   security.PublicationSigningKey     `json:"signing_key"`
}

// Inert facts only. The independent complete C/domain verification must already
// have authenticated every original checkpoint. No old capture Authority is
// reconstructed to decode its historical fields, and no current Job is adopted.
func publicationCertificateParts(capture publicationVerifiedCapture) ([]publicationCertificateJob, []publicationCertificateCheckpoint, error) {
	if !capture.checked() || len(capture.Parts) < 8 || len(capture.Parts) > 10000 || capture.SourceFacts.validate() != nil || !formalCandidateDigest(capture.CaptureContextSHA256) || capture.Input.CaptureAttemptNo < 1 || capture.Input.CaptureAttemptNo > 9007199254740991 {
		return nil, nil, c.ErrExecutionRecord
	}
	jobs := make([]publicationCertificateJob, 0, len(capture.Parts))
	checkpoints := make([]publicationCertificateCheckpoint, 0, len(capture.Parts))
	uids, parts, required := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, part := range capture.Parts {
		var original b.Checkpoint
		if decodeProviderDeploymentJSON(part.Checkpoint, &original) != nil || original.SchemaVersion != "system-backup-b-checkpoint.v1" || original.InstallationID != capture.Input.InstallationID || original.TaskPublicID != capture.Input.TaskPublicID || original.ConfigVersion != capture.Input.ConfigVersion || original.ConfigSHA256 != capture.Input.ConfigSHA256 || original.AttemptNo != capture.Input.CaptureAttemptNo || original.Phase != "capture" || original.InventorySHA256 != capture.Input.SourceSHA256 || original.Part != part.Part || original.InvocationSHA256 != part.InvocationSHA256 || original.ContentSHA256 != part.CipherSHA256 || original.JobUID == "" || len(original.JobUID) > 256 || original.JobGeneration < 1 || original.JobGeneration > 9007199254740991 || original.SealedRef == "" || len(original.SealedRef) > 1024 || uids[original.JobUID] || parts[part.Part] {
			return nil, nil, c.ErrExecutionRecord
		}
		roundtrip, err := json.Marshal(original)
		if err != nil || !bytes.Equal(roundtrip, part.Checkpoint) {
			return nil, nil, c.ErrExecutionRecord
		}
		canonical, err := ce.Canonical(json.RawMessage(part.Checkpoint))
		if err != nil {
			return nil, nil, err
		}
		uids[original.JobUID], parts[part.Part] = true, true
		if part.RequestedPart != "" {
			required[part.RequestedPart] = true
		}
		jobs = append(jobs, publicationCertificateJob{UID: original.JobUID, Generation: original.JobGeneration, Phase: original.Phase})
		checkpoints = append(checkpoints, publicationCertificateCheckpoint{Part: part.Part, SHA256: hash(canonical)})
	}
	for _, part := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		if !required[part] {
			return nil, nil, c.ErrExecutionRecord
		}
	}
	if len(required) != 6 || !parts[ce.Part] || !parts[ce.ProofPart] {
		return nil, nil, c.ErrExecutionRecord
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].UID < jobs[j].UID })
	sort.Slice(checkpoints, func(i, j int) bool { return checkpoints[i].Part < checkpoints[j].Part })
	return jobs, checkpoints, nil
}

type publicationCertificateSQLFacts struct {
	stage        originalStageResource
	locationHash string
	completed    time.Time
	ttl          int64
	taskVersion  uint64
}

// The business snapshot must travel with the prepared signing input. The
// security record deliberately knows nothing about original 104 resources.
// Keeping it private prevents a caller from staging the inner record alone.
type preparedPublicationCaptureCertificate struct {
	service  *DeploymentService
	access   *security.SQLPublisherCaptureAuthority
	facts    security.PublisherCaptureFacts
	capture  publicationVerifiedCapture
	original publicationCertificateSQLFacts
	record   *security.SQLPreparedPublicationRecord
	claim    c.ClaimToken
	payload  []byte
}

// Stage checks the SAME original facts in the caller's real signing-input
// transaction. Local material checks and original SQL share that transaction;
// workload and provider network calls remain outside it.
// A failed Stage requires the caller to roll back the transaction.
func (p *preparedPublicationCaptureCertificate) Stage(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.service == nil || p.access == nil || p.record == nil || tx == nil || !p.capture.checked() {
		return c.ErrExecutionAuthority
	}
	if err := lockOriginalCertificateTask(ctx, tx, p); err != nil {
		return err
	}
	guard, err := p.access.Bind(ctx, tx)
	if err != nil || guard.Facts() != p.facts {
		return c.ErrExecutionAuthority
	}
	if _, err = p.service.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), p.capture, &p.original); err != nil {
		return err
	}
	capacity, retention, now, err := p.service.originalCertificateCapacityTx(ctx, tx, p)
	if err != nil {
		return err
	}
	if err = p.service.stageOriginalCertificateEvidenceBytes(ctx, tx, p, originalCaptureCertificatePreparedID(p.capture), originalCaptureCertificatePreparedVersion, p.payload, capacity, retention, now); err != nil {
		return err
	}
	if err = p.record.Stage(ctx, tx); err != nil {
		return err
	}
	if _, err = p.service.readPublicationCertificateFactsTx(ctx, tx, guard.Facts(), p.capture, &p.original); err != nil {
		return err
	}
	return guard.RecheckTx(ctx, tx)
}

// Only the business wrapper is returned to the owner. The original signer
// still requires committed frozen input and its current signing authority.
func (p *preparedPublicationCaptureCertificate) SignCommitted(ctx context.Context) ([]byte, string, error) {
	if p == nil || p.record == nil || p.access == nil || !p.capture.checked() || p.access.Check(ctx) != nil {
		return nil, "", c.ErrExecutionAuthority
	}
	known, found, err := p.service.loadOriginalPublicationCaptureCertificate(ctx, p.claim, p.capture.Input.CaptureAttemptNo, p.capture)
	if err != nil {
		return nil, "", err
	}
	if found {
		if !originalCertificateMatchesPreparedPayload(known.bytes, p.payload) {
			return nil, "", c.ErrExecutionRecord
		}
		return bytes.Clone(known.bytes), known.sha256, nil
	}
	if err = p.beginOriginalCertificateSign(ctx); err != nil {
		return nil, "", err
	}
	raw, sum, err := p.record.SignCommitted(ctx)
	if err != nil {
		return nil, "", errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	if hash(raw) != sum {
		return nil, "", c.ErrExecutionCommitUnknown
	}
	stored, err := p.service.storeOriginalPublicationCaptureCertificate(ctx, p, raw)
	if err != nil {
		return nil, "", errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	return bytes.Clone(stored.bytes), stored.sha256, nil
}

// Current original SQL, not a replacement staging ledger. The public path
// currently has exactly one original controller-owned capture directory. An
// additional/unknown capture resource is refused rather than omitted from the
// certificate. Publish candidates are deliberately outside this capture scope.
func (s *DeploymentService) readPublicationCertificateFactsTx(ctx context.Context, tx *sql.Tx, facts security.PublisherCaptureFacts, capture publicationVerifiedCapture, expected *publicationCertificateSQLFacts) (publicationCertificateSQLFacts, error) {
	var out publicationCertificateSQLFacts
	if s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Staging == nil || facts.CaptureEpoch != capture.Input.CaptureEpoch || facts.CaptureResultSHA256 != capture.CaptureResultSHA256 || facts.ConfigSHA256 != capture.Input.ConfigSHA256 || facts.ConfigVersion != capture.Input.ConfigVersion || facts.CaptureAttemptNo != capture.Input.CaptureAttemptNo || facts.Status != "validating" {
		return out, c.ErrExecutionAuthority
	}
	var now time.Time
	var lease, deadline time.Time
	var owner string
	if tx.QueryRowContext(ctx, `SELECT a.finished_at,cfg.capture_certificate_ttl_seconds,task.controller_owner,task.controller_lease_expires_at,task.deadline_at,task.row_version,UTC_TIMESTAMP(6) FROM system_backup_v2_attempts a JOIN system_backup_v2_backups task ON task.public_id=a.target_public_id AND task.origin_installation_id=? JOIN system_backup_v2_configs cfg ON cfg.origin_installation_id=task.origin_installation_id AND cfg.version=task.config_version AND cfg.config_sha256=task.config_snapshot_sha256 WHERE a.target_type='backup' AND a.target_public_id=? AND a.attempt_no=? AND a.phase='capture' AND a.status='sealed' AND task.status='validating' FOR SHARE`, facts.InstallationID, facts.BackupPublicID, facts.CaptureAttemptNo).Scan(&out.completed, &out.ttl, &owner, &lease, &deadline, &out.taskVersion, &now) != nil || owner != s.PublisherOwner || !lease.Equal(facts.ClaimLeaseUntil) || !deadline.Equal(facts.TaskDeadline) || !now.Before(lease) || !now.Before(deadline) || out.taskVersion < 1 || out.completed.Before(facts.SourceResumedAt) || out.completed.Before(capture.Control.Generated) || out.completed.After(now) || out.ttl < 3600 || out.ttl > 86400 || !now.Add(time.Duration(out.ttl)*time.Second).After(facts.TaskDeadline) {
		return out, c.ErrExecutionRecord
	}
	location := filepath.Join(s.Runtime.Owner.Staging.Name(), facts.BackupPublicID)
	base := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: facts.InstallationID, Task: facts.BackupPublicID, Phase: "capture", Attempt: facts.CaptureAttemptNo, ConfigVersion: facts.ConfigVersion, ConfigSHA256: facts.ConfigSHA256, Location: location}
	raw, _ := json.Marshal(base)
	base.PhaseUID = "capture-" + hash(raw)
	out.stage.owner = base
	rows, err := tx.QueryContext(ctx, `SELECT public_id,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,observed_name,observed_uid,lifecycle,row_version FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase IN ('capture','secret_capture') ORDER BY public_id FOR SHARE`, facts.InstallationID, facts.BackupPublicID, facts.CaptureAttemptNo)
	if err != nil {
		return publicationCertificateSQLFacts{}, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var phase, phaseUID, kind, actualLocation, observedName, observedUID string
		if rows.Scan(&out.stage.owner.Resource, &phase, &phaseUID, &kind, &actualLocation, &out.locationHash, &out.stage.mac, &out.stage.owner.KeyVersion, &observedName, &observedUID, &out.stage.lifecycle, &out.stage.version) != nil || count != 1 || phase != base.Phase || phaseUID != base.PhaseUID || kind != "hostpath" || actualLocation != location || out.locationHash != hash([]byte(location)) || !formalCandidateDigest(out.stage.mac) || out.stage.owner.KeyVersion == "" || out.stage.lifecycle != "ready" || out.stage.version < 1 || observedName != facts.BackupPublicID || observedUID != out.stage.owner.Resource {
			return publicationCertificateSQLFacts{}, c.ErrExecutionRecord
		}
	}
	if rows.Err() != nil || rows.Close() != nil || count != 1 {
		return publicationCertificateSQLFacts{}, c.ErrExecutionRecord
	}
	if expected != nil && out != *expected {
		return publicationCertificateSQLFacts{}, c.ErrExecutionRecord
	}
	return out, nil
}

// Prepare only: the caller must freeze this original input with Stage in its
// own original transaction, commit, then call SignCommitted. Actual artifact
// JCS/JWS still uses the original external capture-certificate signing purpose.
func (s *DeploymentService) prepareOriginalCaptureCertificate(ctx context.Context, claim c.ClaimToken, attempt uint64, capture publicationVerifiedCapture, signers *security.SQLPublicationTaskSigners) (*preparedPublicationCaptureCertificate, error) {
	if s == nil {
		return nil, c.ErrExecutionAuthority
	}
	jobs, checkpoints, err := publicationCertificateParts(capture)
	if err != nil || signers == nil || attempt != capture.Input.CaptureAttemptNo || claim.Target.PublicID != capture.Input.TaskPublicID {
		return nil, c.ErrExecutionRecord
	}
	key, err := signers.PublicationSigningKey(ctx, "capture_certificate")
	if err != nil {
		return nil, err
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	facts := guard.Facts()
	original, err := s.readPublicationCertificateFactsTx(ctx, tx, facts, capture, nil)
	if err == nil {
		err = originalCertificatePreparationAbsentTx(ctx, tx, capture)
	}
	var issued time.Time
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&issued) != nil || guard.RecheckTx(ctx, tx) != nil {
		tx.Rollback()
		return nil, c.ErrExecutionRecord
	}
	if tx.Rollback() != nil {
		return nil, c.ErrExecutionAuthority
	}
	// Read the actual original marker/key and directory after releasing SQL.
	// This consumes inert originalStageOwner facts; no capture claim/gate token
	// is synthesized and no source/Generate operation is requested.
	if s.Runtime.Owner.verifyStageDirectory(original.stage) != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	final, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer final.Rollback()
	last, err := access.Bind(ctx, final)
	if err != nil || last.Facts() != facts {
		return nil, c.ErrExecutionAuthority
	}
	again, err := s.readPublicationCertificateFactsTx(ctx, final, last.Facts(), capture, &original)
	if err != nil || again != original || last.RecheckTx(ctx, final) != nil {
		return nil, c.ErrExecutionRecord
	}
	if final.Rollback() != nil {
		return nil, c.ErrExecutionAuthority
	}
	payload := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: facts.InstallationID, Backup: facts.BackupPublicID, Attempt: attempt, Fence: strconv.FormatUint(facts.CaptureEpoch, 10), Context: capture.CaptureContextSHA256, Jobs: jobs, Checkpoints: checkpoints, Stages: []publicationCertificateStage{{UID: original.stage.owner.Resource, Location: original.locationHash}}, CompletedAt: original.completed, IssuedAt: issued, ExpiresAt: issued.Add(time.Duration(original.ttl) * time.Second), SigningKey: key}
	raw, err := ce.Canonical(payload)
	if err != nil {
		return nil, c.ErrExecutionRecord
	}
	record, err := signers.PreparePublicationRecord(ctx, "capture_certificate", raw)
	if err != nil {
		return nil, err
	}
	return &preparedPublicationCaptureCertificate{service: s, access: access, facts: facts, capture: capture, original: original, record: record, claim: claim, payload: bytes.Clone(raw)}, nil
}
