package systembackupexecution

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
)

// Inert ORIGINAL 104 facts only. This is not permission to create/send a Job,
// put/read/delete a candidate, mark it sealed or finalize an artifact.
type publicationCandidateIntent struct {
	owner                    originalStageOwner
	MAC, Lifecycle, Checksum string
	Bytes                    int64
	RowVersion               uint64
}

// The same current publisher binds both the task and its original 104 intent.
// The administrator-pinned target explicitly selects a disjoint remote root.
// No original capture execution claim is fabricated or used for this phase.
func (s *DeploymentService) beginPublicationCandidate(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, request PublicationUploadRequest) (publicationCandidateIntent, error) {
	var zero publicationCandidateIntent
	if s == nil || s.staging == nil || target.RemoteStagingRoot == "" {
		return zero, c.ErrExecutionAuthority
	}
	manifest, key, err := request.validate()
	if err != nil {
		return zero, err
	}
	if request.Installation != target.InstallationID || request.Backup != claim.Target.PublicID || request.Attempt != attempt || request.Endpoint != target.Endpoint || request.Region != target.Region || request.Bucket != target.Bucket || request.ArtifactRoot != target.Root || request.RemoteStagingRoot != target.RemoteStagingRoot || request.CAHash != target.CASHA256 {
		return zero, c.ErrExecutionAuthority
	}
	current, err := s.publicationStore(ctx)
	if err != nil {
		return zero, err
	}
	same := reflect.DeepEqual(current.config, target)
	current.Close()
	if !same {
		return zero, c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	baseRequest := request
	baseRequest.CandidateOwnerHMAC = ""
	if baseRequest.Version == publicationPresignedUploadVersion {
		baseRequest.CredentialHash = ""
	}
	requestBytes, _ := json.Marshal(baseRequest)
	locationBytes, _ := json.Marshal(struct{ Endpoint, Bucket, Key string }{target.Endpoint, target.Bucket, key})
	owner := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: target.InstallationID, Task: claim.Target.PublicID, Attempt: attempt, Phase: "publish", PhaseUID: "publish-" + hash(requestBytes), Location: string(locationBytes)}
	if len(owner.Location) > 1024 {
		return zero, c.ErrExecutionRecord
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, err
	}
	facts := guard.Facts()
	if facts.Status != "validating" && facts.Status != "publishing" {
		return zero, c.ErrExecutionAuthority
	}
	if !time.Now().Before(request.Deadline) || request.Deadline.After(facts.TaskDeadline) {
		return zero, c.ErrExecutionAuthority
	}
	if err = s.checkPublicationTargetTx(ctx, tx, facts, target); err != nil {
		return zero, err
	}
	owner.ConfigVersion, owner.ConfigSHA256 = facts.ConfigVersion, facts.ConfigSHA256
	r := publicationCandidateIntent{owner: owner, Checksum: hash(manifest), Bytes: int64(len(manifest))}
	var installation, backup, phase, phaseUID, kind, locator, keyVersion string
	var storedAttempt uint64
	err = tx.QueryRowContext(ctx, "SELECT public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,owner_marker_hmac,owner_marker_key_version,candidate_checksum_sha256,candidate_length_bytes,lifecycle,row_version FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND location_sha256=? FOR UPDATE", owner.Installation, hash(locationBytes)).Scan(&r.owner.Resource, &installation, &backup, &storedAttempt, &phase, &phaseUID, &kind, &locator, &r.MAC, &keyVersion, &r.Checksum, &r.Bytes, &r.Lifecycle, &r.RowVersion)
	if err == nil {
		if installation != owner.Installation || backup != owner.Task || storedAttempt != attempt || phase != "publish" || phaseUID != owner.PhaseUID || kind != "remote_manifest_candidate" || locator != owner.Location || r.Checksum != hash(manifest) || r.Bytes != int64(len(manifest)) || r.Lifecycle != "creating" || !formalCandidateDigest(r.MAC) {
			return zero, c.ErrExecutionRecord
		}
		if request.CandidateOwnerHMAC != "" && request.CandidateOwnerHMAC != r.MAC {
			return zero, c.ErrExecutionRecord
		}
		r.owner.KeyVersion = keyVersion
		if _, err = uuid.Parse(keyVersion); err != nil {
			return zero, c.ErrExecutionRecord
		}
		if err = guard.RecheckTx(ctx, tx); err != nil {
			return zero, err
		}
		if err = tx.Commit(); err != nil {
			return zero, c.ErrExecutionCommitUnknown
		}
		if err = s.verifyPublicationCandidateKey(ctx, r); err != nil {
			return zero, err
		}
		if err = access.Check(ctx); err != nil {
			return zero, err
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	if request.CandidateOwnerHMAC != "" {
		return zero, c.ErrExecutionRecord
	}
	keyBytes := make([]byte, 32)
	if _, err = rand.Read(keyBytes); err != nil {
		return zero, err
	}
	defer clear(keyBytes)
	r.owner.Resource = "sbs_" + uuid.NewString()
	r.owner.KeyVersion = uuid.NewString()
	r.MAC = stageMAC(r.owner, keyBytes)
	r.Lifecycle = "creating"
	r.RowVersion = 1
	var capacity int64
	if err = tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=?", facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256).Scan(&capacity); err != nil {
		return zero, err
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(locationBytes)+1024); err != nil {
		return zero, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_staging_resources(public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,candidate_checksum_sha256,candidate_length_bytes) VALUES(?,?,?,?,'publish',?,'remote_manifest_candidate',?,?,?,?,?,?)", r.owner.Resource, owner.Installation, owner.Task, attempt, owner.PhaseUID, owner.Location, hash(locationBytes), r.MAC, r.owner.KeyVersion, r.Checksum, r.Bytes)
	if err != nil {
		return zero, err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	// Acknowledged original intent precedes even its private owner-key file.
	// An unknown commit returns above, clears the ephemeral key and sends nothing.
	keys, err := stageKeyRoot(s.staging, true)
	if err != nil {
		return zero, err
	}
	err = writeStageOwnerKey(ctx, keys, r.owner.KeyVersion+".key", keyBytes)
	keys.Close()
	if err != nil {
		return zero, err
	}
	if err = access.Check(ctx); err != nil {
		return zero, err
	}
	return r, nil
}

func (s *DeploymentService) verifyPublicationCandidateKey(ctx context.Context, r publicationCandidateIntent) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	keys, err := stageKeyRoot(s.staging, false)
	if err != nil {
		return err
	}
	defer keys.Close()
	key, err := readStageFile(keys, r.owner.KeyVersion+".key", 32)
	if err != nil {
		return err
	}
	defer clear(key)
	if len(key) != 32 || !hmac.Equal([]byte(stageMAC(r.owner, key)), []byte(r.MAC)) {
		return c.ErrExecutionRecord
	}
	return nil
}
