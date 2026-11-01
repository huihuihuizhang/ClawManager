package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// This immutable original intent permits one suspend=false patch. It preserves
// the original 121 spec and material-owner generation; neither is rewritten to
// make an already started Job look like its original suspended definition.
type publicationActivation struct {
	Version, MaterialIntentSHA256, SecretUID, JobUID, JobSpecSHA256 string
	ResourceVersion, IdentityRef, IdentityVersion                   string
	BeforeGeneration, AfterGeneration                               int64
	BoundAt, ExpiresAt                                              time.Time
}

func publicationActivationIdentity(namespace, name, uid string) string {
	return "k8s-secret://" + namespace + "/" + name + "#" + uid
}

func (s *DeploymentService) loadPublicationActivationTx(ctx context.Context, tx *sql.Tx, intent publicationMaterialIntent) (*publicationActivation, error) {
	id := publicationMaterialID(intent.Installation, intent.Backup, intent.Attempt)
	raw, err := loadPublicationMetadata(ctx, tx, intent.Backup, id+"_activation")
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload'`, intent.Installation, intent.Backup, intent.Attempt).Scan(&count) != nil || count != 0 {
			return nil, c.ErrExecutionRecord
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a publicationActivation
	material, _ := ce.Canonical(intent)
	if decodeProviderDeploymentJSON(raw, &a) != nil || a.Version != "system-backup-original-publication-activation.v1" || a.MaterialIntentSHA256 != hash(material) || a.SecretUID == "" || a.JobUID == "" || !formalCandidateDigest(a.JobSpecSHA256) || a.ResourceVersion == "" || a.BeforeGeneration < 1 || a.AfterGeneration != a.BeforeGeneration+1 || a.AfterGeneration <= a.BeforeGeneration || !formalCandidateDigest(a.IdentityVersion) || a.IdentityRef != publicationActivationIdentity(intent.Namespace, intent.Name, a.SecretUID) || a.BoundAt.IsZero() || !a.BoundAt.Before(a.ExpiresAt) || !a.ExpiresAt.Equal(intent.Deadline) {
		return nil, c.ErrExecutionRecord
	}
	ownerRaw, err := loadPublicationMetadata(ctx, tx, intent.Backup, id+"_job_owner")
	var owner publicationMaterialJobOwner
	if err != nil || decodeProviderDeploymentJSON(ownerRaw, &owner) != nil || owner.Version != "system-backup-original-publication-material-job-owner.v1" || owner.MaterialIntentSHA256 != a.MaterialIntentSHA256 || owner.SecretUID != a.SecretUID || owner.JobUID != a.JobUID || owner.JobSpecSHA256 != a.JobSpecSHA256 || owner.Generation != a.BeforeGeneration {
		return nil, c.ErrExecutionRecord
	}
	var state, spec, namespace, namespaceUID, name, uid string
	if tx.QueryRowContext(ctx, `SELECT send_state,spec_sha256,namespace_name,namespace_uid,job_name,job_uid FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' FOR SHARE`, intent.Installation, intent.Backup).Scan(&state, &spec, &namespace, &namespaceUID, &name, &uid) != nil || state != "bound" || spec != a.JobSpecSHA256 || namespace != intent.Namespace || namespaceUID != s.Config.NamespaceUID || name != "sbp-"+intent.RequestSHA256[:32] || uid != a.JobUID {
		return nil, c.ErrExecutionRecord
	}
	var generation int64
	var ref, version string
	var boundAt, expiresAt time.Time
	if tx.QueryRowContext(ctx, `SELECT job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload' FOR SHARE`, intent.Installation, intent.Backup, intent.Attempt).Scan(&uid, &generation, &ref, &version, &boundAt, &expiresAt) != nil || uid != a.JobUID || generation != a.AfterGeneration || ref != a.IdentityRef || version != a.IdentityVersion || !boundAt.Equal(a.BoundAt) || !expiresAt.Equal(a.ExpiresAt) {
		return nil, c.ErrExecutionRecord
	}
	var status string
	var started time.Time
	if tx.QueryRowContext(ctx, `SELECT status,started_at FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' FOR SHARE`, intent.Backup, intent.Attempt).Scan(&status, &started) != nil || status != "running" || !started.Equal(a.BoundAt) {
		return nil, c.ErrExecutionRecord
	}
	return &a, nil
}

func (s *DeploymentService) loadPublicationJobActivationTx(ctx context.Context, tx *sql.Tx, claim c.ClaimToken, attempt uint64, requestSHA string) (*publicationActivation, error) {
	raw, err := loadPublicationMetadata(ctx, tx, claim.Target.PublicID, publicationMaterialID(s.Config.InstallationID, claim.Target.PublicID, attempt))
	if errors.Is(err, sql.ErrNoRows) {
		// The lower-level suspended constructor also has isolated transport
		// callers. An absent capsule can never authorize a started Job.
		var count int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish'`, s.Config.InstallationID, claim.Target.PublicID, attempt).Scan(&count) != nil || count != 0 {
			return nil, c.ErrExecutionRecord
		}
		return nil, nil
	}
	var intent publicationMaterialIntent
	if err != nil || decodeProviderDeploymentJSON(raw, &intent) != nil || intent.Version != "system-backup-original-publication-materials.v1" || intent.Installation != s.Config.InstallationID || intent.Backup != claim.Target.PublicID || intent.Attempt != attempt || intent.Namespace != s.Config.Namespace || intent.RequestSHA256 != requestSHA || !formalCandidateDigest(requestSHA) {
		return nil, c.ErrExecutionRecord
	}
	return s.loadPublicationActivationTx(ctx, tx, intent)
}

func publicationJobMatchesActivation(want, got *batchv1.Job, a *publicationActivation) bool {
	if got == nil || got.Spec.Suspend == nil || got.DeletionTimestamp != nil {
		return false
	}
	if a == nil {
		return *got.Spec.Suspend && got.Generation == 1 && sameJob(want, got)
	}
	if string(got.UID) != a.JobUID || got.Annotations["backup.clawmanager.io/v2-spec-sha256"] != a.JobSpecSHA256 {
		return false
	}
	if *got.Spec.Suspend {
		return got.Generation == a.BeforeGeneration && sameJob(want, got)
	}
	active := want.DeepCopy()
	no := false
	active.Spec.Suspend = &no
	return got.Generation == a.AfterGeneration && sameJob(active, got)
}

func (s *DeploymentService) bindPublicationReceiverAndActivation(ctx context.Context, claim c.ClaimToken, attempt uint64, m *publicationJobMaterials, job *batchv1.Job, specSHA string) (*publicationActivation, bool, error) {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil || checkPublicationMaterialCertificate(s, m) != nil {
		return nil, false, c.ErrExecutionAuthority
	}
	block, _ := pem.Decode(m.secret.Data["tls.crt"])
	if block == nil {
		return nil, false, c.ErrExecutionRecord
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	old, err := s.loadPublicationActivationTx(ctx, tx, m.intent)
	if err != nil {
		return nil, false, err
	}
	if old != nil {
		if old.SecretUID != string(m.secret.UID) || old.JobUID != string(job.UID) || old.JobSpecSHA256 != specSHA || old.IdentityVersion != hash(leaf.Raw) || guard.RecheckTx(ctx, tx) != nil {
			return nil, false, c.ErrExecutionRecord
		}
		return old, false, nil
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend || job.Generation < 1 || job.Generation >= 1<<62 || job.ResourceVersion == "" || leaf.NotAfter.Before(m.intent.Deadline) || publicationPreparationOpenTx(ctx, tx, m.intent.Installation, m.intent.Backup) != nil {
		return nil, false, c.ErrExecutionAuthority
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, m.intent.Installation, guard.Facts().ConfigVersion, guard.Facts().ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(guard.Facts().TaskDeadline) || !now.Before(m.intent.Deadline) {
		return nil, false, c.ErrExecutionRecord
	}
	material, _ := ce.Canonical(m.intent)
	a := &publicationActivation{Version: "system-backup-original-publication-activation.v1", MaterialIntentSHA256: hash(material), SecretUID: string(m.secret.UID), JobUID: string(job.UID), JobSpecSHA256: specSHA, ResourceVersion: job.ResourceVersion, BeforeGeneration: job.Generation, AfterGeneration: job.Generation + 1, IdentityRef: publicationActivationIdentity(m.intent.Namespace, m.intent.Name, string(m.secret.UID)), IdentityVersion: hash(leaf.Raw), BoundAt: now, ExpiresAt: m.intent.Deadline}
	raw, err := ce.Canonical(a)
	if err != nil {
		return nil, false, err
	}
	// Validate the immutable original owner and the current bound 121 again in
	// this transaction. All receiver/activation rows commit before native start.
	id := publicationMaterialID(m.intent.Installation, m.intent.Backup, attempt)
	original, err := loadPublicationMetadata(ctx, tx, m.intent.Backup, id)
	if err != nil || !bytes.Equal(original, material) {
		return nil, false, c.ErrExecutionRecord
	}
	capacityGuard := security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}
	if err = capacityGuard.Reserve(ctx, tx, capacity, len(raw)); err != nil {
		return nil, false, err
	}
	if err = capacityGuard.Reserve(ctx, tx, capacity, 8192); err != nil {
		return nil, false, err
	}
	var attemptState string
	var attemptStarted sql.NullTime
	if tx.QueryRowContext(ctx, `SELECT status,started_at FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' FOR UPDATE`, m.intent.Backup, attempt).Scan(&attemptState, &attemptStarted) != nil || attemptState != "preparing" || attemptStarted.Valid {
		return nil, false, c.ErrExecutionRecord
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_attempts SET status='running',started_at=?,row_version=row_version+1 WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND status='preparing' AND started_at IS NULL`, now, m.intent.Backup, attempt)
	if err != nil {
		return nil, false, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return nil, false, c.ErrExecutionRecord
	}
	if err = registerPublicationMetadata(ctx, tx, m.intent.Installation, m.intent.Backup, id+"_activation", raw, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return nil, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_job_observations(origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key,job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at,created_at,updated_at) VALUES(?,'backup',?,?,'publish','artifact-upload',?,?,?,?,?,?,?,?)`, m.intent.Installation, m.intent.Backup, attempt, a.JobUID, a.AfterGeneration, a.IdentityRef, a.IdentityVersion, a.BoundAt, a.ExpiresAt, now, now)
	if err != nil {
		return nil, false, err
	}
	if _, err = s.loadPublicationActivationTx(ctx, tx, m.intent); err != nil {
		return nil, false, err
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return nil, false, c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return nil, false, c.ErrExecutionCommitUnknown
	}
	return a, true, nil
}

// Only this entry point starts the original Job. It requires the original
// capsule, original 121 binding and Job-owned material before original 107.
// No SQL lock spans native I/O. An unknown patch is never repeated.
func (s *DeploymentService) ensureStartedPublicationJob(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, proposed PublicationUploadRequest) (*batchv1.Job, error) {
	job, m, err := s.ensureDurableSuspendedPublicationJob(ctx, claim, attempt, target, proposed)
	if err != nil {
		return nil, err
	}
	m.Close()
	if job.Spec.Suspend == nil {
		return nil, c.ErrExecutionRecord
	}
	if !*job.Spec.Suspend {
		return job, nil // durable reopen already authenticated original activation
	}
	m, err = s.bindPublicationMaterialJobOwner(ctx, claim, attempt, target)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	job, specSHA, err := s.readBoundPublicationJob(ctx, claim, attempt, m)
	if err != nil {
		return nil, err
	}
	a, send, err := s.bindPublicationReceiverAndActivation(ctx, claim, attempt, m, job, specSHA)
	if err != nil {
		return nil, err
	}
	if send {
		access, err := s.publicationAccess(ctx, claim, attempt)
		if err != nil || access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil {
			return nil, c.ErrExecutionAuthority
		}
		until := a.ExpiresAt
		if access.ValidUntil().Before(until) {
			until = access.ValidUntil()
		}
		bounded, cancel := context.WithDeadline(ctx, until)
		defer cancel()
		patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": a.JobUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": a.ResourceVersion}, {"op": "test", "path": "/metadata/generation", "value": a.BeforeGeneration}, {"op": "test", "path": "/spec/suspend", "value": true}, {"op": "replace", "path": "/spec/suspend", "value": false}})
		if _, err = s.Runtime.Owner.Client.BatchV1().Jobs(job.Namespace).Patch(bounded, job.Name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
			return nil, ErrJobUncertain
		}
	}
	got, _, err := s.readBoundPublicationJob(ctx, claim, attempt, m)
	if err != nil {
		return nil, err
	}
	if got.Spec.Suspend == nil || *got.Spec.Suspend {
		return nil, ErrJobUncertain
	}
	return got, nil
}
