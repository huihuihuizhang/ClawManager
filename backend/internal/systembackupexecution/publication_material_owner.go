package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type publicationMaterialJobOwner struct {
	Version, MaterialIntentSHA256, SecretUID, JobUID, JobSpecSHA256 string
	Generation                                                      int64
}

func (s *DeploymentService) publicationMaterialOwnerIntent(ctx context.Context, claim c.ClaimToken, attempt uint64, intent publicationMaterialIntent) (publicationMaterialJobOwner, error) {
	var zero publicationMaterialJobOwner
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
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
	raw, err := loadPublicationMetadata(ctx, tx, intent.Backup, publicationMaterialID(intent.Installation, intent.Backup, attempt)+"_job_owner")
	if err != nil {
		return zero, err
	}
	var owner publicationMaterialJobOwner
	original, _ := ce.Canonical(intent)
	if decodeProviderDeploymentJSON(raw, &owner) != nil || owner.Version != "system-backup-original-publication-material-job-owner.v1" || owner.MaterialIntentSHA256 != hash(original) || owner.SecretUID == "" || owner.JobUID == "" || owner.Generation < 1 || !formalCandidateDigest(owner.JobSpecSHA256) || guard.RecheckTx(ctx, tx) != nil {
		return zero, c.ErrExecutionRecord
	}
	return owner, nil
}

func (s *DeploymentService) readBoundPublicationJob(ctx context.Context, claim c.ClaimToken, attempt uint64, m *publicationJobMaterials) (*batchv1.Job, string, error) {
	want, specSHA, err := s.publicationJobDefinition(ctx, claim, attempt, m.request)
	if err != nil {
		return nil, "", err
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, "", c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		tx.Rollback()
		return nil, "", err
	}
	var state, digest, namespace, namespaceUID, name, uid string
	err = tx.QueryRowContext(ctx, `SELECT send_state,spec_sha256,namespace_name,namespace_uid,job_name,job_uid FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' FOR SHARE`, m.intent.Installation, m.intent.Backup).Scan(&state, &digest, &namespace, &namespaceUID, &name, &uid)
	if err != nil || state != "bound" || digest != specSHA || namespace != want.Namespace || namespaceUID != s.Config.NamespaceUID || name != want.Name || uid == "" || guard.RecheckTx(ctx, tx) != nil {
		tx.Rollback()
		return nil, "", c.ErrExecutionRecord
	}
	activation, err := s.loadPublicationActivationTx(ctx, tx, m.intent)
	if err != nil {
		tx.Rollback()
		return nil, "", c.ErrExecutionRecord
	}
	if activation != nil {
		leaf, _ := pem.Decode(m.secret.Data["tls.crt"])
		if leaf == nil || activation.SecretUID != string(m.secret.UID) || activation.IdentityVersion != hash(leaf.Bytes) {
			tx.Rollback()
			return nil, "", c.ErrExecutionRecord
		}
	}
	if guard.RecheckTx(ctx, tx) != nil {
		tx.Rollback()
		return nil, "", c.ErrExecutionAuthority
	}
	if tx.Rollback() != nil {
		return nil, "", c.ErrExecutionAuthority
	}
	nativeDeadline := m.intent.Deadline
	if access.ValidUntil().Before(nativeDeadline) {
		nativeDeadline = access.ValidUntil()
	}
	bounded, cancel := context.WithDeadline(ctx, nativeDeadline)
	defer cancel()
	job, err := s.Runtime.Owner.Client.BatchV1().Jobs(namespace).Get(bounded, name, metav1.GetOptions{})
	if err != nil || string(job.UID) != uid || !publicationJobMatchesActivation(want, job, activation) || access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil {
		return nil, "", c.ErrExecutionAuthority
	}
	final, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer final.Rollback()
	last, err := access.Bind(ctx, final)
	if err != nil {
		return nil, "", err
	}
	var finalUID, finalSpec, finalState, finalNamespace, finalNamespaceUID, finalName string
	if final.QueryRowContext(ctx, `SELECT job_uid,spec_sha256,send_state,namespace_name,namespace_uid,job_name FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' FOR SHARE`, m.intent.Installation, m.intent.Backup).Scan(&finalUID, &finalSpec, &finalState, &finalNamespace, &finalNamespaceUID, &finalName) != nil || finalUID != uid || finalSpec != specSHA || finalState != "bound" || finalNamespace != namespace || finalNamespaceUID != namespaceUID || finalName != name {
		return nil, "", c.ErrExecutionRecord
	}
	currentActivation, err := s.loadPublicationActivationTx(ctx, final, m.intent)
	if err != nil || (activation == nil) != (currentActivation == nil) || (activation != nil && *activation != *currentActivation) || last.RecheckTx(ctx, final) != nil || bounded.Err() != nil {
		return nil, "", c.ErrExecutionRecord
	}
	return job, specSHA, nil
}

// Empty before binding is legitimate. Once an original owner intent exists,
// only the exact original 121-bound Job UID/spec may own the immutable Secret.
func (s *DeploymentService) checkPublicationMaterialOwner(ctx context.Context, claim c.ClaimToken, attempt uint64, m *publicationJobMaterials) error {
	owner, err := s.publicationMaterialOwnerIntent(ctx, claim, attempt, m.intent)
	if errors.Is(err, sql.ErrNoRows) {
		if len(m.secret.OwnerReferences) != 0 {
			return c.ErrExecutionRecord
		}
		return nil
	}
	if err != nil {
		return err
	}
	if len(m.secret.OwnerReferences) == 0 {
		return ErrJobUncertain
	}
	if len(m.secret.OwnerReferences) != 1 || owner.SecretUID != string(m.secret.UID) {
		return c.ErrExecutionRecord
	}
	job, specSHA, err := s.readBoundPublicationJob(ctx, claim, attempt, m)
	if err != nil {
		return err
	}
	reference := m.secret.OwnerReferences[0]
	expectedGeneration := owner.Generation
	if job.Spec.Suspend != nil && !*job.Spec.Suspend {
		expectedGeneration++ // readBoundPublicationJob verified original activation
	}
	if owner.JobUID != string(job.UID) || owner.JobSpecSHA256 != specSHA || expectedGeneration != job.Generation || reference.APIVersion != "batch/v1" || reference.Kind != "Job" || reference.Name != job.Name || reference.UID != job.UID || reference.Controller == nil || !*reference.Controller || reference.BlockOwnerDeletion == nil || *reference.BlockOwnerDeletion {
		return c.ErrExecutionRecord
	}
	return nil
}

func (s *DeploymentService) persistPublicationMaterialMetadata(ctx context.Context, claim c.ClaimToken, attempt uint64, intent publicationMaterialIntent, suffix string, body []byte) (bool, error) {
	if suffix != "_job_owner" || len(body) == 0 || len(body) > 8192 {
		return false, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return false, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return false, err
	}
	id := publicationMaterialID(intent.Installation, intent.Backup, attempt)
	original, err := loadPublicationMetadata(ctx, tx, intent.Backup, id)
	if err != nil {
		return false, err
	}
	expected, _ := ce.Canonical(intent)
	if !bytes.Equal(expected, original) {
		return false, c.ErrExecutionRecord
	}
	old, err := loadPublicationMetadata(ctx, tx, intent.Backup, id+suffix)
	if err == nil {
		if !bytes.Equal(old, body) || guard.RecheckTx(ctx, tx) != nil {
			return false, c.ErrExecutionRecord
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, intent.Installation, guard.Facts().ConfigVersion, guard.Facts().ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(guard.Facts().TaskDeadline) {
		return false, c.ErrExecutionRecord
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return false, err
	}
	if err = registerPublicationMetadata(ctx, tx, intent.Installation, intent.Backup, id+suffix, body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return false, err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return false, err
	}
	if tx.Commit() != nil {
		return false, c.ErrExecutionCommitUnknown
	}
	return true, nil
}

// UID/resourceVersion update only, after original intent commit. No credential
// data changes and no foreign/co-owner is adopted. Unknown update ACKs recover
// by GET of the original body/UID/owner, never another update or Secret create.
func (s *DeploymentService) bindPublicationMaterialJobOwner(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials) (*publicationJobMaterials, error) {
	m, err := s.preparePublicationJobMaterials(ctx, claim, attempt, target, PublicationUploadRequest{})
	if err != nil {
		return nil, err
	}
	defer m.Close()
	job, specSHA, err := s.readBoundPublicationJob(ctx, claim, attempt, m)
	if err != nil {
		return nil, err
	}
	original, _ := ce.Canonical(m.intent)
	body, err := ce.Canonical(publicationMaterialJobOwner{Version: "system-backup-original-publication-material-job-owner.v1", MaterialIntentSHA256: hash(original), SecretUID: string(m.secret.UID), JobUID: string(job.UID), JobSpecSHA256: specSHA, Generation: job.Generation})
	if err != nil {
		return nil, err
	}
	send, err := s.persistPublicationMaterialMetadata(ctx, claim, attempt, m.intent, "_job_owner", body)
	if err != nil {
		return nil, err
	}
	if send {
		if len(m.secret.OwnerReferences) != 0 {
			return nil, c.ErrExecutionRecord
		}
		access, err := s.publicationAccess(ctx, claim, attempt)
		if err != nil || access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil {
			return nil, c.ErrExecutionAuthority
		}
		yes, no := true, false
		owned := m.secret.DeepCopy()
		defer func() {
			for _, data := range owned.Data {
				clear(data)
			}
		}()
		owned.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes, BlockOwnerDeletion: &no}}
		nativeDeadline := m.intent.Deadline
		if access.ValidUntil().Before(nativeDeadline) {
			nativeDeadline = access.ValidUntil()
		}
		bounded, cancel := context.WithDeadline(ctx, nativeDeadline)
		defer cancel()
		if _, err = s.Runtime.Owner.Client.CoreV1().Secrets(owned.Namespace).Update(bounded, owned, metav1.UpdateOptions{}); err != nil {
			return nil, ErrJobUncertain
		}
	}
	return s.readPublicationJobMaterials(ctx, claim, attempt, target, m.intent)
}
