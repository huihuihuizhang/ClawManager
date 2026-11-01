package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"sort"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// This identity is separately selected by the administrator in the signed core.
// It never inherits the capture worker's service account or source permissions.
type PublicationWorkerReference struct {
	Protocol           string `json:"protocol"`
	ServiceAccountName string `json:"service_account_name"`
	ServiceAccountUID  string `json:"service_account_uid"`
}

func (r PublicationWorkerReference) validate(captureName, captureUID string) error {
	if r.Protocol != publicationPresignedUploadVersion || r.ServiceAccountName == "" || len(validation.IsDNS1123Subdomain(r.ServiceAccountName)) != 0 || !planToken.MatchString(r.ServiceAccountUID) || r.ServiceAccountName == captureName || r.ServiceAccountUID == captureUID {
		return c.ErrExecutionAuthority
	}
	return nil
}

// Only authenticated original capture records select the individual private C
// files. This reads metadata and hashes, without acquiring a DEK or source grant.
// Complete independent domain verification is a separate prerequisite in the
// first-forward caller; this boundary alone cannot authorize publication.
func (s *DeploymentService) publicationJobInputs(ctx context.Context, claim c.ClaimToken, attempt uint64, request PublicationUploadRequest) ([]kube.PublishInputFile, error) {
	scope := security.PublisherCaptureScope{BackupPublicID: claim.Target.PublicID, Claim: security.SQLSigningClaim{ControllerOwner: claim.Owner, RowVersion: claim.RowVersion}, CaptureAttemptNo: attempt}
	names, err := s.publisherVerifierFactory.CaptureParts(ctx, scope)
	if err != nil || len(names) == 0 || len(names) > 10000 {
		return nil, c.ErrExecutionRecord
	}
	expected := make(map[string]PublicationUploadInput, len(request.Objects))
	for _, object := range request.Objects {
		if _, exists := expected[object.Path]; exists {
			return nil, c.ErrExecutionRecord
		}
		expected[object.Path] = object
	}
	var inputs []kube.PublishInputFile
	containers := false
	for _, object := range request.Objects {
		if isPublicationContainerObject(object.Path) {
			containers = true
		}
	}
	if containers {
		certificate, ok := expected[publicationCaptureCertificatePath]
		if !ok || len(request.CaptureCertificate) == 0 || int64(len(request.CaptureCertificate)) != certificate.Bytes || hash(request.CaptureCertificate) != certificate.SHA256 {
			return nil, c.ErrExecutionRecord
		}
		delete(expected, publicationCaptureCertificatePath)
		bootstrap, ok := expected[cd.BootstrapPath]
		if !ok || len(request.CaptureBootstrap) == 0 || int64(len(request.CaptureBootstrap)) != bootstrap.Bytes || hash(request.CaptureBootstrap) != bootstrap.SHA256 {
			return nil, c.ErrExecutionRecord
		}
		delete(expected, cd.BootstrapPath)
		inputs, err = s.loadPublicationContainerJobInputs(ctx, claim, attempt, expected)
		if err != nil {
			return nil, err
		}
		controls := []string{}
		for _, name := range names {
			if name == cd.Part || name == ce.Part || name == ce.ProofPart {
				controls = append(controls, name)
			}
		}
		if len(names) < 9 || len(controls) != 3 || len(request.Objects) != len(publicationRequestedParts)+2*len(controls)+3 {
			return nil, c.ErrExecutionRecord
		}
		names = controls
	} else if len(request.Objects) != 2*len(names)+1 {
		return nil, c.ErrExecutionRecord
	}
	for _, name := range names {
		verifier, err := s.PublisherVerifierForPart(ctx, claim, attempt, name)
		if err != nil {
			return nil, err
		}
		record, err := verifier.CapturedRecord(ctx)
		verifier.Close()
		if err != nil {
			return nil, err
		}
		var original FormalCandidateRecord
		if decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || hash(record.CandidateJSON) != record.CandidateSHA256 {
			return nil, c.ErrExecutionRecord
		}
		invocationSHA, err := record.Invocation.Hash()
		if err != nil {
			return nil, err
		}
		cipherPath, envelopePath := publicationPartPaths(name, record.Invocation.Request.Binding.PartIndex, invocationSHA)
		for index, item := range []struct {
			name    string
			receipt staging.Receipt
		}{{cipherPath, original.Candidate.Ciphertext}, {envelopePath, original.Candidate.Envelope}} {
			object, ok := expected[item.name]
			if !ok || object.SHA256 != item.receipt.SHA256 || object.Bytes != item.receipt.Size {
				return nil, c.ErrExecutionRecord
			}
			sealScope := record.SealScope
			if index == 1 {
				sealScope.Unit += "/formal-envelope"
			}
			reference, err := staging.SealReferenceForIntent(staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: sealScope, Original: item.receipt})
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, kube.PublishInputFile{Path: item.name, SubPath: ".controller-seals/" + path.Base(reference)})
			delete(expected, item.name)
		}
	}
	if len(expected) != 1 {
		return nil, c.ErrExecutionRecord
	}
	if _, ok := expected["artifact-index.json"]; !ok {
		return nil, c.ErrExecutionRecord
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	return inputs, nil
}

func (s *DeploymentService) checkPublicationJobResources(ctx context.Context) error {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Client == nil || s.Config.PublicationWorker == nil || s.Config.PublicationWorker.validate(s.Config.Security.ServiceAccountName, s.Config.Security.ServiceAccountUID) != nil {
		return c.ErrExecutionAuthority
	}
	client, cfg := s.Runtime.Owner.Client, s.Config
	if cfg.PublicationWorker.ServiceAccountName == s.controllerActor.ServiceAccountName {
		return c.ErrExecutionAuthority
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	sa, err := client.CoreV1().ServiceAccounts(cfg.Namespace).Get(ctx, cfg.PublicationWorker.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != cfg.PublicationWorker.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	for _, volume := range cfg.Security.Volumes {
		if volume.Kind != "PersistentVolumeClaim" || volume.Name != cfg.StagingClaim {
			continue
		}
		pvc, err := client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Get(ctx, volume.Name, metav1.GetOptions{})
		if err != nil || string(pvc.UID) != volume.UID || pvc.DeletionTimestamp != nil || pvc.Spec.VolumeName != volume.PVName {
			return c.ErrExecutionAuthority
		}
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, volume.PVName, metav1.GetOptions{})
		if err != nil || string(pv.UID) != volume.PVUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != volume.UID || pv.Spec.ClaimRef.Namespace != cfg.Namespace || pv.Spec.ClaimRef.Name != volume.Name {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	return c.ErrExecutionAuthority
}

// No native creation, task mutation or new delegation occurs in this exact
// definition. It is also used to authenticate the original Job on reopen.
func (s *DeploymentService) publicationJobDefinition(ctx context.Context, claim c.ClaimToken, attempt uint64, request PublicationUploadRequest) (*batchv1.Job, string, error) {
	inputs, err := s.publicationJobInputs(ctx, claim, attempt, request)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	requestSHA := hash(raw)
	name := "sbp-" + requestSHA[:32]
	// The signed deployment interval supplies a stable native upper bound. The
	// upload worker independently enforces the earlier absolute request deadline;
	// retries never derive a new request/grant window from the native Job clock.
	seconds := int64(request.Deadline.Sub(s.Forward.DeploymentBinding().NotBefore) / time.Second)
	if seconds < 1 || seconds > 86400 || !time.Now().Before(request.Deadline) {
		return nil, "", c.ErrExecutionAuthority
	}
	endpoint, err := url.Parse(s.Config.ControlURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, "", c.ErrExecutionAuthority
	}
	endpoint.Path, endpoint.RawPath = PublicationResultPath, ""
	want, err := kube.PublishJob(kube.PublishJobRequest{Identity: kube.Identity{Namespace: s.Config.Namespace, Name: name, Owner: claim.Target.PublicID}, Image: s.Config.WorkerImage, ServiceAccount: s.Config.PublicationWorker.ServiceAccountName, StagingClaim: s.Config.StagingClaim, InvocationConfigMap: name + "-request", UploadCredentialSecret: name + "-upload", RequestSHA256: requestSHA, DeadlineSeconds: seconds, InputFiles: inputs, ResultRelayURL: endpoint.String()})
	if err != nil {
		return nil, "", err
	}
	yes := true
	want.Spec.Suspend = &yes
	jobBytes, _ := json.Marshal(want)
	specSHA := hash(jobBytes)
	if want.Annotations == nil {
		want.Annotations = map[string]string{}
	}
	want.Annotations["backup.clawmanager.io/v2-spec-sha256"] = specSHA
	want.Labels["backup.clawmanager.io/v2-task"] = claim.Target.PublicID
	want.Spec.Template.Labels["backup.clawmanager.io/v2-task"] = claim.Target.PublicID
	return want, specSHA, nil
}

// Actual original 121 one-send boundary. Fresh creation stays suspended until
// its actual UID-owned resources and original 107 receiving identity are bound.
// Reopen accepts a started Job only with that immutable original activation.
// A lost SQL or native ACK never grants a resend, even when GET returns absent.
func (s *DeploymentService) ensureSuspendedPublicationJob(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, request PublicationUploadRequest) (*batchv1.Job, error) {
	if attempt != 1 || request.Version != publicationPresignedUploadVersion || !formalCandidateDigest(request.CredentialHash) || !formalCandidateDigest(request.CandidateOwnerHMAC) || s.publicationBinding() != nil || s.publisherVerifierFactory == nil || s.publisherVerifierDB == nil || s.Forward.CheckDeployment(ctx, s.publisherVerifierDB) != nil || s.checkPublicationJobResources(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	if _, _, err := request.validate(); err != nil {
		return nil, err
	}
	candidate, err := s.beginPublicationCandidate(ctx, claim, attempt, target, request)
	if err != nil || candidate.MAC != request.CandidateOwnerHMAC {
		return nil, c.ErrExecutionAuthority
	}
	want, specSHA, err := s.publicationJobDefinition(ctx, claim, attempt, request)
	if err != nil {
		return nil, err
	}
	name := want.Name
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return nil, err
	}
	facts := guard.Facts()
	if (facts.Status != "validating" && facts.Status != "publishing") || request.Deadline.After(facts.TaskDeadline) {
		return nil, c.ErrExecutionAuthority
	}
	var state, digest, namespace, namespaceUID, jobName string
	var uid sql.NullString
	preparationChecked := false
	err = tx.QueryRowContext(ctx, `SELECT send_state,spec_sha256,namespace_name,namespace_uid,job_name,job_uid FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' FOR UPDATE`, facts.InstallationID, facts.BackupPublicID).Scan(&state, &digest, &namespace, &namespaceUID, &jobName, &uid)
	if errors.Is(err, sql.ErrNoRows) {
		if err = publicationPreparationOpenTx(ctx, tx, facts.InstallationID, facts.BackupPublicID); err != nil {
			return nil, err
		}
		preparationChecked = true
		var capacity int64
		if err = tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256).Scan(&capacity); err != nil {
			return nil, err
		}
		if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, 8192); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT IGNORE INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) VALUES('backup',?,1,'publish')`, facts.BackupPublicID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_job_send_intents(origin_installation_id,task_public_id,phase,job_unit_key,namespace_name,namespace_uid,job_name,spec_sha256) VALUES(?,?,'publish','artifact-upload',?,?,?,?)`, facts.InstallationID, facts.BackupPublicID, want.Namespace, s.Config.NamespaceUID, name, specSHA); err != nil {
			return nil, err
		}
		state, digest, namespace, namespaceUID, jobName = "planned", specSHA, want.Namespace, s.Config.NamespaceUID, name
	} else if err != nil {
		return nil, err
	}
	if digest != specSHA || namespace != want.Namespace || namespaceUID != s.Config.NamespaceUID || jobName != name {
		return nil, c.ErrExecutionRecord
	}
	send := state == "planned"
	if send {
		if !preparationChecked {
			if err = publicationPreparationOpenTx(ctx, tx, facts.InstallationID, facts.BackupPublicID); err != nil {
				return nil, err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_job_send_intents SET send_state='sending',send_started_at=UTC_TIMESTAMP(6) WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' AND send_state='planned'`, facts.InstallationID, facts.BackupPublicID); err != nil {
			return nil, err
		}
	}
	originalRequest, err := json.Marshal(request)
	if err != nil {
		return nil, c.ErrExecutionRecord
	}
	activation, err := s.loadPublicationJobActivationTx(ctx, tx, claim, attempt, hash(originalRequest))
	if err != nil || (send && activation != nil) {
		return nil, c.ErrExecutionRecord
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return nil, err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return nil, c.ErrExecutionCommitUnknown
	}
	// No SQL transaction spans a Kubernetes request. A withdrawal during Create
	// leaves an inert suspended Job and its original sending intent for cleanup.
	if access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	nativeDeadline := access.ValidUntil()
	if request.Deadline.Before(nativeDeadline) {
		nativeDeadline = request.Deadline
	}
	bounded, cancel := context.WithDeadline(ctx, nativeDeadline)
	defer cancel()
	var got *batchv1.Job
	if send {
		got, err = s.Runtime.Owner.Client.BatchV1().Jobs(want.Namespace).Create(bounded, want, metav1.CreateOptions{})
		if err != nil {
			return nil, ErrJobUncertain
		}
	} else {
		got, err = s.Runtime.Owner.Client.BatchV1().Jobs(want.Namespace).Get(bounded, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, ErrJobUncertain
		}
		if err != nil {
			return nil, err
		}
	}
	if !publicationJobMatchesActivation(want, got, activation) || (uid.Valid && uid.String != string(got.UID)) {
		return nil, c.ErrExecutionRecord
	}
	if parsed, err := uuid.Parse(string(got.UID)); err != nil || parsed.String() != string(got.UID) || got.Generation < 1 {
		return nil, c.ErrExecutionRecord
	}
	if access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	// Bind a new authority object, preserving the exact original claim/window.
	current, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || current.Check(ctx) != nil || !current.ValidUntil().Equal(access.ValidUntil()) {
		return nil, c.ErrExecutionAuthority
	}
	final, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer final.Rollback()
	last, err := current.Bind(ctx, final)
	if err != nil || last.Facts() != facts {
		return nil, c.ErrExecutionAuthority
	}
	var finalState, finalDigest, finalNamespace, finalNamespaceUID, finalName string
	var finalUID sql.NullString
	if err = final.QueryRowContext(ctx, `SELECT send_state,spec_sha256,namespace_name,namespace_uid,job_name,job_uid FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' FOR UPDATE`, facts.InstallationID, facts.BackupPublicID).Scan(&finalState, &finalDigest, &finalNamespace, &finalNamespaceUID, &finalName, &finalUID); err != nil {
		return nil, err
	}
	if finalDigest != specSHA || finalNamespace != want.Namespace || finalNamespaceUID != s.Config.NamespaceUID || finalName != name {
		return nil, c.ErrExecutionRecord
	}
	currentActivation, err := s.loadPublicationJobActivationTx(ctx, final, claim, attempt, hash(originalRequest))
	if err != nil || (activation == nil) != (currentActivation == nil) || (activation != nil && *activation != *currentActivation) {
		return nil, c.ErrExecutionRecord
	}
	if finalState == "bound" {
		if !finalUID.Valid || finalUID.String != string(got.UID) {
			return nil, c.ErrExecutionRecord
		}
	} else if finalState == "sending" && !finalUID.Valid {
		result, err := final.ExecContext(ctx, `UPDATE system_backup_v2_job_send_intents SET send_state='bound',job_uid=?,bound_at=UTC_TIMESTAMP(6) WHERE origin_installation_id=? AND task_public_id=? AND phase='publish' AND job_unit_key='artifact-upload' AND spec_sha256=? AND send_state='sending' AND job_uid IS NULL`, string(got.UID), facts.InstallationID, facts.BackupPublicID, specSHA)
		if err != nil {
			return nil, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return nil, c.ErrExecutionRecord
		}
	} else {
		return nil, c.ErrExecutionRecord
	}
	if last.RecheckTx(ctx, final) != nil {
		return nil, c.ErrExecutionAuthority
	}
	if final.Commit() != nil {
		return nil, c.ErrExecutionCommitUnknown
	}
	return got, nil
}
