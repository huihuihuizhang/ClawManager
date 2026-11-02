package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

type publicationNativeCleanupObject struct{ Kind, Namespace, Name, UID, ResourceVersion string }
type publicationNativeCleanupIntent struct {
	Version, Installation, Backup, NamespaceUID, MaterialSHA256, ProcessSHA256, MarkerSHA256, CandidateResource string
	Attempt                                                                                                     uint64
	Claim                                                                                                       c.ClaimToken
	Deadline                                                                                                    time.Time
	Objects                                                                                                     [3]publicationNativeCleanupObject // Secret, original Pod, original Job
}
type publicationNativeCleanupEvent struct {
	Version, IntentSHA256, Stage string
	Object                       publicationNativeCleanupObject
}
type publicationNativeCleanup struct {
	candidate    *publicationCandidateCleanup
	intent       publicationNativeCleanupIntent
	intentSHA256 string
	absentSHA256 [3]string
	done         bool
	job          *batchv1.Job
}

func (p *publicationNativeCleanup) id() string {
	return publicationMaterialID(p.intent.Installation, p.intent.Backup, p.intent.Attempt) + "_native_cleanup"
}

func (p *publicationNativeCleanup) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.candidate == nil || !p.candidate.deleted || p.candidate.exit == nil || p.candidate.exit.marker.receipt == nil || tx == nil {
		return c.ErrExecutionAuthority
	}
	if err := p.candidate.recheckTx(ctx, tx, "deleted"); err != nil {
		return err
	}
	e := p.candidate.exit
	parent := e.marker.receipt.postManifestMarker
	if p.intent.Version != "system-backup-original-native-cleanup.v1" || p.intent.Installation != e.service.Config.InstallationID || p.intent.Backup != e.claim.Target.PublicID || p.intent.Attempt != e.attempt || p.intent.Claim != e.claim || p.intent.NamespaceUID != e.service.Config.NamespaceUID || !p.intent.Deadline.Equal(p.candidate.deadline) || p.intent.MaterialSHA256 != parent.completion.materialSHA256 || p.intent.ProcessSHA256 != parent.completion.uploadSnapshot.processSHA256 || p.intent.MarkerSHA256 != e.marker.SHA256 || p.intent.CandidateResource != p.candidate.resource.owner.Resource {
		return c.ErrExecutionRecord
	}
	if p.intentSHA256 != "" {
		raw, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, p.id())
		expected, _ := ce.Canonical(p.intent)
		if err != nil || hash(raw) != p.intentSHA256 || !bytes.Equal(raw, expected) {
			return c.ErrExecutionRecord
		}
	}
	return nil
}

// Metadata is diagnostic custody only. No cleanup_result or acceptance may be
// inferred until all actual resource and payload absence observations exist.
func (p *publicationNativeCleanup) register(ctx context.Context, suffix string, body []byte) (bool, error) {
	if p == nil || p.candidate == nil || len(body) == 0 || len(body) > 8192 {
		return false, c.ErrExecutionRecord
	}
	e := p.candidate.exit
	if e.marker.receipt.access.Check(ctx) != nil {
		return false, c.ErrExecutionAuthority
	}
	tx, err := e.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return false, errPublicationUnavailable
	}
	defer tx.Rollback()
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, p.intent.Installation, p.intent.Backup).Scan(&version) != nil || version != e.claim.RowVersion {
		return false, c.ErrClaimLost
	}
	if err = p.recheckTx(ctx, tx); err != nil {
		return false, err
	}
	id := p.id() + suffix
	old, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, id)
	if err == nil {
		if !bytes.Equal(old, body) {
			return false, c.ErrExecutionRecord
		}
		if err = p.recheckTx(ctx, tx); err != nil {
			return false, err
		}
		return false, nil // an existing dispatch grants QUERY only, never resend
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, errPublicationUnavailable
	}
	var capacity, retention int64
	var now time.Time
	completed := e.marker.receipt.postManifestMarker.completion
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, p.intent.Installation, completed.capture.Input.ConfigVersion, completed.capture.Input.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Before(p.intent.Deadline) {
		return false, c.ErrExecutionAuthority
	}
	if err = (security.RegistrationCapacity{ReportFile: e.service.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return false, err
	}
	if err = registerPublicationMetadata(ctx, tx, p.intent.Installation, p.intent.Backup, id, body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return false, c.ErrExecutionRecord
	}
	if err = p.recheckTx(ctx, tx); err != nil {
		return false, err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return false, c.ErrExecutionCommitUnknown
	}
	return true, nil
}

func publicationNativeCleanupSecret(secretBody []byte, secret metav1.Object, e *publicationUploadExit) bool {
	if e == nil || secret == nil || !formalCandidateDigest(e.material.RequestSHA256) || secret.GetNamespace() != e.material.Namespace || secret.GetName() != e.material.Name || string(secret.GetUID()) != e.activation.SecretUID || secret.GetResourceVersion() == "" || secret.GetDeletionTimestamp() != nil || hash(secretBody) != e.material.BodySHA256 {
		return false
	}
	owners := secret.GetOwnerReferences()
	if len(owners) != 1 {
		return false
	}
	owner := owners[0]
	return owner.APIVersion == "batch/v1" && owner.Kind == "Job" && owner.Name == "sbp-"+e.material.RequestSHA256[:32] && string(owner.UID) == e.activation.JobUID && owner.Controller != nil && *owner.Controller && owner.BlockOwnerDeletion != nil && !*owner.BlockOwnerDeletion
}

func (s *DeploymentService) prepareOriginalNativeCleanup(ctx context.Context, candidate *publicationCandidateCleanup) (*publicationNativeCleanup, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || candidate == nil || !candidate.deleted || candidate.exit == nil || candidate.exit.service != s {
		return nil, c.ErrExecutionAuthority
	}
	e := candidate.exit
	if err := e.checkNativeStopped(ctx); err != nil {
		return nil, err
	}
	client := s.Runtime.Owner.Client
	job, err := client.BatchV1().Jobs(e.material.Namespace).Get(ctx, "sbp-"+e.material.RequestSHA256[:32], metav1.GetOptions{})
	if err != nil || !publicationCompletedUploadJob(job, e.material, e.activation, s.Config.PublicationWorker.ServiceAccountName) || job.ResourceVersion != e.jobResourceVersion {
		return nil, ErrJobUncertain
	}
	pod, err := client.CoreV1().Pods(e.material.Namespace).Get(ctx, e.process.Pod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, ErrJobUncertain
	}
	if _, err = publicationOriginalUploadExitPods(job, []corev1.Pod{*pod}, e.process); err != nil {
		return nil, err
	}
	secret, err := client.CoreV1().Secrets(e.material.Namespace).Get(ctx, e.material.Name, metav1.GetOptions{})
	if err != nil {
		return nil, ErrJobUncertain
	}
	secret = secret.DeepCopy()
	body, bodyErr := publicationMaterialBody(secret)
	valid := bodyErr == nil && publicationNativeCleanupSecret(body, secret, e)
	clear(body)
	for _, raw := range secret.Data {
		clear(raw)
	}
	secret.Data = nil
	if !valid {
		return nil, c.ErrExecutionRecord
	}
	parent := e.marker.receipt.postManifestMarker.completion
	p := &publicationNativeCleanup{candidate: candidate, job: job.DeepCopy(), intent: publicationNativeCleanupIntent{Version: "system-backup-original-native-cleanup.v1", Installation: s.Config.InstallationID, Backup: e.claim.Target.PublicID, Attempt: e.attempt, Claim: e.claim, Deadline: candidate.deadline, NamespaceUID: s.Config.NamespaceUID, MaterialSHA256: parent.materialSHA256, ProcessSHA256: parent.uploadSnapshot.processSHA256, MarkerSHA256: e.marker.SHA256, CandidateResource: candidate.resource.owner.Resource, Objects: [3]publicationNativeCleanupObject{{"Secret", secret.Namespace, secret.Name, string(secret.UID), secret.ResourceVersion}, {"Pod", pod.Namespace, pod.Name, string(pod.UID), pod.ResourceVersion}, {"Job", job.Namespace, job.Name, string(job.UID), job.ResourceVersion}}}}
	raw, err := ce.Canonical(p.intent)
	if err != nil {
		return nil, c.ErrExecutionRecord
	}
	if _, err = p.register(ctx, "", raw); err != nil {
		return nil, err
	}
	p.intentSHA256 = hash(raw)
	return p, nil
}

func (p *publicationNativeCleanup) kubeOperations(object publicationNativeCleanupObject) (func(context.Context) (metav1.Object, error), func(context.Context) (watch.Interface, error), func(context.Context) error, error) {
	if p == nil || p.candidate == nil || p.candidate.exit == nil || p.candidate.exit.service == nil || p.candidate.exit.service.Runtime == nil || p.candidate.exit.service.Runtime.Owner == nil || p.candidate.exit.service.Runtime.Owner.Client == nil || object.UID == "" || object.ResourceVersion == "" || object.Name == "" || object.Namespace == "" {
		return nil, nil, nil, c.ErrExecutionAuthority
	}
	owner := p.candidate.exit.service.Runtime.Owner
	client, watchClient := owner.Client, owner.WatchClient
	if watchClient == nil {
		watchClient = client
	}
	uid, rv := types.UID(object.UID), object.ResourceVersion
	policy := metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &policy}
	list := metav1.ListOptions{FieldSelector: "metadata.name=" + object.Name, ResourceVersion: object.ResourceVersion}
	switch object.Kind {
	case "Secret":
		return func(ctx context.Context) (metav1.Object, error) {
				secret, err := client.CoreV1().Secrets(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				metadata := &metav1.PartialObjectMetadata{ObjectMeta: *secret.ObjectMeta.DeepCopy()}
				for _, raw := range secret.Data {
					clear(raw)
				}
				secret.Data = nil
				return metadata, nil
			}, func(ctx context.Context) (watch.Interface, error) {
				return watchClient.CoreV1().Secrets(object.Namespace).Watch(ctx, list)
			}, func(ctx context.Context) error {
				return client.CoreV1().Secrets(object.Namespace).Delete(ctx, object.Name, options)
			}, nil
	case "Pod":
		return func(ctx context.Context) (metav1.Object, error) {
				return client.CoreV1().Pods(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
			}, func(ctx context.Context) (watch.Interface, error) {
				return watchClient.CoreV1().Pods(object.Namespace).Watch(ctx, list)
			}, func(ctx context.Context) error {
				return client.CoreV1().Pods(object.Namespace).Delete(ctx, object.Name, options)
			}, nil
	case "Job":
		return func(ctx context.Context) (metav1.Object, error) {
				return client.BatchV1().Jobs(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
			}, func(ctx context.Context) (watch.Interface, error) {
				return watchClient.BatchV1().Jobs(object.Namespace).Watch(ctx, list)
			}, func(ctx context.Context) error {
				return client.BatchV1().Jobs(object.Namespace).Delete(ctx, object.Name, options)
			}, nil
	}
	return nil, nil, nil, c.ErrExecutionRecord
}

func publicationObserveNativeAbsence(ctx context.Context, object publicationNativeCleanupObject, get func(context.Context) (metav1.Object, error), stream watch.Interface) error {
	current, err := get(ctx)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || current == nil || string(current.GetUID()) != object.UID || current.GetDeletionTimestamp() == nil {
		return ErrJobUncertain
	}
	for {
		select {
		case <-ctx.Done():
			return ErrJobUncertain
		case event, ok := <-stream.ResultChan():
			if !ok || event.Type == watch.Error {
				return ErrJobUncertain
			}
			observed, ok := event.Object.(metav1.Object)
			if !ok || string(observed.GetUID()) != object.UID || observed.GetName() != object.Name || observed.GetNamespace() != object.Namespace {
				return c.ErrExecutionRecord
			}
			if event.Type == watch.Deleted {
				if _, err = get(ctx); apierrors.IsNotFound(err) {
					return nil
				}
				return ErrJobUncertain
			}
			if observed.GetDeletionTimestamp() == nil {
				return ErrJobUncertain
			}
		}
	}
}

func (p *publicationNativeCleanup) deleteAndObserve(ctx context.Context, index int) error {
	if p == nil || index < 0 || index >= len(p.intent.Objects) || p.intentSHA256 == "" {
		return c.ErrExecutionRecord
	}
	object := p.intent.Objects[index]
	get, arm, remove, err := p.kubeOperations(object)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, p.intent.Deadline)
	defer cancel()
	current, err := get(ctx)
	if err != nil || current == nil || current.GetName() != object.Name || current.GetNamespace() != object.Namespace || string(current.GetUID()) != object.UID || current.GetResourceVersion() != object.ResourceVersion || current.GetDeletionTimestamp() != nil {
		return ErrJobUncertain
	}
	stream, err := arm(ctx)
	if err != nil {
		return ErrJobUncertain
	}
	defer stream.Stop()
	event := publicationNativeCleanupEvent{Version: "system-backup-original-native-cleanup-event.v1", IntentSHA256: p.intentSHA256, Stage: "delete_dispatched", Object: object}
	raw, _ := ce.Canonical(event)
	sent, err := p.register(ctx, "_"+object.Kind+"_sent", raw)
	if err != nil {
		return err
	}
	if p.candidate.exit.marker.receipt.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	if sent {
		_ = remove(ctx)
	} // one send only; a lost ACK permits only observation
	if err = publicationObserveNativeAbsence(ctx, object, get, stream); err != nil {
		return err
	}
	event.Stage = "confirmed_absent"
	raw, _ = ce.Canonical(event)
	if _, err = p.register(ctx, "_"+object.Kind+"_absent", raw); err != nil {
		return err
	}
	p.absentSHA256[index] = hash(raw)
	return nil
}

func (s *DeploymentService) cleanupOriginalPublicationNativeResources(ctx context.Context, candidate *publicationCandidateCleanup) (*publicationNativeCleanup, error) {
	p, err := s.prepareOriginalNativeCleanup(ctx, candidate)
	if err != nil {
		return nil, err
	}
	for index := range p.intent.Objects {
		if err = p.deleteAndObserve(ctx, index); err != nil {
			return nil, err
		}
	}
	for _, object := range p.intent.Objects {
		get, _, _, err := p.kubeOperations(object)
		if err != nil {
			return nil, err
		}
		if _, err = get(ctx); !apierrors.IsNotFound(err) {
			return nil, ErrJobUncertain
		}
	}
	list, err := s.Runtime.Owner.Client.CoreV1().Pods(p.intent.Objects[1].Namespace).List(ctx, metav1.ListOptions{Limit: 1001})
	if err != nil || list.Continue != "" || len(list.Items) > 1000 {
		return nil, ErrJobUncertain
	}
	for i := range list.Items {
		if publicationUploadPodRelated(p.job, &list.Items[i]) {
			return nil, ErrJobUncertain
		}
	}
	if p.candidate.exit.marker.receipt.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errPublicationUnavailable
	}
	defer tx.Rollback()
	if err = p.recheckCompleteTx(ctx, tx); err != nil {
		return nil, err
	}
	if tx.Rollback() != nil {
		return nil, errPublicationUnavailable
	}
	p.done = true
	return p, nil
}

func (p *publicationNativeCleanup) recheckCompleteTx(ctx context.Context, tx *sql.Tx) error {
	if err := p.recheckTx(ctx, tx); err != nil {
		return err
	}
	for index, object := range p.intent.Objects {
		expected, _ := ce.Canonical(publicationNativeCleanupEvent{Version: "system-backup-original-native-cleanup-event.v1", IntentSHA256: p.intentSHA256, Stage: "confirmed_absent", Object: object})
		raw, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, p.id()+"_"+object.Kind+"_absent")
		if err != nil || !formalCandidateDigest(p.absentSHA256[index]) || hash(raw) != p.absentSHA256[index] || !bytes.Equal(expected, raw) {
			return c.ErrExecutionRecord
		}
	}
	return p.recheckTx(ctx, tx)
}

func (s *DeploymentService) completeOriginalPublicationThroughNativeCleanup(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (*publicationCompleteCleanup, error) {
	candidate, err := s.completeOriginalPublicationThroughCandidateCleanup(ctx, claim, attempt, policy, store, capture)
	if err != nil {
		return nil, err
	}
	native, err := s.cleanupOriginalPublicationNativeResources(ctx, candidate)
	if err != nil {
		return nil, err
	}
	return s.cleanupOriginalPublicationLocal(ctx, native)
}
