package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This is an observation of actual kubelet exits, not cleanup_result evidence.
// Job Complete, a prepared deletion or Pod absence cannot produce this receipt.
type publicationUploadExit struct {
	service            *DeploymentService
	claim              c.ClaimToken
	attempt            uint64
	marker             nativePublicationObject
	material           publicationMaterialIntent
	activation         publicationActivation
	jobResourceVersion string
	pods               map[string]quiesce.PodIdentity
	process            publicationUploadProcess
}

func (p *publicationUploadExit) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.service == nil || tx == nil || p.marker.receipt == nil || p.marker.receipt.postManifestMarker == nil {
		return c.ErrExecutionAuthority
	}
	parent := p.marker.receipt.postManifestMarker
	if parent.service != p.service || parent.claim != p.claim || parent.attempt != p.attempt || parent.completion == nil || p.marker.receipt.action.Kind != "marker_put" {
		return c.ErrExecutionAuthority
	}
	if err := p.marker.recheckPublicationReceiptTx(ctx, tx, p.claim); err != nil {
		return err
	}
	if err := parent.recheckTx(ctx, tx, p.service, p.claim, p.attempt, p.marker.receipt.target, parent.intent); err != nil {
		return err
	}
	return nil
}

// No capture Recovery authority is adopted here. Every read/write joins the
// actual current publishing claim and the independently read marker receipt.
type publicationUploadExitStore struct{ exit *publicationUploadExit }

func (s publicationUploadExitStore) validWitness(p quiesce.ExitWitness) bool {
	if s.exit == nil || p.Namespace != s.exit.material.Namespace || p.PodUID == "" || p.NodeUID == "" || p.ResourceVersion == "" {
		return false
	}
	original, ok := s.exit.pods[p.PodUID]
	if !ok || p.PodName != original.Name || p.Node != original.Node || p.NodeUID != s.exit.service.Config.Security.NodeUIDs[p.Node] || len(p.Containers) != len(original.Containers) || len(p.Containers) == 0 {
		return false
	}
	for _, id := range original.Containers {
		if at := p.Containers[id]; at.IsZero() || at.Before(s.exit.activation.BoundAt) {
			return false
		}
	}
	return true
}

func publicationUploadExitTimes(p quiesce.ExitWitness, started, now time.Time) bool {
	if started.IsZero() || now.IsZero() || now.Before(started) || len(p.Containers) == 0 {
		return false
	}
	for _, at := range p.Containers {
		if at.IsZero() || at.Before(started) || at.After(now) {
			return false
		}
	}
	return true
}

func (s publicationUploadExitStore) Save(ctx context.Context, p quiesce.ExitWitness) error {
	if !s.validWitness(p) {
		return c.ErrExecutionRecord
	}
	raw := quiesce.WitnessBytes(p)
	if len(raw) > 65536 {
		return c.ErrExecutionRecord
	}
	tx, err := s.exit.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return errPublicationUnavailable
	}
	defer tx.Rollback()
	if err = s.exit.recheckTx(ctx, tx); err != nil {
		return err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return c.ErrExecutionAuthority
	}
	if !publicationUploadExitTimes(p, s.exit.activation.BoundAt, now) {
		return c.ErrExecutionRecord
	}
	var old []byte
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=? FOR SHARE`, s.exit.claim.Target.PublicID, p.PodUID).Scan(&old, &digest)
	if err == nil {
		var original quiesce.ExitWitness
		if hash(old) != digest || json.Unmarshal(old, &original) != nil || !s.validWitness(original) || !quiesce.SameExitWitness(original, p) {
			return c.ErrExecutionRecord
		}
		return s.exit.recheckTx(ctx, tx)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return errPublicationUnavailable
	}
	var capacity int64
	completed := s.exit.marker.receipt.postManifestMarker.completion
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, s.exit.service.Config.InstallationID, completed.capture.Input.ConfigVersion, completed.capture.Input.ConfigSHA256).Scan(&capacity) != nil {
		return c.ErrExecutionRecord
	}
	if err = (security.RegistrationCapacity{ReportFile: s.exit.service.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(raw)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_stop_proofs(task_public_id,pod_uid,proof_json,proof_sha256) VALUES(?,?,?,?)`, s.exit.claim.Target.PublicID, p.PodUID, raw, hash(raw)); err != nil {
		return errPublicationUnavailable
	}
	if err = s.exit.recheckTx(ctx, tx); err != nil {
		return err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (s publicationUploadExitStore) Load(ctx context.Context, uid string) (quiesce.ExitWitness, error) {
	var p quiesce.ExitWitness
	if s.exit == nil {
		return p, c.ErrExecutionAuthority
	}
	if _, ok := s.exit.pods[uid]; !ok {
		return p, c.ErrExecutionRecord
	}
	tx, err := s.exit.service.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, errPublicationUnavailable
	}
	defer tx.Rollback()
	if err = s.exit.recheckTx(ctx, tx); err != nil {
		return p, err
	}
	var raw []byte
	var digest string
	if err = tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=?`, s.exit.claim.Target.PublicID, uid).Scan(&raw, &digest); err != nil {
		return p, err
	}
	if len(raw) > 65536 || hash(raw) != digest || json.Unmarshal(raw, &p) != nil || p.PodUID != uid || !s.validWitness(p) {
		return quiesce.ExitWitness{}, c.ErrExecutionRecord
	}
	if err = s.exit.recheckTx(ctx, tx); err != nil {
		return quiesce.ExitWitness{}, err
	}
	return p, nil
}

func publicationCompletedUploadJob(job *batchv1.Job, material publicationMaterialIntent, activation publicationActivation, worker string) bool {
	if !formalCandidateDigest(material.RequestSHA256) || worker == "" {
		return false
	}
	if job == nil || job.Namespace != material.Namespace || job.Name != "sbp-"+material.RequestSHA256[:32] || string(job.UID) != activation.JobUID || job.Generation != activation.AfterGeneration || job.ResourceVersion == "" || job.DeletionTimestamp != nil || job.Spec.Suspend == nil || *job.Spec.Suspend || job.Annotations["backup.clawmanager.io/v2-spec-sha256"] != activation.JobSpecSHA256 || job.Labels["backup.clawmanager.io/v2-task"] != material.Backup || job.Spec.Template.Spec.ServiceAccountName != worker || job.Status.Active != 0 || job.Status.Succeeded != 1 || job.Status.Failed != 0 || job.Status.CompletionTime == nil || job.Status.CompletionTime.IsZero() {
		return false
	}
	complete := false
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
			return false
		}
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			complete = true
		}
	}
	return complete
}

// Inspect the whole namespace instead of trusting a selector that could omit a
// Pod with a changed label. Every original Job child must be explicitly exited.
func publicationUploadPodIdentities(job *batchv1.Job, pods []corev1.Pod) ([]quiesce.PodIdentity, error) {
	if job == nil || job.UID == "" {
		return nil, c.ErrExecutionRecord
	}
	var out []quiesce.PodIdentity
	seen := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		owned := false
		for _, owner := range pod.OwnerReferences {
			if string(owner.UID) == string(job.UID) {
				owned = true
			}
		}
		if !owned {
			if publicationUploadPodRelated(job, pod) {
				return nil, c.ErrExecutionRecord
			}
			continue
		}
		if len(pod.OwnerReferences) != 1 {
			return nil, c.ErrExecutionRecord
		}
		owner := pod.OwnerReferences[0]
		if owner.Kind != "Job" || owner.APIVersion != "batch/v1" || owner.Name != job.Name || owner.Controller == nil || !*owner.Controller || pod.Namespace != job.Namespace || pod.UID == "" || seen[string(pod.UID)] || pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" || pod.ResourceVersion == "" || pod.Status.Phase != corev1.PodSucceeded || pod.Labels["backup.clawmanager.io/v2-task"] != job.Labels["backup.clawmanager.io/v2-task"] {
			return nil, c.ErrExecutionRecord
		}
		comparison := job.DeepCopy()
		comparison.Spec.Template.Spec = *pod.Spec.DeepCopy()
		comparison.Spec.Template.Spec.NodeName = job.Spec.Template.Spec.NodeName
		if !sameJob(job, comparison) || len(pod.Status.ContainerStatuses) != len(pod.Spec.Containers) || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
			return nil, c.ErrExecutionRecord
		}
		identity := quiesce.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName}
		ids := map[string]bool{}
		names := map[string]bool{}
		for _, container := range pod.Spec.Containers {
			names[container.Name] = true
		}
		for _, status := range pod.Status.ContainerStatuses {
			terminated := status.State.Terminated
			if !names[status.Name] || status.ContainerID == "" || ids[status.ContainerID] || terminated == nil || status.State.Running != nil || status.State.Waiting != nil || terminated.ContainerID != status.ContainerID || terminated.FinishedAt.IsZero() || terminated.ExitCode != 0 || status.RestartCount != 0 {
				return nil, c.ErrExecutionRecord
			}
			delete(names, status.Name)
			ids[status.ContainerID] = true
			identity.Containers = append(identity.Containers, status.ContainerID)
		}
		if len(names) != 0 || len(ids) == 0 {
			return nil, c.ErrExecutionRecord
		}
		sort.Strings(identity.Containers)
		out = append(out, identity)
		seen[identity.UID] = true
	}
	if len(out) != 1 {
		return nil, c.ErrExecutionRecord
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

func (s *DeploymentService) observeOriginalPublicationUploadExit(ctx context.Context, claim c.ClaimToken, attempt uint64, marker nativePublicationObject) (*publicationUploadExit, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Client == nil || s.Config.PublicationWorker == nil || marker.receipt == nil || marker.receipt.postManifestMarker == nil || marker.receipt.service != s || marker.receipt.access == nil {
		return nil, c.ErrExecutionAuthority
	}
	parent := marker.receipt.postManifestMarker
	if parent.service != s || parent.claim != claim || parent.attempt != attempt || parent.completion == nil || marker.receipt.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errPublicationUnavailable
	}
	defer tx.Rollback()
	p := &publicationUploadExit{service: s, claim: claim, attempt: attempt, marker: marker, pods: map[string]quiesce.PodIdentity{}}
	if err = p.recheckTx(ctx, tx); err != nil {
		return nil, err
	}
	raw, err := loadPublicationMetadata(ctx, tx, claim.Target.PublicID, publicationMaterialID(s.Config.InstallationID, claim.Target.PublicID, attempt))
	if err != nil || hash(raw) != parent.completion.materialSHA256 || decodeProviderDeploymentJSON(raw, &p.material) != nil || !formalCandidateDigest(p.material.RequestSHA256) {
		return nil, c.ErrExecutionRecord
	}
	a, err := s.loadPublicationActivationTx(ctx, tx, p.material)
	if err != nil || a == nil {
		return nil, c.ErrExecutionRecord
	}
	p.activation = *a
	process, processRaw, err := loadPublicationProcessTx(ctx, tx, p.material, *a)
	if err != nil || hash(processRaw) != parent.completion.uploadSnapshot.processSHA256 || process.NodeUID != s.Config.Security.NodeUIDs[process.Pod.Node] || process.ServiceAccountUID != s.Config.PublicationWorker.ServiceAccountUID {
		return nil, c.ErrExecutionRecord
	}
	p.process = process
	if tx.Rollback() != nil {
		return nil, errPublicationUnavailable
	}
	client := s.Runtime.Owner.Client
	if err = s.checkPublicationJobResources(ctx); err != nil {
		return nil, err
	}
	job, err := client.BatchV1().Jobs(p.material.Namespace).Get(ctx, "sbp-"+p.material.RequestSHA256[:32], metav1.GetOptions{})
	if err != nil || !publicationCompletedUploadJob(job, p.material, p.activation, s.Config.PublicationWorker.ServiceAccountName) {
		return nil, ErrJobUncertain
	}
	list, err := client.CoreV1().Pods(p.material.Namespace).List(ctx, metav1.ListOptions{Limit: 1001})
	if err != nil || list.Continue != "" || len(list.Items) > 1000 {
		return nil, ErrJobUncertain
	}
	pods, err := publicationOriginalUploadExitPods(job, list.Items, p.process)
	if err != nil {
		return nil, err
	}
	for _, pod := range pods {
		p.pods[pod.UID] = pod
	}
	p.jobResourceVersion = job.ResourceVersion
	witness := quiesce.KubeletStopWitness{Client: client, Watches: s.Runtime.Owner.WatchClient, Namespace: p.material.Namespace, NodeUIDs: s.Config.Security.NodeUIDs, Store: publicationUploadExitStore{exit: p}, Timeout: 5 * time.Second}
	if err = witness.Arm(ctx, pods); err != nil {
		return nil, err
	}
	if err = witness.Confirm(ctx, pods); err != nil {
		return nil, err
	}
	// A replacement/mutated Job is never accepted after the stop observation.
	current, err := client.BatchV1().Jobs(p.material.Namespace).Get(ctx, job.Name, metav1.GetOptions{})
	if err != nil || !publicationCompletedUploadJob(current, p.material, p.activation, s.Config.PublicationWorker.ServiceAccountName) || current.ResourceVersion != job.ResourceVersion {
		return nil, ErrJobUncertain
	}
	last, err := client.CoreV1().Pods(p.material.Namespace).List(ctx, metav1.ListOptions{Limit: 1001})
	if err != nil || last.Continue != "" || len(last.Items) > 1000 {
		return nil, ErrJobUncertain
	}
	lastPods, err := publicationOriginalUploadExitPods(current, last.Items, p.process)
	wantBytes, _ := json.Marshal(pods)
	lastBytes, _ := json.Marshal(lastPods)
	if err != nil || !bytes.Equal(wantBytes, lastBytes) {
		return nil, ErrJobUncertain
	}
	if marker.receipt.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	final, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errPublicationUnavailable
	}
	defer final.Rollback()
	if err = p.recheckTx(ctx, final); err != nil {
		return nil, err
	}
	if final.Rollback() != nil {
		return nil, errPublicationUnavailable
	}
	return p, nil
}

func (s *DeploymentService) completeOriginalPublicationThroughUploadExit(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (*publicationUploadExit, error) {
	marker, err := s.completeOriginalPublicationManifestAndMarker(ctx, claim, attempt, policy, store, capture)
	if err != nil {
		return nil, err
	}
	return s.observeOriginalPublicationUploadExit(ctx, *claim, attempt, marker)
}
