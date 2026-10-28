package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (o *PublicJobOwner) ensureStaging(task string) error {
	if o.Staging == nil || len(task) != 40 {
		return c.ErrExecutionRecord
	}
	e := o.Staging.Mkdir(task, 0700)
	if e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	info, e := o.Staging.Lstat(task)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return c.ErrExecutionRecord
	}
	return nil
}

// The invocation ConfigMap is created after Prepare. Bind its actual UID from
// the original resource journal, not from an arbitrary same-name live object.
// All pre-existing source/staging/identity refs remain pinned by deployment.
func (o *PublicJobOwner) workerSecurity(ctx context.Context, a d.Authority, part b.JobPart) (kube.WorkerSecurity, error) {
	s := o.Security
	s.Volumes = append([]kube.MountIdentity(nil), s.Volumes...)
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return s, e
	}
	defer tx.Rollback()
	rows, e := o.rows(a.TaskPublicID)
	if e != nil {
		return s, e
	}
	record, e := rows.Load(ctx, tx, kube.ResourceIntent{Kind: "ConfigMap", Identity: kube.Identity{Namespace: part.Intent.Namespace, Name: part.InvocationConfigMap}})
	if e != nil || record.Deleted || record.Deleting || record.UID == "" {
		return s, kube.ErrOwnership
	}
	var desired corev1.ConfigMap
	if json.Unmarshal(record.Intent.RequestJSON, &desired) != nil || desired.Data["invocation.json"] != string(part.InvocationJSON) {
		return s, kube.ErrOwnership
	}
	for _, v := range s.Volumes {
		if v.Volume == "worker-request" {
			return s, kube.ErrOwnership
		}
	}
	s.Volumes = append(s.Volumes, kube.MountIdentity{Volume: "worker-request", Kind: "ConfigMap", Name: part.InvocationConfigMap, UID: record.UID, SHA256: kube.ContentHash([]any{desired.Data, desired.BinaryData})})
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		return s, kube.ErrOwnership
	}
	var identityName string
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "worker-identity" && v.Secret != nil {
			identityName = v.Secret.SecretName
		}
	}
	var identityUID string
	var sealed []byte
	if tx.QueryRowContext(ctx, "SELECT observed_uid,request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=? AND create_dispatched=TRUE AND lifecycle='ready'", a.TaskPublicID, part.Intent.Namespace, identityName).Scan(&identityUID, &sealed) != nil || identityUID == "" {
		return s, kube.ErrOwnership
	}
	var identity identityEnvelope
	if json.Unmarshal(sealed, &identity) != nil {
		return s, kube.ErrOwnership
	}
	for _, v := range s.Volumes {
		if v.Volume == "worker-identity" {
			return s, kube.ErrOwnership
		}
	}
	s.Volumes = append(s.Volumes, kube.MountIdentity{Volume: "worker-identity", Kind: "Secret", Name: identityName, UID: identityUID, SHA256: identity.PlainSHA256})
	tx.Rollback()
	actual, e := o.Client.CoreV1().ConfigMaps(part.Intent.Namespace).Get(ctx, part.InvocationConfigMap, metav1.GetOptions{})
	if e != nil || string(actual.UID) != record.UID {
		return s, kube.ErrOwnership
	}
	return s, nil
}
