package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type identityEnvelope struct {
	KeyRef, PlainSHA256, InvocationSHA256 string
	Cipher                                []byte
}

func identityBinding(a d.Authority, name, digest string) staging.Binding {
	return staging.Binding{BackupID: a.TaskPublicID, Attempt: "1", Path: "worker-identity/" + name, CaptureContextHash: a.ConfigSHA256, EnvelopeID: digest}
}

// ensureIdentity stores encrypted key material BEFORE its only possible create.
// After an uncertain create, only GET of the original object is allowed. Public
// resource rows never contain a Kubernetes Secret's plaintext private key.
func (o *PublicJobOwner) ensureIdentity(ctx context.Context, a d.Authority, part b.JobPart) error {
	if o.Issuer.Certificate == nil || o.Issuer.Signer == nil || o.Issuer.TrustDomain != o.TrustDomain {
		return d.ErrNotReady
	}
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		return c.ErrExecutionRecord
	}
	var name string
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "worker-identity" && v.Secret != nil {
			name = v.Secret.SecretName
		}
	}
	if name == "" {
		return c.ErrExecutionRecord
	}
	db := o.Gate.Authority.DB
	var raw []byte
	var envelope identityEnvelope
	var sent bool
	var uid, rv string
	e := db.QueryRowContext(ctx, "SELECT request_json,create_dispatched,observed_uid,resource_version FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=?", a.TaskPublicID, o.Namespace, name).Scan(&raw, &sent, &uid, &rv)
	if errors.Is(e, sql.ErrNoRows) {
		tx, z := db.BeginTx(ctx, nil)
		if z != nil {
			return z
		}
		defer tx.Rollback()
		if z = o.Identity.AuthorizeWorkerIssuer(ctx, tx, a, hash(o.Issuer.Certificate.Raw)); z != nil {
			return z
		}
		tx.Rollback()
		identity, z := o.Issuer.IssueWorker(a.TaskPublicID, jobDeadline(part, a), part.InvocationSHA256)
		if z != nil {
			return z
		}
		defer identity.Clear()
		plain, z := json.Marshal(identity.Data)
		if z != nil {
			return z
		}
		defer clear(plain)
		ref, key, z := o.Identity.Resolve(ctx, a, "")
		defer clear(key)
		if z != nil {
			return z
		}
		envelope = identityEnvelope{KeyRef: ref, PlainSHA256: hash(plain), InvocationSHA256: part.InvocationSHA256}
		var cipher bytes.Buffer
		if z = staging.Seal(ctx, &cipher, key, identityBinding(a, name, envelope.PlainSHA256), func(w io.Writer) error { _, q := w.Write(plain); return q }); z != nil {
			return z
		}
		envelope.Cipher = cipher.Bytes()
		raw, _ = json.Marshal(envelope)
		tx, z = db.BeginTx(ctx, nil)
		if z != nil {
			return z
		}
		defer tx.Rollback()
		guard, z := o.Gate.Authority.Bind(ctx, tx, a)
		if z != nil {
			return z
		}
		if z = o.Identity.AuthorizeWorkerIssuer(ctx, tx, a, hash(o.Issuer.Certificate.Raw)); z != nil {
			return z
		}
		var capacity int64
		if z = tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", a.InstallationID, a.ConfigVersion).Scan(&capacity); z != nil {
			return z
		}
		if z = (security.RegistrationCapacity{ReportFile: o.Gate.Records.CapacityReportFile}).ReserveExecutionPayload(ctx, tx, capacity, len(raw)); z != nil {
			return z
		}
		_, z = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version) VALUES(?,'IdentitySecret',?,?,?,?,?,1)", a.TaskPublicID, o.Namespace, name, a.TaskPublicID, hash(raw), raw)
		if z != nil {
			return z
		}
		if z = guard.Recheck(ctx, tx); z != nil {
			return z
		}
		if z = tx.Commit(); z != nil {
			return c.ErrExecutionCommitUnknown
		}
	} else if e != nil {
		return e
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.InvocationSHA256 != part.InvocationSHA256 {
		return c.ErrExecutionRecord
	}
	actual, key, e := o.Identity.Resolve(ctx, a, envelope.KeyRef)
	defer clear(key)
	if e != nil || actual != envelope.KeyRef {
		return c.ErrExecutionRecord
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(envelope.Cipher), &plain, key, identityBinding(a, name, envelope.PlainSHA256), 64<<10) != nil || hash(plain.Bytes()) != envelope.PlainSHA256 {
		return c.ErrExecutionRecord
	}
	var data map[string][]byte
	if json.Unmarshal(plain.Bytes(), &data) != nil {
		return c.ErrExecutionRecord
	}
	defer func() {
		for _, v := range data {
			clear(v)
		}
	}()
	if !sent {
		tx, z := db.BeginTx(ctx, nil)
		if z != nil {
			return z
		}
		defer tx.Rollback()
		guard, z := o.Gate.Authority.Bind(ctx, tx, a)
		if z != nil {
			return z
		}
		if z = o.Identity.AuthorizeWorkerIssuer(ctx, tx, a, hash(o.Issuer.Certificate.Raw)); z != nil {
			return z
		}
		r, z := tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET create_dispatched=TRUE,row_version=row_version+1 WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=? AND create_dispatched=FALSE AND request_sha256=?", a.TaskPublicID, o.Namespace, name, hash(raw))
		if z != nil {
			return z
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return c.ErrExecutionRecoveryRequired
		}
		if z = guard.Recheck(ctx, tx); z != nil {
			return z
		}
		if z = tx.Commit(); z != nil {
			return c.ErrExecutionCommitUnknown
		}
	}
	// Lock authority across the bounded create/GET so takeover cannot overlap
	// another sender. The durable dispatched bit prevents creation on replay.
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	guard, e := o.Gate.Authority.Bind(ctx, tx, a)
	if e != nil {
		return e
	}
	if e = o.Identity.AuthorizeWorkerIssuer(ctx, tx, a, hash(o.Issuer.Certificate.Raw)); e != nil {
		return e
	}
	yes := true
	var secret *corev1.Secret
	if !sent {
		secret, e = o.Client.CoreV1().Secrets(o.Namespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: o.Namespace, Labels: map[string]string{kube.OwnerLabel: a.TaskPublicID}}, Immutable: &yes, Data: data}, metav1.CreateOptions{})
		if e != nil && !apierrors.IsAlreadyExists(e) {
			secret = nil
		}
	}
	if secret == nil {
		secret, e = o.Client.CoreV1().Secrets(o.Namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			return c.ErrExecutionRecoveryRequired
		}
	}
	if secret.UID == "" || secret.ResourceVersion == "" || secret.Labels[kube.OwnerLabel] != a.TaskPublicID || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil || kube.ContentHash(secret.Data) != envelope.PlainSHA256 || uid != "" && string(secret.UID) != uid {
		return kube.ErrOwnership
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET observed_uid=?,resource_version=?,lifecycle='ready',row_version=row_version+1 WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=? AND request_sha256=?", string(secret.UID), secret.ResourceVersion, a.TaskPublicID, o.Namespace, name, hash(raw)); e != nil {
		return e
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func jobDeadline(part b.JobPart, a d.Authority) time.Time {
	var inv worker.Invocation
	if json.Unmarshal(part.InvocationJSON, &inv) != nil || inv.Request.Deadline.After(a.DeadlineAt) {
		return time.Time{}
	}
	return inv.Request.Deadline
}
