package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type StopProof interface {
	Confirm(context.Context, []quiesce.PodIdentity) error
}

// PublicJobOwner is the concrete public resource/worker composition. It never
// creates a private control.Task. Immutable TLS Secrets and mount/node identities
// are supplied by deployment admission. It supports functional staging only;
// the final artifact key provider/acceptance belongs to M3.
type PublicJobOwner struct {
	Gate                                 c.SQLCaptureGate
	Client                               kubernetes.Interface
	WatchClient                          kubernetes.Interface
	Dynamic                              dynamic.Interface
	Namespace, NamespaceUID, TrustDomain string
	Security                             kube.WorkerSecurity
	Identity                             *c.PinnedExecutionIdentity
	Issuer                               control.IdentityIssuer
	Staging                              *os.Root
	Proof                                StopProof
	AllowKubeletStopWitness              bool
}

func hash(v []byte) string { s := sha256.Sum256(v); return hex.EncodeToString(s[:]) }

func (o *PublicJobOwner) ready() bool {
	return o != nil && o.Client != nil && o.Dynamic != nil && o.Namespace != "" && o.NamespaceUID != "" && o.TrustDomain != "" && o.Identity != nil && o.Staging != nil && (o.Proof != nil || o.AllowKubeletStopWitness) && o.Security.ServiceAccountUID != ""
}
func (o *PublicJobOwner) input(ctx context.Context, a d.Authority, recovery bool) (d.Input, d.Plan, b.Discovery, error) {
	var in d.Input
	var p d.Plan
	var desc b.Discovery
	if !o.ready() {
		return in, p, desc, d.ErrNotReady
	}
	var e error
	if recovery {
		e = o.Gate.Recovery.Check(ctx, a)
	} else {
		e = o.Gate.Check(ctx, a)
	}
	if e != nil {
		return in, p, desc, e
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return in, p, desc, e
	}
	defer tx.Rollback()
	var profile, config []byte
	if e = tx.QueryRowContext(ctx, `SELECT i.profile_json,b.config_snapshot_json FROM system_backup_v2_execution_inputs i JOIN system_backup_v2_backups b ON b.public_id=i.task_public_id AND b.origin_installation_id=i.origin_installation_id WHERE b.origin_installation_id=? AND b.public_id=? AND i.task_type='backup'`, a.InstallationID, a.TaskPublicID).Scan(&profile, &config); e != nil {
		return in, p, desc, e
	}
	var identity struct {
		Profile  string `json:"source_profile"`
		Revision string `json:"revision"`
	}
	if json.Unmarshal(profile, &identity) != nil {
		return in, p, desc, c.ErrExecutionInput
	}
	bclaim := c.ClaimedBackup{Claim: c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: a.TaskPublicID}, Owner: a.ClaimOwner, RowVersion: a.ClaimRowVersion}, InstallationID: a.InstallationID, Profile: profile, Config: config, RequestID: a.RequestID, ConfigVersion: a.ConfigVersion, ConfigSHA256: a.ConfigSHA256, Deadline: a.DeadlineAt}
	in, e = bclaim.ExecutionInput(ctx, tx)
	tx.Rollback()
	if e != nil || in.Authority != a {
		return in, p, desc, c.ErrExecutionAuthority
	}
	if in.Backup.TaskPurpose != "functional_test" {
		return in, p, desc, d.ErrNotReady
	}
	if recovery {
		p, e = o.Gate.Records.LoadRecoveryPlan(ctx, in, o.Gate.Recovery)
	} else {
		p, e = o.Gate.Records.LoadPlan(ctx, in)
	}
	if e != nil {
		return in, p, desc, e
	}
	inner, e := d.UnwrapTaskPlan(in, p, b.PlanVersion)
	if e != nil {
		return in, p, desc, e
	}
	defer clear(inner.CanonicalJSON)
	desc, e = b.DescribePlan(in, inner)
	return in, p, desc, e
}
func (o *PublicJobOwner) namespace(ctx context.Context) error {
	ns, e := o.Client.CoreV1().Namespaces().Get(ctx, o.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != o.NamespaceUID || ns.DeletionTimestamp != nil {
		return kube.ErrOwnership
	}
	return nil
}
func (o *PublicJobOwner) rows(task string) (*kube.MappedResourceRows, error) {
	return kube.NewMappedResourceRows(task, "system_backup_v2_runtime_resources", "ready", kube.ResourceColumns{Scope: "task_public_id", Kind: "resource_kind", Namespace: "namespace_name", Name: "resource_name", Owner: "resource_owner", RequestHash: "request_sha256", RequestJSON: "request_json", Revision: "row_version", Dispatched: "create_dispatched", UID: "observed_uid", ResourceVersion: "resource_version", Lifecycle: "lifecycle"})
}
func (o *PublicJobOwner) runner(a d.Authority, recovery bool) (kube.Runner, error) {
	rows, e := o.rows(a.TaskPublicID)
	if e != nil {
		return kube.Runner{}, e
	}
	fence := func(ctx context.Context, tx *sql.Tx) error {
		if e := o.namespace(ctx); e != nil {
			return e
		}
		if recovery {
			return o.Gate.Recovery.CheckTx(ctx, tx, a)
		}
		guard, e := o.Gate.Authority.Bind(ctx, tx, a)
		if e != nil {
			return e
		}
		return guard.Recheck(ctx, tx)
	}
	check := func(ctx context.Context) error {
		if e := o.namespace(ctx); e != nil {
			return e
		}
		if recovery {
			return o.Gate.Recovery.Check(ctx, a)
		}
		return o.Gate.ValidateCollectors(ctx, a)
	}
	return kube.Runner{Client: o.Dynamic, Journal: kube.SQLJournal{DB: o.Gate.Authority.DB, Rows: rows, Fence: fence}, CheckFence: check}, nil
}
func (o *PublicJobOwner) Admit(ctx context.Context, a d.Authority, intent d.JobIntent) (d.Input, d.Plan, kube.Runner, error) {
	in, p, desc, e := o.input(ctx, a, false)
	if e != nil {
		return in, p, kube.Runner{}, e
	}
	if intent.Namespace != o.Namespace {
		return in, p, kube.Runner{}, kube.ErrOwnership
	}
	if e = o.Gate.ValidateCollectors(ctx, a); e != nil {
		return in, p, kube.Runner{}, e
	}
	if e = o.ensureStaging(a.TaskPublicID); e != nil {
		return in, p, kube.Runner{}, e
	}
	found := false
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey == intent.JobUnitKey && part.Intent.Name == intent.Name && part.Intent.Generation == intent.Generation && part.Intent.SpecSHA256 == intent.SpecSHA256 && bytes.Equal(part.Intent.SpecJSON, intent.SpecJSON) {
			found = true
		}
	}
	if !found {
		return in, p, kube.Runner{}, c.ErrExecutionRecord
	}
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey == intent.JobUnitKey {
			if e = o.ensureIdentity(ctx, a, part); e != nil {
				return in, p, kube.Runner{}, e
			}
		}
	}
	runner, e := o.runner(a, false)
	return in, p, runner, e
}
func partFor(desc b.Discovery, unit string) (b.JobPart, error) {
	for _, p := range desc.Parts {
		if p.Intent.JobUnitKey == unit {
			return p, nil
		}
	}
	return b.JobPart{}, c.ErrExecutionRecord
}

func (o *PublicJobOwner) Bind(ctx context.Context, a d.Authority, i d.JobIntent, r kube.ResourceRecord) (d.JobBinding, error) {
	return o.bindOriginal(ctx, a, i, r, false)
}

// Recovery binding records original identity only; it never issues credentials.
func (o *PublicJobOwner) bindOriginal(ctx context.Context, a d.Authority, i d.JobIntent, r kube.ResourceRecord, recovery bool) (d.JobBinding, error) {
	var zero d.JobBinding
	_, _, desc, e := o.input(ctx, a, recovery)
	if e != nil {
		return zero, e
	}
	part, e := partFor(desc, i.JobUnitKey)
	if e != nil {
		return zero, e
	}
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil || r.UID == "" || r.Intent.Identity.Namespace != part.Intent.Namespace || r.Intent.Identity.Name != part.Intent.Name {
		return zero, c.ErrExecutionRecord
	}
	var secretName string
	boundToken := false
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "worker-identity" && v.Secret != nil {
			secretName = v.Secret.SecretName
		}
		if v.Name == "worker-pod-identity" && v.Projected != nil {
			boundToken = true
		}
	}
	if secretName == "" || !boundToken {
		return zero, d.ErrNotReady
	}
	secret, e := o.Client.CoreV1().Secrets(o.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if e != nil || secret.UID == "" || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil {
		return zero, kube.ErrOwnership
	}
	var originalUID, originalHash string
	var originalRaw []byte
	if o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT observed_uid,request_sha256,request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=? AND create_dispatched=TRUE AND lifecycle='ready'`, a.TaskPublicID, o.Namespace, secretName).Scan(&originalUID, &originalHash, &originalRaw) != nil {
		return zero, c.ErrExecutionRecord
	}
	if !originalIdentitySecretMatches(secret, originalUID, originalHash, originalRaw, part.InvocationSHA256) {
		return zero, kube.ErrOwnership
	}
	block, _ := pem.Decode(secret.Data["tls.crt"])
	if block == nil {
		return zero, kube.ErrOwnership
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://"+o.TrustDomain+"/backup/"+a.TaskPublicID+"/"+part.InvocationSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	until := cert.NotAfter
	if until.After(a.DeadlineAt) {
		until = a.DeadlineAt
	}
	var inv worker.Invocation
	json.Unmarshal(part.InvocationJSON, &inv)
	if until.After(inv.Request.Deadline) {
		until = inv.Request.Deadline
	}
	now := time.Now().UTC()
	if !recovery && (!until.After(now) || now.Before(cert.NotBefore)) {
		return zero, c.ErrExecutionAuthority
	}
	if recovery {
		now = cert.NotBefore
	}
	binding := d.JobBinding{JobUnitKey: i.JobUnitKey, Namespace: i.Namespace, Name: i.Name, UID: r.UID, Generation: i.Generation, RelayIdentityRef: string(secret.UID), RelayIdentityVersion: hash(cert.Raw), RelayBoundAt: now, RelayExpiresAt: until}
	raw, _ := json.Marshal(binding)
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback()
	recheck := func() error { return o.Gate.Recovery.CheckTx(ctx, tx, a) }
	if !recovery {
		guard, z := o.Gate.Authority.Bind(ctx, tx, a)
		if z != nil {
			return zero, z
		}
		recheck = func() error { return guard.Recheck(ctx, tx) }
	}
	if e = recheck(); e != nil {
		return zero, e
	}
	var old []byte
	if e = tx.QueryRowContext(ctx, "SELECT binding_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? FOR UPDATE", a.TaskPublicID, i.Namespace, i.Name, r.UID).Scan(&old); e != nil {
		return zero, e
	}
	if len(old) > 0 {
		if json.Unmarshal(old, &binding) != nil || binding.UID != r.UID || binding.Generation != i.Generation || binding.RelayIdentityRef != string(secret.UID) || binding.RelayIdentityVersion != hash(cert.Raw) {
			return zero, c.ErrExecutionRecord
		}
	} else {
		query := "UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND binding_json IS NULL"
		if recovery {
			query = "UPDATE system_backup_v2_runtime_resources SET binding_json=?,revoked=TRUE WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND binding_json IS NULL"
		}
		if _, e = tx.ExecContext(ctx, query, raw, a.TaskPublicID, i.Namespace, i.Name, r.UID); e != nil {
			return zero, e
		}
	}
	if e = recheck(); e != nil {
		return zero, e
	}
	if e = tx.Commit(); e != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	return binding, nil
}

// Same-name replacement or modified identity material cannot become the
// original binding, including recovery after a missing binding write.
func originalIdentitySecretMatches(actual *corev1.Secret, uid, digest string, raw []byte, invocation string) bool {
	if actual == nil || uid == "" || string(actual.UID) != uid || hash(raw) != digest {
		return false
	}
	var original identityEnvelope
	if json.Unmarshal(raw, &original) != nil || original.InvocationSHA256 != invocation || len(original.Cipher) == 0 {
		return false
	}
	plain, e := json.Marshal(actual.Data)
	defer clear(plain)
	return e == nil && hash(plain) == original.PlainSHA256
}

func (o *PublicJobOwner) Read(ctx context.Context, a d.Authority, binding d.JobBinding, recovery bool) (kube.Runner, kube.ResourceRecord, error) {
	var record kube.ResourceRecord
	if !o.ready() {
		return kube.Runner{}, record, d.ErrNotReady
	}
	_, _, desc, e := o.input(ctx, a, recovery)
	if e != nil {
		return kube.Runner{}, record, e
	}
	part, e := partFor(desc, binding.JobUnitKey)
	if e != nil {
		return kube.Runner{}, record, e
	}
	var originalJob batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &originalJob) != nil {
		return kube.Runner{}, record, c.ErrExecutionRecord
	}
	expected, e := kube.Intent("Job", &originalJob)
	if e != nil {
		return kube.Runner{}, record, e
	}
	if recovery {
		if e := o.Gate.Recovery.Check(ctx, a); e != nil {
			return kube.Runner{}, record, e
		}
	} else {
		if e := o.Gate.Check(ctx, a); e != nil {
			return kube.Runner{}, record, e
		}
	}
	rows, e := o.rows(a.TaskPublicID)
	if e != nil {
		return kube.Runner{}, record, e
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return kube.Runner{}, record, e
	}
	defer tx.Rollback()
	record, e = rows.Load(ctx, tx, kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: binding.Namespace, Name: binding.Name}})
	if e != nil {
		return kube.Runner{}, record, e
	}
	if record.Intent.Identity != expected.Identity || record.Intent.RequestSHA256 != expected.RequestSHA256 || !bytes.Equal(record.Intent.RequestJSON, expected.RequestJSON) {
		return kube.Runner{}, record, c.ErrExecutionRecord
	}
	var raw []byte
	var original d.JobBinding
	if tx.QueryRowContext(ctx, "SELECT binding_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=?", a.TaskPublicID, binding.Namespace, binding.Name).Scan(&raw) != nil || json.Unmarshal(raw, &original) != nil || original != binding || record.UID != binding.UID {
		return kube.Runner{}, record, c.ErrExecutionRecord
	}
	runner, e := o.runner(a, recovery)
	return runner, record, e
}

func (o *PublicJobOwner) Revoke(ctx context.Context, a d.Authority, binding d.JobBinding) error {
	var processRaw []byte
	if o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?", a.TaskPublicID, binding.UID).Scan(&processRaw) != nil {
		return c.ErrExecutionRecoveryRequired
	}
	var process kube.WorkerProcess
	if json.Unmarshal(processRaw, &process) != nil || process.UID == "" {
		return c.ErrExecutionRecoveryRequired
	}
	// Arm while the original Pod still exists, before foreground deletion can
	// remove its CRI record. A saved witness makes this idempotent on recovery.
	if e := o.StopWitness(a).Arm(ctx, []quiesce.PodIdentity{{Name: process.Name, UID: process.UID, Node: process.Node, Containers: process.Containers}}); e != nil {
		if o.Proof == nil {
			return c.ErrExecutionRecoveryRequired
		}
		if e = o.Proof.Confirm(ctx, []quiesce.PodIdentity{{Name: process.Name, UID: process.UID, Node: process.Node, Containers: process.Containers}}); e != nil {
			return e
		}
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	r, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=?", a.TaskPublicID, binding.Namespace, binding.Name, binding.UID)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		var revoked bool
		if tx.QueryRowContext(ctx, "SELECT revoked FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=?", a.TaskPublicID, binding.Namespace, binding.Name, binding.UID).Scan(&revoked) != nil || !revoked {
			return c.ErrExecutionRecord
		}
	}
	return tx.Commit()
}
func (o *PublicJobOwner) Stopped(ctx context.Context, a d.Authority, binding d.JobBinding) error {
	if e := o.Gate.Recovery.Check(ctx, a); e != nil {
		return e
	}
	var process []byte
	var revoked bool
	if e := o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT process_json,revoked FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?", a.TaskPublicID, binding.UID).Scan(&process, &revoked); e != nil || !revoked {
		return c.ErrExecutionRecoveryRequired
	}
	var p kube.WorkerProcess
	if json.Unmarshal(process, &p) != nil || p.UID == "" || len(p.Containers) == 0 {
		return c.ErrExecutionRecoveryRequired
	}
	pods := []quiesce.PodIdentity{{Name: p.Name, UID: p.UID, Node: p.Node, Containers: p.Containers}}
	proved := false
	if o.AllowKubeletStopWitness {
		proved = o.StopWitness(a).Confirm(ctx, pods) == nil
	}
	if !proved {
		if o.Proof == nil {
			return c.ErrExecutionRecoveryRequired
		}
		if e := o.Proof.Confirm(ctx, pods); e != nil {
			return e
		}
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = o.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET stopped_at=COALESCE(stopped_at,UTC_TIMESTAMP(6)) WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND revoked=TRUE", a.TaskPublicID, binding.UID)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// Authorize is reached only behind WorkloadIdentity + worker.ControlHandler's
// mTLS verification. The bound Pod and saved process/Job UID must agree.
func (o *PublicJobOwner) Authorize(ctx context.Context, peer string, req worker.ControlRequest) (worker.Lease, error) {
	var lease worker.Lease
	pod, ok := boundPod(ctx)
	if !ok || !o.ready() || pod.Namespace != o.Namespace || pod.ServiceAccountUID != o.Security.ServiceAccountUID {
		return lease, worker.ErrExecution
	}
	task := req.Invocation.Request.Binding.BackupID
	var a d.Authority
	var owner, request, configHash string
	var version, configVersion, fence uint64
	var deadline time.Time
	db := o.Gate.Authority.DB
	if e := db.QueryRowContext(ctx, "SELECT controller_owner,row_version,request_id,config_version,config_snapshot_sha256,deadline_at,maintenance_fencing_token FROM system_backup_v2_backups WHERE public_id=? AND origin_installation_id=?", task, o.Gate.Authority.InstallationID).Scan(&owner, &version, &request, &configVersion, &configHash, &deadline, &fence); e != nil {
		return lease, worker.ErrNotReady
	}
	a = d.Authority{InstallationID: o.Gate.Authority.InstallationID, TaskPublicID: task, TaskType: "backup", RequestID: request, ConfigVersion: configVersion, ConfigSHA256: configHash, AttemptNo: 1, Phase: "capture", ClaimOwner: owner, ClaimRowVersion: version, MaintenanceOwner: task, MaintenanceFencingToken: fence, DeadlineAt: deadline}
	in, plan, desc, e := o.input(ctx, a, false)
	if e != nil {
		return lease, worker.ErrExecution
	}
	var part *b.JobPart
	for idx := range desc.Parts {
		p := &desc.Parts[idx]
		if p.InvocationSHA256 == req.InvocationSHA256 {
			part = p
		}
	}
	if part == nil || peer != "spiffe://"+o.TrustDomain+"/backup/"+task+"/"+part.InvocationSHA256 {
		return lease, worker.ErrExecution
	}
	original, _ := json.Marshal(req.Invocation)
	if !bytes.Equal(original, part.InvocationJSON) {
		return lease, worker.ErrExecution
	}
	var rawBinding []byte
	var revoked bool
	if e = db.QueryRowContext(ctx, "SELECT binding_json,revoked FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=?", task, part.Intent.Namespace, part.Intent.Name).Scan(&rawBinding, &revoked); e != nil || len(rawBinding) == 0 {
		return lease, worker.PendingControl("job_binding_pending")
	}
	var binding d.JobBinding
	if json.Unmarshal(rawBinding, &binding) != nil || revoked || !time.Now().Before(binding.RelayExpiresAt) {
		return lease, worker.ErrExecution
	}
	_, record, e := o.Read(ctx, a, binding, false)
	if e != nil {
		return lease, worker.ErrExecution
	}
	security, e := o.workerSecurity(ctx, a, *part)
	if e != nil {
		return lease, worker.PendingControl("worker_mount_identity_pending")
	}
	process, e := (kube.WorkerObserver{Client: o.Client}).Observe(ctx, record, security)
	if e != nil {
		return lease, worker.PendingControl("worker_" + kube.ObservationStage(e) + "_pending")
	}
	if process.Name != pod.Name || process.UID != pod.UID {
		return lease, worker.ErrExecution
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return lease, worker.ErrNotReady
	}
	defer tx.Rollback()
	guard, e := o.Gate.Authority.Bind(ctx, tx, a)
	if e != nil {
		return lease, worker.ErrExecution
	}
	var old []byte
	if e = tx.QueryRowContext(ctx, "SELECT process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND revoked=FALSE FOR UPDATE", task, binding.UID).Scan(&old); e != nil {
		return lease, worker.ErrExecution
	}
	if len(old) > 0 {
		var p kube.WorkerProcess
		if json.Unmarshal(old, &p) != nil || !kube.SameWorkerProcess(p, process) {
			return lease, worker.ErrExecution
		}
	} else {
		raw, _ := json.Marshal(process)
		if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET process_json=? WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND process_json IS NULL", raw, task, binding.UID); e != nil {
			return lease, worker.ErrNotReady
		}
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return lease, worker.ErrExecution
	}
	observationRaw, _ := json.Marshal(req)
	observationHash := hash(observationRaw)
	clear(observationRaw)
	if e = recordPublicObservation(ctx, tx, a, binding, "running", observationHash); e != nil {
		return lease, worker.ErrNotReady
	}
	if e = tx.Commit(); e != nil {
		return lease, worker.ErrNotReady
	}
	if e = o.Gate.ValidateCollectors(ctx, a); e != nil {
		return lease, worker.ErrExecution
	}
	lease = worker.Lease{InvocationSHA256: req.InvocationSHA256, ExpiresAt: binding.RelayExpiresAt}
	keyInput, _ := json.Marshal(req.Invocation.Request.Binding)
	switch req.Action {
	case "ready", "check":
		return lease, nil
	case "acquire":
		if req.Invocation.Request.Database != nil {
			return worker.Lease{}, worker.ErrNotReady
		} // no implicit SQL credentials
		lease.DEK, e = o.Identity.DeriveCaptureKey(ctx, a, keyInput)
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		return lease, nil
	case "complete":
		if req.Result == nil || !worker.ValidateResult(req.Invocation.Request, req.Result) {
			return worker.Lease{}, worker.ErrExecution
		}
		key, e := o.Identity.DeriveCaptureKey(ctx, a, keyInput)
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		defer clear(key)
		root, e := o.Staging.OpenRoot(a.TaskPublicID)
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		defer root.Close()
		file, e := staging.OpenFile(ctx, root, req.Result.Receipt)
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		defer file.Close()
		if e = staging.Open(ctx, file, io.Discard, key, req.Invocation.Request.Binding, req.Invocation.Request.MaxCompressedBytes); e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		inner, e := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		defer clear(inner.CanonicalJSON)
		result, e := b.BuildPartResult(in, inner, part.Intent.JobUnitKey, binding, *req.Result, b.SealedPart{Reference: req.Result.Receipt.Name, ContentSHA256: req.Result.Receipt.SHA256, EvidenceIDs: []string{}})
		if e != nil {
			return worker.Lease{}, worker.ErrExecution
		}
		resultRaw, _ := json.Marshal(result)
		if e = o.saveResult(ctx, a, binding, resultRaw); e != nil {
			return worker.Lease{}, worker.ErrNotReady
		}
		return lease, nil
	}
	return worker.Lease{}, worker.ErrExecution
}

func (o *PublicJobOwner) saveResult(ctx context.Context, a d.Authority, binding d.JobBinding, raw []byte) error {
	ref, key, e := o.Identity.Resolve(ctx, a, "")
	if e != nil {
		return e
	}
	defer clear(key)
	digest := hash(raw)
	var cipher bytes.Buffer
	bnd := staging.Binding{BackupID: a.TaskPublicID, Attempt: "1", Path: "worker-result/" + binding.JobUnitKey, CaptureContextHash: a.ConfigSHA256, EnvelopeID: digest}
	if e = staging.Seal(ctx, &cipher, key, bnd, func(w io.Writer) error { _, z := w.Write(raw); return z }); e != nil {
		return e
	}
	tx, e := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	guard, e := o.Gate.Authority.Bind(ctx, tx, a)
	if e != nil {
		return e
	}
	var old sql.NullString
	if e = tx.QueryRowContext(ctx, "SELECT result_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND revoked=FALSE FOR UPDATE", a.TaskPublicID, binding.UID).Scan(&old); e != nil {
		return e
	}
	if old.Valid && old.String != digest {
		return c.ErrExecutionRecord
	}
	if !old.Valid {
		if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET result_cipher=?,result_key_ref=?,result_sha256=? WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=? AND result_sha256 IS NULL AND revoked=FALSE", cipher.Bytes(), ref, digest, a.TaskPublicID, binding.UID); e != nil {
			return e
		}
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return e
	}
	if e = recordPublicObservation(ctx, tx, a, binding, "sealed", digest); e != nil {
		return e
	}
	return tx.Commit()
}
func (o *PublicJobOwner) Evidence(ctx context.Context, a d.Authority, binding d.JobBinding) (*d.EvidenceRef, error) {
	if e := o.Gate.Check(ctx, a); e != nil {
		return nil, e
	}
	var digest sql.NullString
	if e := o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT result_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?", a.TaskPublicID, binding.UID).Scan(&digest); e != nil {
		return nil, e
	}
	if !digest.Valid {
		return nil, nil
	}
	return &d.EvidenceRef{PublicID: "sev_" + digest.String, SHA256: digest.String}, nil
}
func (o *PublicJobOwner) ReadResult(ctx context.Context, a d.Authority, binding d.JobBinding, ref d.EvidenceRef) ([]byte, error) {
	if _, _, e := o.Read(ctx, a, binding, false); e != nil {
		return nil, e
	}
	if e := o.Gate.Check(ctx, a); e != nil {
		return nil, e
	}
	var digest, keyRef string
	var cipher []byte
	if e := o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT result_sha256,result_key_ref,result_cipher FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?", a.TaskPublicID, binding.UID).Scan(&digest, &keyRef, &cipher); e != nil {
		return nil, e
	}
	if ref.PublicID != "sev_"+digest || ref.SHA256 != digest || len(cipher) > 1<<20 {
		return nil, c.ErrExecutionRecord
	}
	actual, key, e := o.Identity.Resolve(ctx, a, keyRef)
	defer clear(key)
	if e != nil || actual != keyRef {
		return nil, c.ErrExecutionRecord
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(cipher), &plain, key, staging.Binding{BackupID: a.TaskPublicID, Attempt: "1", Path: "worker-result/" + binding.JobUnitKey, CaptureContextHash: a.ConfigSHA256, EnvelopeID: digest}, 1<<20) != nil || hash(plain.Bytes()) != digest {
		return nil, c.ErrExecutionRecord
	}
	if e = o.Gate.Check(ctx, a); e != nil {
		return nil, e
	}
	return bytes.Clone(plain.Bytes()), nil
}

type PublicResults struct{ Owner *PublicJobOwner }

func (r PublicResults) Read(ctx context.Context, a d.Authority, binding d.JobBinding, ref d.EvidenceRef) ([]byte, error) {
	if r.Owner == nil {
		return nil, d.ErrNotReady
	}
	return r.Owner.ReadResult(ctx, a, binding, ref)
}

var _ c.ExecutionJobOwner = (*PublicJobOwner)(nil)
var _ worker.Authorizer = (*PublicJobOwner)(nil)
