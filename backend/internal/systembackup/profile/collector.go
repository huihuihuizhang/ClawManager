package profile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type collector struct {
	d     *Driver
	t     control.Task
	p     plan
	w     work
	inner *control.JobCollector
}

func (c *collector) ID() string { return c.w.ID }
func (d *Driver) runner(t control.Task, recovery bool) (kube.Runner, error) {
	var j kube.ResourceJournal
	var e error
	if recovery {
		j, e = d.Store.CleanupJournal(t)
	} else {
		j, e = d.Store.ResourceJournal(t)
	}
	return kube.Runner{Client: d.Dynamic, Journal: j, CheckFence: func(ctx context.Context) error { return d.fence(ctx, t, recovery) }}, e
}
func resourceName(t control.Task, id string) string { return t.ID + "-" + id }
func (c *collector) identity(suffix string) kube.Identity {
	return kube.Identity{Namespace: c.w.Namespace, Name: resourceName(c.t, c.w.ID) + suffix, Owner: c.t.ID}
}
func (c *collector) credentials() control.DatabaseCredentials {
	db := c.d.TargetAdmin
	if c.w.Invocation.Request.Operation == "capture-database" {
		db = c.d.SourceAdmin
	}
	return control.DatabaseCredentials{Vault: c.d.Vault, Admin: db}
}
func (c *collector) resolved(ctx context.Context) (work, error) {
	w := c.w
	if w.Invocation.Request.Operation != "verify-database" {
		return w, nil
	}
	for _, candidate := range c.p.Work {
		if candidate.Invocation.Request.Operation == "restore-database" {
			hash, _ := candidate.Invocation.Hash()
			status, e := c.d.Store.WorkerStatus(ctx, c.t, hash)
			if e != nil || status.Result == nil || status.Result.Evidence.Name == "" {
				return w, ErrProfile
			}
			w.Invocation.Request.Receipt = status.Result.Evidence
			return w, nil
		}
	}
	return w, ErrProfile
}
func (c *collector) build(w work) (*batchv1.Job, *corev1.ConfigMap, error) {
	controlRef := kube.WorkerControl{URL: c.d.Config.ControlURL, InvocationConfigMap: c.identity("-request").Name, IdentitySecret: c.identity("-identity").Name}
	cfg, e := kube.WorkerConfigMap(c.identity("-request"), w.Invocation)
	if e != nil {
		return nil, nil, e
	}
	staging := c.d.Config.Staging[w.Namespace].Name
	if w.Invocation.Request.Operation == "verify-database" {
		staging = c.d.Config.Evidence.Name
	}
	var job *batchv1.Job
	if w.Invocation.Request.Database != nil {
		evidence := ""
		if w.Invocation.Request.Operation == "restore-database" {
			evidence = c.d.Config.Evidence.Name
		}
		job, e = kube.DatabaseJob(kube.DatabaseJobRequest{Identity: c.identity(""), Image: c.d.Config.WorkerImage, ServiceAccount: c.d.Config.ServiceAccount, StagingClaim: staging, EvidenceClaim: evidence, NodeName: w.Node, Operation: w.Invocation.Request.Operation, DeadlineSeconds: 7200, Control: controlRef})
	} else {
		if w.Source == nil {
			return nil, nil, ErrProfile
		}
		source := *w.Source.DeepCopy()
		if w.SnapshotClass != "" {
			source = corev1.Volume{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: c.identity("-clone").Name, ReadOnly: true}}}
		}
		job, e = kube.Job(kube.JobRequest{Identity: c.identity(""), Image: c.d.Config.WorkerImage, ServiceAccount: c.d.Config.ServiceAccount, Source: source, SourceSubPath: w.SubPath, StagingClaim: staging, NodeName: w.Node, DeadlineSeconds: 7200, Restore: strings.HasPrefix(w.Invocation.Request.Operation, "restore-"), WorkerControl: &controlRef})
	}
	if e != nil {
		return nil, nil, e
	}
	job.Spec.Template.Spec.NodeSelector = map[string]string{corev1.LabelOSStable: "linux"}
	if w.Invocation.Request.Operation == "verify-assets" {
		for index := range job.Spec.Template.Spec.Volumes {
			v := &job.Spec.Template.Spec.Volumes[index]
			if v.PersistentVolumeClaim != nil {
				v.PersistentVolumeClaim.ReadOnly = true
			}
		}
	}
	// A per-task directory on the explicitly shared staging/evidence claims.
	// The invocation keeps its fixed /staging and /evidence paths inside the Pod.
	for idx := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
		m := &job.Spec.Template.Spec.Containers[0].VolumeMounts[idx]
		if m.Name == "staging" || m.Name == "evidence" {
			m.SubPath = c.t.ID
			if w.Invocation.Request.Operation == "verify-assets" {
				m.ReadOnly = true
			}
		}
	}
	return job, cfg, nil
}
func (c *collector) grant(w work, job *batchv1.Job) control.WorkerGrant {
	hash, _ := w.Invocation.Hash()
	g := control.WorkerGrant{TaskID: c.t.ID, ProfileRevision: c.t.ProfileRevision, SPIFFE: "spiffe://" + c.d.Identities.Issuer.TrustDomain + "/backup/" + c.t.ID + "/" + hash, JobNamespace: job.Namespace, JobName: job.Name, Invocation: w.Invocation, Key: w.Key}
	if w.Invocation.Request.Database != nil {
		g.CredentialRef = c.w.ID + "-sql"
	}
	return g
}
func (c *collector) snapshot(ctx context.Context, runner kube.Runner) error {
	var frozen *frozenInstance
	for idx := range c.p.Instances {
		f := &c.p.Instances[idx]
		if fmt.Sprintf("instance-%d", f.SQL.ID) == c.w.PartID {
			frozen = f
		}
	}
	if frozen == nil {
		return ErrProfile
	}
	uid, e := c.d.snapshotClass(ctx, c.w.SnapshotClass, frozen.SnapshotDriver)
	if e != nil || uid != frozen.SnapshotUID {
		return ErrProfile
	}
	for _, m := range frozen.Mounts {
		live, e := c.d.claim(ctx, c.w.Namespace, Claim{m.Name, m.UID})
		live.Volume = m.Volume
		if e != nil || !jsonEqual(live, m) {
			return ErrProfile
		}
	}
	snapshot, e := kube.Snapshot(c.identity("-snapshot"), c.w.SnapshotClaim, c.w.SnapshotClass, true)
	if e != nil {
		return e
	}
	// The class is probed and bound before pause; no snapshot exists until this
	// method runs inside Capture with every source writer acknowledged stopped.
	r, e := runner.Ensure(ctx, "VolumeSnapshot", snapshot)
	if e != nil {
		return e
	}
	api := c.d.Dynamic.Resource(schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}).Namespace(c.w.Namespace)
	for {
		s, e := api.Get(ctx, r.Intent.Identity.Name, metav1.GetOptions{})
		if e != nil {
			return ErrProfile
		}
		if kube.SnapshotReady(s, r.Intent.Identity, r.UID, c.w.SnapshotClaim) {
			contentName, _, _ := unstructured.NestedString(s.Object, "status", "boundVolumeSnapshotContentName")
			content, e := c.d.Dynamic.Resource(schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotcontents"}).Get(ctx, contentName, metav1.GetOptions{})
			if e != nil {
				return ErrProfile
			}
			refUID, _, _ := unstructured.NestedString(content.Object, "spec", "volumeSnapshotRef", "uid")
			driver, _, _ := unstructured.NestedString(content.Object, "spec", "driver")
			handle, _, _ := unstructured.NestedString(content.Object, "spec", "source", "volumeHandle")
			if refUID != r.UID || driver != frozen.SnapshotDriver || frozen.SnapshotVolume == "" || handle != frozen.SnapshotVolume {
				return ErrProfile
			}
			break
		}
		if !poll(ctx) {
			return ctx.Err()
		}
	}
	source, e := c.d.Client.CoreV1().PersistentVolumeClaims(c.w.Namespace).Get(ctx, c.w.SnapshotClaim, metav1.GetOptions{})
	if e != nil || source.Spec.StorageClassName == nil {
		return ErrProfile
	}
	group := "snapshot.storage.k8s.io"
	clone := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: c.identity("-clone").Name, Namespace: c.w.Namespace, Labels: map[string]string{kube.OwnerLabel: c.t.ID}}, Spec: corev1.PersistentVolumeClaimSpec{AccessModes: append([]corev1.PersistentVolumeAccessMode(nil), source.Spec.AccessModes...), StorageClassName: source.Spec.StorageClassName, Resources: *source.Spec.Resources.DeepCopy(), DataSource: &corev1.TypedLocalObjectReference{APIGroup: &group, Kind: "VolumeSnapshot", Name: snapshot.GetName()}}}
	if _, e = runner.Ensure(ctx, "PersistentVolumeClaim", clone); e != nil {
		return e
	}
	return nil
}
func (c *collector) waitClaim(ctx context.Context, name string) error {
	for {
		p, e := c.d.Client.CoreV1().PersistentVolumeClaims(c.w.Namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			return ErrProfile
		}
		if p.Status.Phase == corev1.ClaimBound && p.UID != "" {
			return nil
		}
		if !poll(ctx) {
			return ctx.Err()
		}
	}
}
func poll(ctx context.Context) bool {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func endpoint(raw string) (kube.WorkerEndpoint, error) {
	host, port, e := net.SplitHostPort(raw)
	n, ne := strconv.Atoi(port)
	if e != nil || ne != nil || n <= 0 || n > 65535 || net.ParseIP(host) == nil {
		return kube.WorkerEndpoint{}, ErrProfile
	}
	return kube.WorkerEndpoint{Address: host, Port: int32(n)}, nil
}
func (c *collector) prepare(ctx context.Context) error {
	w, e := c.resolved(ctx)
	if e != nil {
		return e
	}
	runner, e := c.d.runner(c.t, false)
	if e != nil {
		return e
	}
	if w.SnapshotClass != "" {
		if e = c.snapshot(ctx, runner); e != nil {
			return e
		}
	}
	if w.RestoreClaim != "" {
		p, e := kube.RestorePVC(kube.Identity{Namespace: w.Namespace, Name: w.RestoreClaim, Owner: c.t.ID}, c.d.Config.TargetStorageClass, c.d.Config.TargetStorageSize, "")
		if e != nil {
			return e
		}
		if _, e = runner.Ensure(ctx, "PersistentVolumeClaim", p); e != nil {
			return e
		}
	}
	job, cfg, e := c.build(w)
	if e != nil {
		return e
	}
	hash, _ := w.Invocation.Hash()
	g := c.grant(w, job)
	if g.CredentialRef != "" {
		spec := w.Invocation.Request.Database
		mode := "capture"
		if strings.HasPrefix(w.Invocation.Request.Operation, "restore-") {
			mode = "restore"
		}
		if strings.HasPrefix(w.Invocation.Request.Operation, "verify-") {
			mode = "verify"
		}
		if e = c.credentials().Ensure(ctx, c.t, g.CredentialRef, control.DatabaseGrant{Database: spec.Name, ServerUUID: spec.ServerUUID, Host: "%", Mode: mode}); e != nil {
			return e
		}
	}
	if _, e = runner.Ensure(ctx, "ConfigMap", cfg); e != nil {
		return e
	}
	if _, e = c.d.Identities.Ensure(ctx, c.t, w.Namespace, c.identity("-identity").Name, hash); e != nil {
		return e
	}
	u, e := url.Parse(c.d.Config.ControlURL)
	if e != nil {
		return e
	}
	relay, e := endpoint(u.Host)
	if e != nil {
		return e
	}
	var database *kube.WorkerEndpoint
	if w.Invocation.Request.Database != nil {
		ep, e := endpoint(w.Invocation.Request.Database.Address)
		if e != nil {
			return e
		}
		database = &ep
	}
	policy, e := kube.WorkerEgressPolicy(c.identity("-network"), relay, database, nil)
	if e != nil {
		return e
	}
	// Select the actual Job's immutable labels, not the policy object's name.
	policy.Spec.PodSelector.MatchLabels = job.Spec.Template.Labels
	if _, e = runner.Ensure(ctx, "NetworkPolicy", policy); e != nil {
		return e
	}
	// Scheduling may be needed to bind WaitForFirstConsumer volumes. The fixed
	// worker waits for a registered mTLS grant before receiving any key or SQL
	// credential. Record the Job first, then freeze the resolved volume binding.
	if _, e = runner.Ensure(ctx, "Job", job); e != nil {
		return e
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			if e = c.waitClaim(ctx, v.PersistentVolumeClaim.ClaimName); e != nil {
				return e
			}
		}
	}
	security, e := c.security(ctx, job)
	if e != nil {
		return e
	}
	g.Security = &security
	cleanup, e := c.d.runner(c.t, true)
	if e != nil {
		return e
	}
	live := control.LiveWorkers{Store: c.d.Store, Observer: kube.WorkerObserver{Client: c.d.Client}, Proof: c.d.Proof, CheckEvidence: c.d.EvidenceCheck}
	c.inner = &control.JobCollector{Store: c.d.Store, Task: c.t, Runner: runner, CleanupRunner: cleanup, Job: job, Grant: g, PartID: w.ID, StopProof: live.Stopped, RevokeCredential: func(ctx context.Context, ref string) error { return c.credentials().Revoke(ctx, c.t, ref) }}
	return c.inner.Prepare(ctx)
}
func (c *collector) Prepare(ctx context.Context) error {
	if c.w.SnapshotClass != "" {
		return c.d.fence(ctx, c.t, false)
	}
	return c.prepare(ctx)
}
func (c *collector) Capture(ctx context.Context) (flow.Part, error) {
	if c.inner == nil {
		if e := c.prepare(ctx); e != nil {
			return flow.Part{}, e
		}
	}
	return c.inner.Capture(ctx)
}
func (c *collector) security(ctx context.Context, job *batchv1.Job) (kube.WorkerSecurity, error) {
	result := kube.WorkerSecurity{NodeUIDs: map[string]string{}}
	nodes, e := c.d.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if e != nil {
		return result, ErrProfile
	}
	for _, n := range nodes.Items {
		if n.Labels[corev1.LabelOSStable] == "linux" && n.UID != "" && c.p.Nodes[n.Name] == string(n.UID) && (c.w.Node == "" || n.Name == c.w.Node) {
			result.NodeUIDs[n.Name] = string(n.UID)
		}
	}
	if len(result.NodeUIDs) == 0 {
		return result, ErrProfile
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			pvc, e := c.d.Client.CoreV1().PersistentVolumeClaims(job.Namespace).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if e != nil {
				return result, ErrProfile
			}
			if v.Name == "staging" || v.Name == "evidence" {
				expected := c.d.Config.Staging[job.Namespace]
				if v.Name == "evidence" || c.w.Invocation.Request.Operation == "verify-database" {
					expected = c.d.Config.Evidence
				}
				if pvc.Name != expected.Name || string(pvc.UID) != expected.UID {
					return result, ErrProfile
				}
			}
			b, e := c.d.claim(ctx, job.Namespace, Claim{pvc.Name, string(pvc.UID)})
			if e != nil {
				return result, e
			}
			b.Volume = v.Name
			if v.Name == "workspace" && (c.w.SnapshotClass != "" || c.w.RestoreClaim != "") {
				var uid string
				if c.d.Store.DB.QueryRowContext(ctx, "SELECT uid FROM system_backup_resources WHERE task_id=? AND kind='PersistentVolumeClaim' AND namespace_name=? AND resource_name=? AND lifecycle='created' AND dispatched=TRUE", c.t.ID, job.Namespace, pvc.Name).Scan(&uid) != nil || uid != string(pvc.UID) {
					return result, ErrProfile
				}
			}
			if v.Name == "workspace" && c.w.SnapshotClass == "" && c.w.RestoreClaim == "" {
				for _, f := range c.p.Instances {
					if fmt.Sprintf("instance-%d", f.SQL.ID) == c.w.PartID && !jsonEqual([]kube.MountIdentity{b}, f.Mounts) {
						return result, ErrProfile
					}
				}
			}
			result.Volumes = append(result.Volumes, b)
		case v.Secret != nil:
			s, e := c.d.Client.CoreV1().Secrets(job.Namespace).Get(ctx, v.Secret.SecretName, metav1.GetOptions{})
			if e != nil {
				return result, ErrProfile
			}
			result.Volumes = append(result.Volumes, kube.MountIdentity{Volume: v.Name, Kind: "Secret", Name: s.Name, UID: string(s.UID), SHA256: kube.ContentHash(s.Data)})
		case v.ConfigMap != nil:
			cm, e := c.d.Client.CoreV1().ConfigMaps(job.Namespace).Get(ctx, v.ConfigMap.Name, metav1.GetOptions{})
			if e != nil {
				return result, ErrProfile
			}
			result.Volumes = append(result.Volumes, kube.MountIdentity{Volume: v.Name, Kind: "ConfigMap", Name: cm.Name, UID: string(cm.UID), SHA256: kube.ContentHash([]any{cm.Data, cm.BinaryData})})
		}
	}
	return result, nil
}
func (c *collector) Stop(ctx context.Context) error {
	// Recovery reads the journal's actual request/grant. It never reconstructs
	// an expired ConfigMap or generates credentials, identities, snapshots or Jobs.
	var request []byte
	var uid, lifecycle string
	e := c.d.Store.DB.QueryRowContext(ctx, "SELECT request_json,uid,lifecycle FROM system_backup_resources WHERE task_id=? AND kind='Job' AND namespace_name=? AND resource_name=?", c.t.ID, c.w.Namespace, c.identity("").Name).Scan(&request, &uid, &lifecycle)
	if errors.Is(e, sql.ErrNoRows) {
		return c.revokeIfPresent(ctx)
	}
	if e != nil {
		return ErrProfile
	}
	var job batchv1.Job
	if json.Unmarshal(request, &job) != nil {
		return ErrProfile
	}
	delete(job.Annotations, kube.RequestHashAnnotation)
	var grant control.WorkerGrant
	var raw []byte
	e = c.d.Store.DB.QueryRowContext(ctx, "SELECT grant_json FROM system_backup_workers WHERE task_id=? AND JSON_UNQUOTE(JSON_EXTRACT(grant_json,'$.job_name'))=?", c.t.ID, job.Name).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		grant = c.grant(c.w, &job)
		grant.JobUID = uid
	} else if e != nil || json.Unmarshal(raw, &grant) != nil {
		return ErrProfile
	}
	cleanup, e := c.d.runner(c.t, true)
	if e != nil {
		return e
	}
	live := control.LiveWorkers{Store: c.d.Store, Proof: c.d.Proof}
	inner := control.JobCollector{Store: c.d.Store, Task: c.t, Job: &job, Grant: grant, PartID: c.w.ID, CleanupRunner: cleanup, StopProof: func(ctx context.Context, g control.WorkerGrant, r kube.ResourceRecord) error {
		return c.stopProof(ctx, live, g, r)
	}, RevokeCredential: func(ctx context.Context, ref string) error { return c.credentials().Revoke(ctx, c.t, ref) }}
	return inner.Stop(ctx)
}
func (c *collector) revokeIfPresent(ctx context.Context) error {
	if c.w.Invocation.Request.Database == nil {
		return nil
	}
	ref := c.w.ID + "-sql"
	raw, e := c.d.Vault.Get(ctx, c.t, ref, "database-credential")
	clear(raw)
	if errors.Is(e, control.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return c.credentials().Revoke(ctx, c.t, ref)
}
func (c *collector) stopProof(ctx context.Context, live control.LiveWorkers, g control.WorkerGrant, r kube.ResourceRecord) error {
	live.Observer = kube.WorkerObserver{Client: c.d.Client}
	return live.StoppedOrNeverGranted(ctx, c.t, g, r)
}
