package profile

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type sqlInstance = domain.SourceInstance
type frozenInstance struct {
	Input                                       Instance
	SQL                                         sqlInstance
	Source                                      control.SourceBinding
	Pod                                         *corev1.Pod
	Deployment                                  *appsv1.Deployment
	Volume                                      corev1.Volume
	SubPath, Node                               string
	Mounts                                      []kube.MountIdentity
	SnapshotUID, SnapshotDriver, SnapshotVolume string
}
type work struct {
	ID, PartID, Namespace                                     string
	Invocation                                                worker.Invocation
	Key                                                       artifact.WrappedKey
	Source                                                    *corev1.Volume
	LocalAssets                                               bool
	SubPath, Node, SnapshotClass, SnapshotClaim, RestoreClaim string
}
type plan struct {
	Version, Task, Revision                           string
	Deadline                                          int64
	Identity                                          flow.Identity
	Users                                             int
	Instances                                         []frozenInstance
	Work                                              []work
	Bundle                                            *artifact.Bundle
	Nodes                                             map[string]string
	TargetNamespaceUID, QuarantineUID, QuarantineHash string
	Applications                                      []control.AppProcess
	TeamVolumes                                       []SharedVolumeReceipt `json:",omitempty"`
	OwnerPlan                                         json.RawMessage       `json:",omitempty"`
}

func (d *Driver) inventory(ctx context.Context) (int, []sqlInstance, error) {
	tx, e := d.Source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return 0, nil, ErrProfile
	}
	defer tx.Rollback()
	var users int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&users) != nil || users < 1 {
		return 0, nil, ErrProfile
	}
	out, e := domain.ReadSourceInstances(ctx, tx)
	if e != nil {
		return 0, nil, ErrProfile
	}
	return users, out, nil
}
func (d *Driver) claim(ctx context.Context, ns string, c Claim) (kube.MountIdentity, error) {
	pvc, e := d.Client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, c.Name, metav1.GetOptions{})
	if e != nil || string(pvc.UID) != c.UID || c.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
		return kube.MountIdentity{}, ErrProfile
	}
	pv, e := d.Client.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Name != c.Name || pv.Spec.ClaimRef.Namespace != ns {
		return kube.MountIdentity{}, ErrProfile
	}
	return kube.MountIdentity{Kind: "PersistentVolumeClaim", Name: c.Name, UID: c.UID, PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}, nil
}
func (d *Driver) mount(ctx context.Context, ns string, v corev1.Volume) ([]kube.MountIdentity, error) {
	if v.PersistentVolumeClaim != nil {
		p, e := d.Client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
		if e != nil {
			return nil, ErrProfile
		}
		b, e := d.claim(ctx, ns, Claim{p.Name, string(p.UID)})
		b.Volume = "workspace"
		return []kube.MountIdentity{b}, e
	}
	if v.HostPath == nil && v.NFS == nil {
		return nil, ErrProfile
	}
	return nil, nil
}
func (d *Driver) discoverInstance(ctx context.Context, task control.Task, input Instance, i sqlInstance) (frozenInstance, error) {
	f := frozenInstance{Input: input, SQL: i, Source: control.SourceBinding{Database: d.Config.Source.Name, ServerUUID: d.Config.Source.ServerUUID, InstanceID: i.ID, UserID: i.UserID, Generation: i.Generation, Mode: i.Mode, PodName: i.Pod, Namespace: i.Namespace, Workspace: input.Workspace}}
	if _, e := scope.PlanRuntime(scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS}); e != nil {
		return f, ErrProfile
	}
	if i.Status != "running" && i.Status != "stopped" {
		return f, ErrProfile
	}
	if i.Namespace != "" && i.Namespace != input.Namespace {
		return f, ErrProfile
	}
	if input.WorkloadKind == "Stopped" {
		if i.Status != "stopped" || input.StoppedVolume == nil {
			return f, ErrProfile
		}
		f.Volume = *input.StoppedVolume.DeepCopy()
		f.SubPath = input.SubPath
		f.Node = input.Node
	} else {
		if i.Status != "running" || i.Generation <= 0 {
			return f, ErrProfile
		}
		pod, e := d.Client.CoreV1().Pods(input.Namespace).Get(ctx, input.PodName, metav1.GetOptions{})
		if e != nil || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning {
			return f, ErrProfile
		}
		f.Pod = pod
		if input.PodName != i.Pod || input.Namespace != i.Namespace {
			return f, ErrProfile
		}
		f.Node = pod.Spec.NodeName
		if input.WorkloadKind == "Deployment" {
			deployment, e := d.Client.AppsV1().Deployments(input.Namespace).Get(ctx, input.WorkloadName, metav1.GetOptions{})
			if e != nil || deployment.UID == "" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
				return f, ErrProfile
			}
			f.Deployment = deployment
			if !d.deploymentOwns(ctx, f, pod) {
				return f, ErrProfile
			}
		} else if input.WorkloadKind == "Pod" && len(pod.OwnerReferences) > 0 {
			return f, ErrProfile
		}
		found := false
		for _, v := range pod.Spec.Volumes {
			if v.Name != input.VolumeName && (v.PersistentVolumeClaim != nil || v.NFS != nil || v.HostPath != nil || v.CSI != nil) {
				return f, ErrProfile
			}
			if v.Name == input.VolumeName {
				f.Volume = v
				found = true
			}
		}
		if !found {
			return f, ErrProfile
		}
		mountFound := false
		for _, c := range pod.Spec.Containers {
			for _, m := range c.VolumeMounts {
				if m.Name == input.VolumeName {
					relative, e := kube.VolumeRelativePath(m, input.Workspace)
					if e != nil {
						continue
					}
					if mountFound && relative != f.SubPath {
						return f, ErrProfile
					}
					f.SubPath = relative
					mountFound = true
				}
			}
		}
		if !mountFound {
			return f, ErrProfile
		}
		f.Source.PodUID = string(pod.UID)
		if input.WorkloadKind == "Gateway" {
			if i.Mode != "lite" || d.Agent == nil || d.AgentProbe == nil || d.AgentProbe(ctx, input.Endpoint, string(pod.UID)) != nil {
				return f, ErrProfile
			}
			var bindingGeneration int
			var state string
			e = d.Source.QueryRowContext(ctx, "SELECT runtime_pod_id,gateway_id,gateway_port,workspace_path,generation,state FROM instance_runtime_bindings WHERE instance_id=?", i.ID).Scan(&f.Source.RuntimePodID, &f.Source.GatewayID, &f.Source.Port, &f.Source.Workspace, &bindingGeneration, &state)
			if e != nil || bindingGeneration != i.Generation || state != "running" || f.Source.Workspace != input.Workspace {
				return f, ErrProfile
			}
			var uid string
			if d.Source.QueryRowContext(ctx, "SELECT pod_uid,used_slots FROM runtime_pods WHERE id=?", f.Source.RuntimePodID).Scan(&uid, &f.Source.UsedSlots) != nil || uid != string(pod.UID) {
				return f, ErrProfile
			}
			r := input.Restart
			if r.InstanceID != i.ID || r.UserID != i.UserID || r.WorkspacePath != input.Workspace || r.GatewayPort != f.Source.Port || r.UID <= 0 || r.GID <= 0 || r.AgentType != i.Type || r.UpgradeID != "" {
				return f, ErrProfile
			}
			f.Input.Restart.Generation = i.Generation + 1
		} else if i.Mode != "pro" {
			return f, ErrProfile
		}
	}
	var e error
	if input.SnapshotClass != "" && f.Volume.PersistentVolumeClaim == nil {
		return f, ErrProfile
	}
	if f.Volume.HostPath != nil && f.Node == "" {
		return f, ErrProfile
	}
	f.Mounts, e = d.mount(ctx, input.Namespace, f.Volume)
	if e != nil {
		return f, e
	}
	if f.Volume.NFS != nil {
		if d.Config.ExclusiveNFSProofURL == "" || d.ExternalNFSProof == nil || d.ExternalNFSProof(ctx, d.Config.ExclusiveNFSProofURL, kube.ContentHash(f.Volume)) != nil {
			return f, ErrProfile
		}
	}
	if f.Volume.PersistentVolumeClaim != nil {
		pv, e := d.Client.CoreV1().PersistentVolumes().Get(ctx, f.Mounts[0].PVName, metav1.GetOptions{})
		if e != nil {
			return f, ErrProfile
		}
		if pv.Spec.NFS != nil && (d.ExternalNFSProof == nil || d.ExternalNFSProof(ctx, d.Config.ExclusiveNFSProofURL, kube.ContentHash(pv.Spec.NFS)) != nil) {
			return f, ErrProfile
		}
		if input.SnapshotClass != "" && pv.Spec.CSI == nil {
			return f, ErrProfile
		}
		if input.SnapshotClass != "" {
			f.SnapshotDriver = pv.Spec.CSI.Driver
			f.SnapshotVolume = pv.Spec.CSI.VolumeHandle
			f.SnapshotUID, e = d.snapshotClass(ctx, input.SnapshotClass, f.SnapshotDriver)
			if e != nil {
				return f, e
			}
		}
	}
	return f, nil
}
func (d *Driver) Discover(ctx context.Context, t control.Task) (json.RawMessage, error) {
	p := plan{Version: "kubernetes-linux.v1", Task: t.ID, Revision: t.ProfileRevision, Deadline: t.Deadline, Identity: flow.Identity{Task: t.ID, Attempt: t.ID + "-capture", Generation: 1, Phase: "capture"}}
	var e error
	p.Nodes, e = d.nodes(ctx)
	if e != nil {
		return nil, e
	}
	if t.Request.Kind != "backup" {
		return d.discoverTarget(ctx, t, p)
	}
	p.Applications, e = d.applicationCoverage(ctx)
	if e != nil {
		return nil, e
	}
	users, instances, e := d.inventory(ctx)
	if e != nil || len(instances) != len(d.Config.Instances) {
		return nil, ErrProfile
	}
	p.Users = users
	inputs := map[int]Instance{}
	for _, i := range d.Config.Instances {
		inputs[i.ID] = i
	}
	for _, i := range instances {
		input, ok := inputs[i.ID]
		if !ok {
			return nil, ErrProfile
		}
		f, e := d.discoverInstance(ctx, t, input, i)
		if e != nil {
			return nil, e
		}
		policy, ok := d.Config.RuntimePolicies[input.Policy]
		if d.Config.Assets.CheckPod(f.Pod) != nil {
			return nil, ErrProfile
		}
		if !ok || policy.Validate() != nil {
			return nil, ErrProfile
		}
		actualRuntime, e := scope.PlanRuntime(scope.Runtime{Type: i.Type, Mode: i.Mode, Backend: i.Backend, Variant: i.Variant, OS: i.OS})
		policyRuntime, pe := scope.PlanRuntime(policy.Runtime)
		if e != nil || pe != nil || !jsonEqual(actualRuntime, policyRuntime) {
			return nil, ErrProfile
		}
		if f.Pod != nil {
			found := false
			for _, c := range f.Pod.Spec.Containers {
				if c.Image == policy.Image {
					found = true
				}
			}
			if !found {
				return nil, ErrProfile
			}
		}
		if f.Node != "" && p.Nodes[f.Node] == "" {
			return nil, ErrProfile
		}
		p.Instances = append(p.Instances, f)
	}
	if e = d.checkMountUsers(ctx, p); e != nil {
		return nil, e
	}
	var identitySnapshot domain.Snapshot
	defer func() { clearSnapshot(identitySnapshot) }()
	if d.workBuddyUID() {
		identitySnapshot, e = domain.CaptureSource(ctx, d.Source, domain.Limits{MaxRows: d.Config.Source.MaxRows, MaxBytes: d.Config.Source.MaxMemoryBytes}, d.Config.Source.Name, d.Config.Source.ServerUUID)
		if e != nil {
			return nil, e
		}
	}
	for _, f := range p.Instances {
		id := fmt.Sprintf("instance-%d", f.SQL.ID)
		w, e := d.newWork(ctx, t, p, id, "capture-workspace", f.Input.Namespace)
		if e != nil {
			return nil, e
		}
		v := f.Volume
		w.Source = &v
		policy := d.Config.RuntimePolicies[f.Input.Policy]
		w.Invocation.Request.RuntimePolicy = &policy
		if d.workBuddyUID() {
			if e = bindWorkBuddyIdentity(identitySnapshot, &w); e != nil {
				return nil, e
			}
		}
		w.SubPath = f.SubPath
		w.Node = f.Node
		w.SnapshotClass = f.Input.SnapshotClass
		if w.SnapshotClass != "" {
			w.SnapshotClaim = v.PersistentVolumeClaim.ClaimName
		}
		p.Work = append(p.Work, w)
	}
	w, e := d.newWork(ctx, t, p, "database", "capture-database", d.Config.Namespace)
	if e != nil {
		return nil, e
	}
	source := d.Config.Source
	source.Configs = nil
	source.Placements = nil
	w.Invocation.Request.Database = &source
	w.Invocation.Request.MaxFiles = 0
	w.Invocation.Request.MaxFileBytes = 0
	w.Invocation.Request.MaxArchiveBytes = 32 << 20
	w.Invocation.Request.MaxCompressedBytes = 32 << 20
	w.Invocation.WorkspacePath = ""
	p.Work = append(p.Work, w)
	assetWork, e := d.newWork(ctx, t, p, "assets", "capture-assets", d.Config.Namespace)
	if e != nil || d.Config.Assets.Validate() != nil {
		return nil, ErrProfile
	}
	assetWork.LocalAssets = true
	assetWork.Invocation.Request.MaxCompressedBytes = 48 << 20
	p.Work = append(p.Work, assetWork)
	for _, w := range p.Work {
		if w.LocalAssets {
			continue
		}
		if !worker.ValidateRecordedInvocation(w.Invocation) {
			return nil, ErrProfile
		}
	}
	if d.Config.SixDomainModule != nil {
		if d.SixDomain == nil {
			return nil, ErrProfile
		}
		p.OwnerPlan, e = d.SixDomain.Discover(ctx, t)
		if e != nil {
			return nil, e
		}
		if _, e = d.bindSix(t, p); e != nil {
			return nil, e
		}
	}
	return json.Marshal(p)
}
func (d *Driver) newWork(ctx context.Context, t control.Task, p plan, id, operation, namespace string) (work, error) {
	binding := staging.Binding{BackupID: t.ID, Attempt: p.Identity.Attempt, Path: id, CaptureContextHash: kube.ContentHash(p.Instances), EnvelopeID: t.ID + "-" + id}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return work{}, ErrProfile
	}
	defer clear(key)
	wrapped, e := d.Keys.Wrap(ctx, binding, d.Config.KeyVersion, key)
	if e != nil {
		return work{}, e
	}
	return work{ID: "capture-" + id, PartID: id, Namespace: namespace, Key: wrapped, Invocation: worker.Invocation{WorkspacePath: "/workspace", StagingPath: "/staging", Request: worker.Request{Version: worker.Version, Operation: operation, Deadline: time.UnixMilli(t.Deadline), Binding: binding, ArtifactName: id + ".enc", MaxFiles: d.Config.MaxFiles, MaxFileBytes: d.Config.MaxFileBytes, MaxArchiveBytes: d.Config.MaxArchiveBytes, MaxCompressedBytes: d.Config.MaxCompressedBytes}}}, nil
}
func (d *Driver) checkMountUsers(ctx context.Context, p plan) error {
	pods, e := d.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if e != nil {
		return ErrProfile
	}
	allowed := map[string]bool{}
	for _, app := range p.Applications {
		allowed[app.Pod.UID] = true
	}
	for _, f := range p.Instances {
		if f.Pod != nil {
			allowed[string(f.Pod.UID)] = true
		}
	}
	for _, pod := range pods.Items {
		if allowed[string(pod.UID)] || (pod.Labels[kube.OwnerLabel] == p.Task && d.ownedWorker(ctx, p.Task, &pod)) {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			for _, f := range p.Instances {
				a, e := d.backing(ctx, pod.Namespace, v)
				if e != nil {
					return e
				}
				b, e := d.backing(ctx, f.Input.Namespace, f.Volume)
				if e != nil {
					return e
				}
				if sameBacking(pod.Namespace, v, f.Input.Namespace, f.Volume) || sameBacking(pod.Namespace, a, f.Input.Namespace, b) || (a.Name != "" && a.Name == b.Name) {
					return ErrProfile
				}
			}
		}
	}
	// Autoscalers must not race a zero-replica source. A profile with HPA requires
	// its own explicit pause adapter; never silently patch an unrelated autoscaler.
	seen := map[string]bool{}
	for _, f := range p.Instances {
		if seen[f.Input.Namespace] {
			continue
		}
		seen[f.Input.Namespace] = true
		hpas, e := d.Client.AutoscalingV2().HorizontalPodAutoscalers(f.Input.Namespace).List(ctx, metav1.ListOptions{})
		if e != nil {
			return ErrProfile
		}
		for _, h := range hpas.Items {
			for _, s := range p.Instances {
				if s.Deployment != nil && s.Input.Namespace == f.Input.Namespace && h.Spec.ScaleTargetRef.Name == s.Deployment.Name {
					return ErrProfile
				}
			}
		}
	}
	return nil
}
func sameBacking(aNS string, a corev1.Volume, bNS string, b corev1.Volume) bool {
	switch {
	case a.PersistentVolumeClaim != nil && b.PersistentVolumeClaim != nil:
		return aNS == bNS && a.PersistentVolumeClaim.ClaimName == b.PersistentVolumeClaim.ClaimName
	case a.NFS != nil && b.NFS != nil:
		return a.NFS.Server == b.NFS.Server && overlaps(a.NFS.Path, b.NFS.Path)
	case a.HostPath != nil && b.HostPath != nil:
		return overlaps(a.HostPath.Path, b.HostPath.Path)
	}
	return false
}
func (d *Driver) load(ctx context.Context, t control.Task) (plan, error) {
	var p plan
	raw, e := d.Vault.Get(ctx, t, "execution-plan", "plan")
	if e != nil {
		return p, e
	}
	defer clear(raw)
	if json.Unmarshal(raw, &p) != nil || p.Task != t.ID || p.Revision != t.ProfileRevision || p.Deadline != t.Deadline || p.Version != "kubernetes-linux.v1" {
		return p, ErrProfile
	}
	return p, nil
}
func sortWorks(w []work) { sort.Slice(w, func(i, j int) bool { return w[i].ID < w[j].ID }) }
