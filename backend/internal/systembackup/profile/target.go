package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Driver) artifact(ctx context.Context, t control.Task) (artifact.Bundle, error) {
	directory := d.Publisher.Directory
	directory.Authorize = func(ctx context.Context, id, action string) error {
		if id != t.Request.Artifact || action != "read" {
			return ErrProfile
		}
		return d.fence(ctx, t, false)
	}
	return directory.Read(ctx, t.Request.Artifact)
}
func (d *Driver) discoverTarget(ctx context.Context, t control.Task, p plan) (json.RawMessage, error) {
	bundle, e := d.artifact(ctx, t)
	if e != nil || bundle.PolicyVersion != d.Config.PolicyVersion || !jsonEqual(bundle.Contract, d.contract()) {
		return nil, ErrProfile
	}
	p.Bundle = &bundle
	var identitySnapshot domain.Snapshot
	defer func() { clearSnapshot(identitySnapshot) }()
	if d.workBuddyUID() {
		identitySnapshot, e = d.databaseSnapshot(ctx, d.Publisher.Directory.Root, bundle)
		if e != nil {
			return nil, e
		}
	}
	ns, e := d.Client.CoreV1().Namespaces().Get(ctx, d.Config.TargetNamespace, metav1.GetOptions{})
	if e != nil || ns.UID == "" {
		return nil, ErrProfile
	}
	p.TargetNamespaceUID = string(ns.UID)
	deny, e := d.Client.NetworkingV1().NetworkPolicies(ns.Name).Get(ctx, "backup-quarantine", metav1.GetOptions{})
	if e != nil || deny.UID == "" {
		return nil, ErrProfile
	}
	p.QuarantineUID = string(deny.UID)
	p.QuarantineHash = kube.ContentHash(deny.Spec)
	p.Users = bundle.Users
	if len(d.Config.Instances) != bundle.Instances {
		return nil, ErrProfile
	}
	configured := map[string]Instance{}
	if d.Config.SharedWorkspaceModule != nil {
		if d.SharedWorkspace == nil {
			return nil, ErrProfile
		}
		p.TeamVolumes, e = d.SharedWorkspace.Receipts(ctx, t)
		if e != nil {
			return nil, e
		}
	}
	teamPlacements, e := d.teamPlacements(ctx, t, p.TeamVolumes)
	if e != nil {
		return nil, e
	}
	placements := map[string]domain.Placement{}
	for _, i := range d.Config.Instances {
		part := fmt.Sprintf("instance-%d", i.ID)
		configured[part] = i
		claim := resourceName(t, part)
		placements[fmt.Sprint(i.ID)] = domain.Placement{Workspace: "/workspace", MountPath: "/workspace", PVC: claim, Namespace: d.Config.TargetNamespace, StorageClass: d.Config.TargetStorageClass}
	}
	for _, part := range bundle.Parts {
		w := work{ID: "restore-" + part.ID, PartID: part.ID, Namespace: d.Config.TargetNamespace, Key: part.Key, Invocation: worker.Invocation{StagingPath: "/staging", Request: worker.Request{Version: worker.Version, Operation: "restore-workspace", Binding: part.Binding, Receipt: part.Receipt, Deadline: time.UnixMilli(t.Deadline), PolicyVersion: d.Config.PolicyVersion, MaxFiles: d.Config.MaxFiles, MaxFileBytes: d.Config.MaxFileBytes, MaxArchiveBytes: d.Config.MaxArchiveBytes, MaxCompressedBytes: d.Config.MaxCompressedBytes}}}
		if part.ID == "assets" {
			w.Invocation.Request.Operation = "restore-assets"
			w.Invocation.Request.MaxArchiveBytes = 48 << 20
			w.Invocation.Request.MaxCompressedBytes = 48 << 20
			w.Invocation.WorkspacePath = "/workspace"
			w.RestoreClaim = resourceName(t, "assets")
			w.Source = &corev1.Volume{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: w.RestoreClaim}}}
			verify := w
			verify.ID = "verify-assets"
			verify.Invocation.Request.Operation = "verify-assets"
			p.Work = append(p.Work, w, verify)
			continue
		}
		if part.ID == "database" {
			spec := d.Config.Target
			spec.Configs = d.Config.Configs
			spec.WorkBuddy = d.Config.WorkBuddy
			spec.Dependencies = d.Config.Dependencies
			spec.Placements = placements
			spec.TeamPlacements = teamPlacements
			spec.EvidenceName = "database-evidence.enc"
			spec.EvidenceBinding = part.Binding
			spec.EvidenceBinding.Path = "database/evidence/" + t.ID
			w.Invocation.Request.Operation = "restore-database"
			w.Invocation.Request.Database = &spec
			w.Invocation.Request.MaxFiles = 0
			w.Invocation.Request.MaxFileBytes = 0
			w.Invocation.Request.MaxArchiveBytes = 32 << 20
			w.Invocation.Request.MaxCompressedBytes = 32 << 20
			w.Invocation.EvidencePath = "/evidence"
			verify := work{ID: "verify-database", PartID: "database", Namespace: d.Config.TargetNamespace, Invocation: worker.Invocation{StagingPath: "/staging", Request: w.Invocation.Request}}
			target := d.Config.Target
			target.Configs = nil
			target.Placements = nil
			target.EvidenceName = ""
			verify.Invocation.Request.Database = &target
			verify.Invocation.Request.Operation = "verify-database"
			verify.Invocation.Request.Binding = spec.EvidenceBinding
			verify.Invocation.Request.Receipt = staging.Receipt{}
			key, e := d.Keys.Unwrap(ctx, part.Binding, part.Key)
			if e != nil {
				return nil, e
			}
			verify.Key, e = d.Keys.Wrap(ctx, verify.Invocation.Request.Binding, d.Config.KeyVersion, key)
			clear(key)
			if e != nil {
				return nil, e
			}
			p.Work = append(p.Work, verify)
		} else {
			input, ok := configured[part.ID]
			if !ok {
				return nil, ErrProfile
			}
			w.Invocation.WorkspacePath = "/workspace"
			policy, ok := d.Config.RuntimePolicies[input.Policy]
			if !ok || policy.Validate() != nil {
				return nil, ErrProfile
			}
			w.Invocation.Request.Files = policy.Files
			w.Invocation.Request.RuntimePolicy = &policy
			if d.workBuddyUID() {
				if e = bindWorkBuddyIdentity(identitySnapshot, &w); e != nil {
					return nil, e
				}
			}
			w.RestoreClaim = placements[fmt.Sprint(input.ID)].PVC
			w.Source = &corev1.Volume{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: w.RestoreClaim}}}
			w.SubPath = ""
		}
		p.Work = append(p.Work, w)
	}
	sortWorks(p.Work)
	for _, w := range p.Work {
		if w.LocalAssets {
			continue
		}
		if w.Invocation.Request.Operation != "verify-database" && !worker.ValidateRecordedInvocation(w.Invocation) {
			return nil, ErrProfile
		}
	}
	if e = d.checkTarget(ctx, t, p); e != nil {
		return nil, e
	}
	if e = d.blankTarget(ctx, t, p); e != nil {
		return nil, e
	}
	return json.Marshal(p)
}
func (d *Driver) blankTarget(ctx context.Context, t control.Task, p plan) error {
	if p.Bundle == nil {
		return ErrProfile
	}
	bundle, e := d.artifact(ctx, t)
	if e != nil || !jsonEqual(bundle, *p.Bundle) {
		return ErrProfile
	}
	source, e := d.databaseSnapshot(ctx, d.Publisher.Directory.Root, bundle)
	if e != nil {
		return e
	}
	defer clearSnapshot(source)
	spec, e := preflightSpec(p, source)
	if e != nil {
		return e
	}
	return domain.PreflightRestoreDrill(ctx, d.TargetAdmin, domain.DrillTarget{Database: d.Config.Target.Name, ServerUUID: d.Config.Target.ServerUUID, CheckIsolation: func(ctx context.Context) error { return d.checkTarget(ctx, t, p) }}, source, domain.Policy{WorkBuddy: spec.WorkBuddy, Placements: spec.Placements, Configs: spec.Configs, Dependencies: spec.Dependencies, TeamPlacements: spec.TeamPlacements})
}

func preflightSpec(p plan, s domain.Snapshot) (*worker.DatabaseSpec, error) {
	var spec *worker.DatabaseSpec
	for _, w := range p.Work {
		if w.Invocation.Request.Operation == "restore-database" {
			if spec != nil || w.Invocation.Request.Database == nil {
				return nil, ErrProfile
			}
			spec = w.Invocation.Request.Database
		}
	}
	if spec == nil || spec.MaxRows <= 0 || spec.MaxRows > 100_000 || spec.MaxMemoryBytes <= 0 || spec.MaxMemoryBytes > 32<<20 {
		return nil, ErrProfile
	}
	var rows, size int64
	for _, t := range s.Tables {
		rows += int64(len(t.Rows))
		for _, r := range t.Rows {
			for name, c := range r {
				size += int64(len(name) + len(c.Bytes) + 128)
			}
		}
	}
	if rows > spec.MaxRows || size > spec.MaxMemoryBytes {
		return nil, ErrProfile
	}
	return spec, nil
}
func (d *Driver) checkTarget(ctx context.Context, t control.Task, p plan) error {
	placements, e := d.teamPlacements(ctx, t, p.TeamVolumes)
	if e != nil {
		return e
	}
	for _, w := range p.Work {
		if w.Invocation.Request.Operation == "restore-database" && (w.Invocation.Request.Database == nil || !jsonEqual(w.Invocation.Request.Database.TeamPlacements, placements)) {
			return ErrProfile
		}
	}
	if !strings.HasPrefix(d.Config.TargetNamespace, "cm-drill-") || !strings.HasPrefix(d.Config.Target.Name, "cm_drill_") || d.Config.Target.Name == d.Config.Source.Name && d.Config.Target.ServerUUID == d.Config.Source.ServerUUID {
		return ErrProfile
	}
	if e := d.fence(ctx, t, true); e != nil {
		return e
	}
	ns, e := d.Client.CoreV1().Namespaces().Get(ctx, d.Config.TargetNamespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != p.TargetNamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["backup.clawmanager.io/quarantine"] != "true" {
		return ErrProfile
	}
	pods, e := d.Client.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil {
		return ErrProfile
	}
	for _, pod := range pods.Items {
		if !d.ownedWorker(ctx, t.ID, &pod) {
			return ErrProfile
		}
	}
	jobs, e := d.Client.BatchV1().Jobs(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil {
		return ErrProfile
	}
	for _, job := range jobs.Items {
		var uid string
		if job.Labels[kube.OwnerLabel] != t.ID || d.Store.DB.QueryRowContext(ctx, "SELECT uid FROM system_backup_resources WHERE task_id=? AND kind='Job' AND namespace_name=? AND resource_name=? AND lifecycle='created' AND dispatched=TRUE", t.ID, ns.Name, job.Name).Scan(&uid) != nil || uid != string(job.UID) {
			return ErrProfile
		}
	}
	replicas, e := d.Client.AppsV1().ReplicaSets(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil || len(replicas.Items) != 0 {
		return ErrProfile
	}
	deployments, e := d.Client.AppsV1().Deployments(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil || len(deployments.Items) != 0 {
		return ErrProfile
	}
	sets, e := d.Client.AppsV1().StatefulSets(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil || len(sets.Items) != 0 {
		return ErrProfile
	}
	daemons, e := d.Client.AppsV1().DaemonSets(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil || len(daemons.Items) != 0 {
		return ErrProfile
	}
	crons, e := d.Client.BatchV1().CronJobs(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil || len(crons.Items) != 0 {
		return ErrProfile
	}
	policies, e := d.Client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
	if e != nil {
		return ErrProfile
	}
	deny := false
	for _, policy := range policies.Items {
		if policy.DeletionTimestamp != nil {
			return ErrProfile
		}
		if policy.Name == "backup-quarantine" {
			if string(policy.UID) != p.QuarantineUID || kube.ContentHash(policy.Spec) != p.QuarantineHash || len(policy.Spec.PolicyTypes) != 2 || policy.Spec.PolicyTypes[0] == policy.Spec.PolicyTypes[1] {
				return ErrProfile
			}
			if len(policy.Spec.PodSelector.MatchLabels) != 0 || len(policy.Spec.PodSelector.MatchExpressions) != 0 || len(policy.Spec.Ingress) != 0 || len(policy.Spec.Egress) != 0 || len(policy.Spec.PolicyTypes) != 2 {
				return ErrProfile
			}
			deny = true
			continue
		}
		var raw []byte
		var uid string
		if d.Store.DB.QueryRowContext(ctx, "SELECT request_json,uid FROM system_backup_resources WHERE task_id=? AND kind='NetworkPolicy' AND namespace_name=? AND resource_name=? AND lifecycle='created'", t.ID, ns.Name, policy.Name).Scan(&raw, &uid) != nil || uid != string(policy.UID) {
			return ErrProfile
		}
		var frozen struct{ Spec any }
		if json.Unmarshal(raw, &frozen) != nil || !jsonEqual(frozen.Spec, policy.Spec) {
			return ErrProfile
		}
	}
	if !deny {
		return ErrProfile
	}
	var database, uuid string
	if d.TargetAdmin.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&database, &uuid) != nil || database != d.Config.Target.Name || uuid != d.Config.Target.ServerUUID {
		return ErrProfile
	}
	var active int
	if d.TargetAdmin.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances WHERE status <> 'stopped'").Scan(&active) != nil || active != 0 {
		return ErrProfile
	}
	return nil
}
func (d *Driver) ownedWorker(ctx context.Context, task string, p *corev1.Pod) bool {
	owner := metav1.GetControllerOf(p)
	if owner == nil || owner.Kind != "Job" || owner.APIVersion != "batch/v1" || p.Labels[kube.OwnerLabel] != task {
		return false
	}
	var uid string
	return d.Store.DB.QueryRowContext(ctx, "SELECT uid FROM system_backup_resources WHERE task_id=? AND kind='Job' AND namespace_name=? AND resource_name=? AND lifecycle='created' AND dispatched=TRUE", task, p.Namespace, owner.Name).Scan(&uid) == nil && uid == string(owner.UID)
}
func (d *Driver) prepareDirectories(t control.Task) error {
	for _, root := range []*os.Root{d.Staging, d.Evidence} {
		if e := root.Mkdir(t.ID, 0700); e != nil && !os.IsExist(e) {
			return ErrProfile
		}
		before, e := root.Lstat(t.ID)
		if e != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return ErrProfile
		}
		f, e := root.Open(t.ID)
		if e != nil {
			return ErrProfile
		}
		info, e := f.Stat()
		f.Close()
		if e != nil || !info.IsDir() || !os.SameFile(before, info) {
			return ErrProfile
		}
	}
	return nil
}
func (d *Driver) stageInput(ctx context.Context, t control.Task, p plan) error {
	if p.Bundle == nil {
		return ErrProfile
	}
	bundle, e := d.artifact(ctx, t)
	if e != nil || !jsonEqual(bundle, *p.Bundle) {
		return ErrProfile
	}
	root, e := d.Staging.OpenRoot(t.ID)
	if e != nil {
		return ErrProfile
	}
	defer root.Close()
	for _, part := range bundle.Parts {
		// O_EXCL and full hash verification reconcile a prior interrupted copy.
		if existing, e := staging.OpenFile(ctx, root, part.Receipt); e == nil {
			existing.Close()
			continue
		}
		src, e := d.Publisher.Directory.Root.Open(part.Receipt.Name)
		if e != nil {
			return ErrProfile
		}
		dst, e := root.OpenFile(part.Receipt.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			src.Close()
			return ErrProfile
		}
		_, e = io.Copy(dst, io.LimitReader(src, part.Receipt.Size+1))
		src.Close()
		syncErr := dst.Sync()
		closeErr := dst.Close()
		if e != nil || syncErr != nil || closeErr != nil {
			return ErrProfile
		}
		f, e := staging.OpenFile(ctx, root, part.Receipt)
		if e != nil {
			return e
		}
		f.Close()
	}
	return nil
}
