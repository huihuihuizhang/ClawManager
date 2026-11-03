package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const currentStoppedProMaterialVersion = "current-stopped-pro-source-material.v1"

// Original source-owner configuration, read through the existing Installer
// configuration pin. It declares the COMPLETE current persistent layout, not
// historical Pod fields, observed identities, a stop witness or a held gate.
type CurrentStoppedProLayout struct {
	InstanceID     int
	ControllerName string
	Mounts         []CurrentStoppedProMountLayout
}
type CurrentStoppedProMountLayout struct {
	MountID, Claim, MountPath, DataPath, SubPath string
}
type currentStoppedProSQLStorage struct {
	Claim, MountPath string
}
type CurrentStoppedProMount struct {
	Layout                  CurrentStoppedProMountLayout
	Identity                kube.MountIdentity
	Node, NodeUID, HostPath string
}

// DATA in the signed discovery scope. Every consumer repeats actual reads;
// possessing this struct cannot construct a P7 opaque proof or D's held gate.
type CurrentStoppedProSourceMaterial struct {
	Version  string
	Source   b.InstanceIdentity
	Layout   CurrentStoppedProLayout
	Baseline quiesce.StoppedProBaseline
	Mounts   []CurrentStoppedProMount
}

func isCurrentStoppedPro(i b.InstanceIdentity) bool {
	return i.ID > 0 && i.UserID > 0 && i.Generation > 0 && i.Mode == "pro" && i.OS == "linux" && i.Status == "stopped"
}
func currentStoppedProLayoutValid(l CurrentStoppedProLayout) bool {
	if l.InstanceID <= 0 || len(l.Mounts) == 0 || len(l.Mounts) > 128 || l.ControllerName != "" && len(validation.IsDNS1123Subdomain(l.ControllerName)) != 0 {
		return false
	}
	seen := map[string]bool{}
	for n, m := range l.Mounts {
		if !persistentMountID.MatchString(m.MountID) || seen[m.MountID] || n > 0 && l.Mounts[n-1].MountID >= m.MountID || len(validation.IsDNS1123Subdomain(m.Claim)) != 0 || !cleanMountRoot(m.MountPath) || !cleanMountRoot(m.DataPath) || m.DataPath != m.MountPath && !strings.HasPrefix(m.DataPath, m.MountPath+"/") || m.SubPath != "" && (path.IsAbs(m.SubPath) || path.Clean(m.SubPath) != m.SubPath || m.SubPath == ".." || strings.HasPrefix(m.SubPath, "../") || strings.ContainsAny(m.SubPath, "\\\x00\r\n:")) {
			return false
		}
		seen[m.MountID] = true
	}
	return seen["workspace"]
}
func validateCurrentStoppedProLayouts(all []CurrentStoppedProLayout) error {
	if len(all) > 9998 {
		return d.ErrNotReady
	}
	seen := map[int]bool{}
	for _, l := range all {
		if seen[l.InstanceID] || !currentStoppedProLayoutValid(l) {
			return d.ErrNotReady
		}
		seen[l.InstanceID] = true
	}
	return nil
}
func currentStoppedProLayoutFor(cfg DeploymentConfig, id int) (CurrentStoppedProLayout, error) {
	if cfg.RuntimeSources == nil || validateCurrentStoppedProLayouts(cfg.RuntimeSources.CurrentStoppedProLayouts) != nil {
		return CurrentStoppedProLayout{}, d.ErrNotReady
	}
	for _, l := range cfg.RuntimeSources.CurrentStoppedProLayouts {
		if l.InstanceID == id {
			return l, nil
		}
	}
	return CurrentStoppedProLayout{}, mountInputError("current_stopped_pro_layout_required", id, "")
}
func currentStoppedProConfigSHA(i b.InstanceIdentity, l CurrentStoppedProLayout, storage currentStoppedProSQLStorage) string {
	// This is the independent current source configuration. No final material,
	// grant, reservation, nonce or P7 response digest is included.
	raw, _ := json.Marshal(struct {
		Version string
		Source  b.InstanceIdentity
		Layout  CurrentStoppedProLayout
		Storage currentStoppedProSQLStorage
	}{currentStoppedProMaterialVersion, i, l, storage})
	return hash(raw)
}
func readCurrentStoppedProSQLStorage(ctx context.Context, tx *sql.Tx, instances []b.InstanceIdentity) (map[int]currentStoppedProSQLStorage, error) {
	var out map[int]currentStoppedProSQLStorage
	for _, i := range instances {
		if !isCurrentStoppedPro(i) {
			continue
		}
		var s currentStoppedProSQLStorage
		if tx.QueryRowContext(ctx, "SELECT COALESCE(pvc_name,''),mount_path FROM instances WHERE id=?", i.ID).Scan(&s.Claim, &s.MountPath) != nil || s.Claim == "" || !cleanMountRoot(s.MountPath) {
			return nil, mountInputError("current_stopped_pro_sql_storage_required", i.ID, "")
		}
		if out == nil {
			out = map[int]currentStoppedProSQLStorage{}
		}
		out[i.ID] = s
	}
	return out, nil
}
func (m CurrentStoppedProSourceMaterial) OriginalState() flow.State {
	return flow.State{UID: m.Baseline.SourceKey, Generation: int64(m.Source.Generation), Running: false, Checkpoint: quiesce.StoppedProBaselineSHA256(m.Baseline)}
}
func (m CurrentStoppedProSourceMaterial) validate() error {
	if m.Version != currentStoppedProMaterialVersion || !isCurrentStoppedPro(m.Source) || !currentStoppedProLayoutValid(m.Layout) || m.Layout.InstanceID != m.Source.ID || len(m.Mounts) != len(m.Layout.Mounts) || len(m.Baseline.Volumes) != len(m.Mounts) || m.Baseline.SourceKey != "stopped/"+strconv.Itoa(m.Source.ID) || m.Baseline.RuntimeType != m.Source.Type || m.Baseline.InstanceID != uint64(m.Source.ID) || m.Baseline.UserID != uint64(m.Source.UserID) || m.Baseline.InstanceGeneration != uint64(m.Source.Generation) || m.Baseline.NamespaceUID == "" || !formalCandidateDigest(m.Baseline.CurrentConfigSHA256) || m.Baseline.ControllerReplicas != 0 {
		return d.ErrNotReady
	}
	if m.Baseline.ControllerUID == "" {
		if m.Baseline.ControllerGeneration != 0 || m.Baseline.ControllerSpecSHA256 != "" {
			return d.ErrNotReady
		}
	} else if m.Baseline.ControllerGeneration <= 0 || !formalCandidateDigest(m.Baseline.ControllerSpecSHA256) {
		return d.ErrNotReady
	}
	for n, mount := range m.Mounts {
		v := m.Baseline.Volumes[n]
		id := mount.Identity
		if mount.Layout != m.Layout.Mounts[n] || id.Kind != "PersistentVolumeClaim" || id.Name != mount.Layout.Claim || id.UID == "" || id.PVName == "" || id.PVUID == "" || !formalCandidateDigest(id.SHA256) || mount.Node == "" || mount.NodeUID == "" || !cleanMountRoot(mount.HostPath) || v.NamespaceUID != m.Baseline.NamespaceUID || v.ClaimName != id.Name || v.ClaimUID != id.UID || v.PVName != id.PVName || v.PVUID != id.PVUID || v.PVSpecSHA256 != id.SHA256 || v.DataNodeUID != mount.NodeUID || v.HostPath != mount.HostPath || !formalCandidateDigest(v.UniqueNodeEvidenceSHA256) {
			return d.ErrNotReady
		}
		if mount.Layout.MountID == "workspace" && (mount.Layout.MountPath != m.Source.Workspace && !strings.HasPrefix(m.Source.Workspace, mount.Layout.MountPath+"/")) {
			return d.ErrNotReady
		}
		for j := 0; j < n; j++ {
			old := m.Mounts[j]
			if old.NodeUID != mount.NodeUID || old.HostPath == mount.HostPath || strings.HasPrefix(old.HostPath, mount.HostPath+"/") || strings.HasPrefix(mount.HostPath, old.HostPath+"/") {
				return d.ErrNotReady
			}
		}
	}
	return nil
}

func currentStoppedProMaterialFor(scope *productionPersistentMountScope, i b.InstanceIdentity) (*CurrentStoppedProSourceMaterial, error) {
	if scope == nil || !isCurrentStoppedPro(i) {
		return nil, d.ErrNotReady
	}
	var out *CurrentStoppedProSourceMaterial
	for n := range scope.CurrentStoppedPro {
		m := &scope.CurrentStoppedPro[n]
		if m.Source.ID == i.ID {
			if out != nil || m.Source != i || m.validate() != nil {
				return nil, d.ErrNotReady
			}
			out = m
		}
	}
	if out == nil {
		return nil, mountInputError("current_stopped_pro_material_required", i.ID, "")
	}
	return out, nil
}

// Complete unfiltered Nodes are used, including unavailable nodes. A plain
// hostPath on two possible nodes is ambiguous even if only one node is Ready.
func currentStoppedProNode(pv *corev1.PersistentVolume, nodes []corev1.Node) (*corev1.Node, string, error) {
	var selected *corev1.Node
	for n := range nodes {
		node := &nodes[n]
		match, err := currentStoppedProNodeMatches(pv.Spec.NodeAffinity, node)
		if err != nil {
			return nil, "", err
		}
		if match {
			if selected != nil {
				return nil, "", mountInputError("current_stopped_pro_ambiguous_data_node", 0, "")
			}
			selected = node
		}
	}
	if selected == nil {
		return nil, "", d.ErrNotReady
	}
	type nodePin struct {
		Name, UID string
		Labels    map[string]string
	}
	pins := []nodePin{}
	for _, node := range nodes {
		pins = append(pins, nodePin{node.Name, string(node.UID), node.Labels})
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Name < pins[j].Name })
	raw, _ := json.Marshal(struct {
		PVSpecSHA256 string
		Nodes        []nodePin
	}{kube.ContentHash(pv.Spec), pins})
	return selected, hash(raw), nil
}
func currentStoppedProNodeMatches(a *corev1.VolumeNodeAffinity, n *corev1.Node) (bool, error) {
	if a == nil || a.Required == nil {
		return true, nil
	}
	for _, term := range a.Required.NodeSelectorTerms {
		if len(term.MatchExpressions)+len(term.MatchFields) == 0 {
			continue
		}
		match := true
		for _, r := range term.MatchExpressions {
			var op selection.Operator
			switch r.Operator {
			case corev1.NodeSelectorOpIn:
				op = selection.In
			case corev1.NodeSelectorOpNotIn:
				op = selection.NotIn
			case corev1.NodeSelectorOpExists:
				op = selection.Exists
			case corev1.NodeSelectorOpDoesNotExist:
				op = selection.DoesNotExist
			case corev1.NodeSelectorOpGt:
				op = selection.GreaterThan
			case corev1.NodeSelectorOpLt:
				op = selection.LessThan
			default:
				return false, d.ErrNotReady
			}
			req, e := labels.NewRequirement(r.Key, op, r.Values)
			if e != nil {
				return false, d.ErrNotReady
			}
			match = match && req.Matches(labels.Set(n.Labels))
		}
		for _, r := range term.MatchFields {
			if r.Key != "metadata.name" || len(r.Values) != 1 {
				return false, d.ErrNotReady
			}
			switch r.Operator {
			case corev1.NodeSelectorOpIn:
				match = match && n.Name == r.Values[0]
			case corev1.NodeSelectorOpNotIn:
				match = match && n.Name != r.Values[0]
			default:
				return false, d.ErrNotReady
			}
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// Actual metadata reads only. This leaf cannot establish physical quiescence.
// Its callers retain the Installer/source delegation and complete SQL/API census.
func observeCurrentStoppedPro(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, i b.InstanceIdentity, storage currentStoppedProSQLStorage) (CurrentStoppedProSourceMaterial, error) {
	var zero CurrentStoppedProSourceMaterial
	if ctx == nil || ctx.Err() != nil || client == nil || !isCurrentStoppedPro(i) || i.Namespace != "" && i.Namespace != cfg.Namespace {
		return zero, d.ErrNotReady
	}
	l, err := currentStoppedProLayoutFor(cfg, i.ID)
	if err != nil {
		return zero, err
	}
	for _, mount := range l.Mounts {
		if mount.MountID == "workspace" && (storage.Claim != mount.Claim || storage.MountPath != mount.MountPath) {
			return zero, mountInputError("current_stopped_pro_sql_layout_mismatch", i.ID, "workspace")
		}
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, d.ErrNotReady
	}
	m := CurrentStoppedProSourceMaterial{Version: currentStoppedProMaterialVersion, Source: i, Layout: l, Mounts: []CurrentStoppedProMount{}, Baseline: quiesce.StoppedProBaseline{SourceKey: "stopped/" + strconv.Itoa(i.ID), RuntimeType: i.Type, InstanceID: uint64(i.ID), UserID: uint64(i.UserID), InstanceGeneration: uint64(i.Generation), NamespaceUID: cfg.NamespaceUID, CurrentConfigSHA256: currentStoppedProConfigSHA(i, l, storage), Volumes: []quiesce.StoppedProVolume{}}}
	deployments, err := client.AppsV1().Deployments(cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || deployments.Continue != "" || len(deployments.Items) > 10000 {
		return zero, d.ErrNotReady
	}
	for _, dep := range deployments.Items {
		selected := dep.Name == l.ControllerName
		if dep.Labels["instance-id"] == strconv.Itoa(i.ID) && !selected {
			return zero, d.ErrNotReady
		}
		if !selected {
			continue
		}
		if l.ControllerName == "" || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Generation <= 0 || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Labels["instance-id"] != strconv.Itoa(i.ID) || dep.Labels["user-id"] != strconv.Itoa(i.UserID) || currentStoppedProTemplateCoverage(i, dep.Spec.Template.Spec, l) != nil {
			return zero, d.ErrNotReady
		}
		m.Baseline.ControllerUID = string(dep.UID)
		m.Baseline.ControllerGeneration = dep.Generation
		m.Baseline.ControllerSpecSHA256 = kube.ContentHash(dep.Spec)
	}
	rs, err := client.AppsV1().ReplicaSets(cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || rs.Continue != "" || len(rs.Items) > 10000 {
		return zero, d.ErrNotReady
	}
	for _, r := range rs.Items {
		owner := metav1.GetControllerOf(&r)
		owned := owner != nil && owner.Kind == "Deployment" && string(owner.UID) == m.Baseline.ControllerUID && m.Baseline.ControllerUID != ""
		if r.Labels["instance-id"] == strconv.Itoa(i.ID) || owned {
			if !owned || r.DeletionTimestamp != nil || r.Spec.Replicas == nil || *r.Spec.Replicas != 0 || currentStoppedProTemplateCoverage(i, r.Spec.Template.Spec, l) != nil {
				return zero, d.ErrNotReady
			}
		}
	}
	pods, err := client.CoreV1().Pods(cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || pods.Continue != "" || len(pods.Items) > 10000 {
		return zero, d.ErrNotReady
	}
	for _, pod := range pods.Items {
		// Any Pod of this instance is a current mismatch, including terminating.
		if pod.Labels["instance-id"] == strconv.Itoa(i.ID) || i.Pod != "" && pod.Name == i.Pod {
			return zero, d.ErrNotReady
		}
		owner := metav1.GetControllerOf(&pod)
		for _, r := range rs.Items {
			if owner != nil && string(owner.UID) == string(r.UID) {
				o := metav1.GetControllerOf(&r)
				if o != nil && m.Baseline.ControllerUID != "" && string(o.UID) == m.Baseline.ControllerUID {
					return zero, d.ErrNotReady
				}
			}
		}
	}
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil || nodes.Continue != "" || len(nodes.Items) == 0 || len(nodes.Items) > 10000 {
		return zero, d.ErrNotReady
	}
	for _, mount := range l.Mounts {
		pvc, err := client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Get(ctx, mount.Claim, metav1.GetOptions{})
		if err != nil || pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" || pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode != corev1.PersistentVolumeFilesystem {
			return zero, d.ErrNotReady
		}
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Name != pvc.Name || pv.Spec.ClaimRef.Namespace != cfg.Namespace {
			return zero, d.ErrNotReady
		}
		var hostRoot string
		switch {
		case pv.Spec.HostPath != nil && reflect.DeepEqual(pv.Spec.PersistentVolumeSource, corev1.PersistentVolumeSource{HostPath: pv.Spec.HostPath}):
			hostRoot = pv.Spec.HostPath.Path
		case pv.Spec.Local != nil && reflect.DeepEqual(pv.Spec.PersistentVolumeSource, corev1.PersistentVolumeSource{Local: pv.Spec.Local}):
			hostRoot = pv.Spec.Local.Path
		default:
			return zero, mountInputError("current_stopped_pro_local_pv_required", i.ID, mount.MountID)
		}
		if !cleanMountRoot(hostRoot) {
			return zero, d.ErrNotReady
		}
		node, evidence, err := currentStoppedProNode(pv, nodes.Items)
		if err != nil {
			return zero, err
		}
		if node.UID == "" || node.DeletionTimestamp != nil || node.Labels[corev1.LabelOSStable] != "linux" || cfg.Security.NodeUIDs[node.Name] != string(node.UID) || node.Name != cfg.Workspace.Node {
			return zero, d.ErrNotReady
		}
		id := kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: pvc.Name, UID: string(pvc.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
		pinned := false
		for _, pin := range cfg.Security.Volumes {
			pinned = pinned || pin.Kind == id.Kind && pin.Name == id.Name && pin.UID == id.UID && pin.PVName == id.PVName && pin.PVUID == id.PVUID && pin.SHA256 == id.SHA256
		}
		if !pinned {
			return zero, mountInputError("current_stopped_pro_volume_pin_required", i.ID, mount.MountID)
		}
		relative := path.Join(mount.SubPath, strings.TrimPrefix(strings.TrimPrefix(mount.DataPath, mount.MountPath), "/"))
		host := path.Join(hostRoot, relative)
		m.Mounts = append(m.Mounts, CurrentStoppedProMount{Layout: mount, Identity: id, Node: node.Name, NodeUID: string(node.UID), HostPath: host})
		m.Baseline.Volumes = append(m.Baseline.Volumes, quiesce.StoppedProVolume{NamespaceUID: cfg.NamespaceUID, ClaimName: id.Name, ClaimUID: id.UID, PVName: id.PVName, PVUID: id.PVUID, PVSpecSHA256: id.SHA256, DataNodeUID: string(node.UID), UniqueNodeEvidenceSHA256: evidence, HostPath: host})
	}
	if ctx.Err() != nil || m.validate() != nil {
		return zero, d.ErrNotReady
	}
	return m, nil
}

func currentStoppedProTemplateCoverage(i b.InstanceIdentity, spec corev1.PodSpec, l CurrentStoppedProLayout) error {
	if len(spec.EphemeralContainers) != 0 {
		return d.ErrNotReady
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		if v.Name == "" || volumes[v.Name].Name != "" {
			return d.ErrNotReady
		}
		volumes[v.Name] = v
	}
	used := map[string]bool{}
	for _, container := range append(append([]corev1.Container{}, spec.Containers...), spec.InitContainers...) {
		if len(container.VolumeDevices) != 0 {
			return d.ErrNotReady
		}
		for _, mount := range container.VolumeMounts {
			v, ok := volumes[mount.Name]
			if !ok || mount.SubPathExpr != "" {
				return d.ErrNotReady
			}
			if mount.SubPath != "" && (path.IsAbs(mount.SubPath) || path.Clean(mount.SubPath) != mount.SubPath || mount.SubPath == ".." || strings.HasPrefix(mount.SubPath, "../") || strings.ContainsAny(mount.SubPath, "\\\x00\r\n:")) {
				return d.ErrNotReady
			}
			if transientSource(v) {
				for _, decl := range l.Mounts {
					if mount.MountPath == decl.DataPath || strings.HasPrefix(mount.MountPath, decl.DataPath+"/") {
						return d.ErrNotReady
					}
				}
				continue
			}
			if v.PersistentVolumeClaim == nil || !reflect.DeepEqual(v.VolumeSource, corev1.VolumeSource{PersistentVolumeClaim: v.PersistentVolumeClaim}) {
				return d.ErrNotReady
			}
			matched := false
			for _, decl := range l.Mounts {
				root := path.Clean(path.Join(decl.SubPath, strings.TrimPrefix(strings.TrimPrefix(decl.DataPath, decl.MountPath), "/")))
				mountRoot := path.Clean(mount.SubPath)
				if v.PersistentVolumeClaim.ClaimName == decl.Claim && (root == "." || root == mountRoot || strings.HasPrefix(mountRoot, root+"/")) {
					used[decl.MountID] = true
					matched = true
				}
			}
			if !matched {
				return d.ErrNotReady
			}
		}
	}
	for _, decl := range l.Mounts {
		if !used[decl.MountID] {
			return d.ErrNotReady
		}
	}
	return nil
}

func recheckCurrentStoppedProMaterial(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, m CurrentStoppedProSourceMaterial) error {
	var storage currentStoppedProSQLStorage
	for _, mount := range m.Layout.Mounts {
		if mount.MountID == "workspace" {
			storage = currentStoppedProSQLStorage{Claim: mount.Claim, MountPath: mount.MountPath}
		}
	}
	actual, err := observeCurrentStoppedPro(ctx, client, cfg, m.Source, storage)
	if err != nil || !reflect.DeepEqual(actual, m) {
		return d.ErrNotReady
	}
	return nil
}
func bootstrapNativeNeedsAgent(all []bootstrapSourceNativeWriter) bool {
	for _, n := range all {
		if n.CurrentStoppedPro == nil {
			return true
		}
	}
	return false
}
func hasRunningSourceInstances(instances []b.InstanceIdentity) bool {
	for _, i := range instances {
		if i.Status == "running" {
			return true
		}
	}
	return false
}
func checkCurrentStoppedProScopes(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, scope *productionPersistentMountScope, instances []b.InstanceIdentity) error {
	count := 0
	for _, i := range instances {
		if !isCurrentStoppedPro(i) {
			continue
		}
		count++
		m, err := currentStoppedProMaterialFor(scope, i)
		if err != nil {
			return err
		}
		if recheckCurrentStoppedProMaterial(ctx, client, cfg, *m) != nil {
			return mountInputError("current_stopped_pro_baseline_changed", i.ID, "")
		}
	}
	if scope != nil && count != len(scope.CurrentStoppedPro) {
		return d.ErrNotReady
	}
	return nil
}

func currentStoppedProConfiguredStorage(cfg DeploymentConfig, id int) (currentStoppedProSQLStorage, error) {
	l, err := currentStoppedProLayoutFor(cfg, id)
	if err != nil {
		return currentStoppedProSQLStorage{}, err
	}
	for _, m := range l.Mounts {
		if m.MountID == "workspace" {
			return currentStoppedProSQLStorage{Claim: m.Claim, MountPath: m.MountPath}, nil
		}
	}
	return currentStoppedProSQLStorage{}, d.ErrNotReady
}
func checkCurrentStoppedProSQL(scope *productionPersistentMountScope, metadata productionSQLSourceMetadata, instances []b.InstanceIdentity) error {
	count := 0
	for _, i := range instances {
		if !isCurrentStoppedPro(i) {
			continue
		}
		count++
		m, err := currentStoppedProMaterialFor(scope, i)
		if err != nil {
			return err
		}
		storage, ok := metadata.CurrentStoppedProStorage[i.ID]
		if !ok || currentStoppedProConfigSHA(i, m.Layout, storage) != m.Baseline.CurrentConfigSHA256 {
			return mountInputError("current_stopped_pro_sql_layout_mismatch", i.ID, "")
		}
	}
	if count != len(metadata.CurrentStoppedProStorage) || scope != nil && count != len(scope.CurrentStoppedPro) {
		return d.ErrNotReady
	}
	return nil
}
func currentStoppedProGraphRoots(cfg DeploymentConfig, source b.SourceInventory, api *observedWriterAPI, want map[string]string) (map[string]bool, error) {
	stopped := map[string]bool{}
	for _, i := range source.Instances {
		if !isCurrentStoppedPro(i) {
			continue
		}
		l, err := currentStoppedProLayoutFor(cfg, i.ID)
		if err != nil {
			return nil, err
		}
		if l.ControllerName == "" {
			continue
		}
		key := "Deployment/" + cfg.Namespace + "/" + l.ControllerName
		for _, object := range api.objects {
			if object.Kind == "Deployment" && object.Namespace == cfg.Namespace && object.Name == l.ControllerName {
				if object.UID == "" || object.Replicas != 0 || object.Ready != 0 || want[key] != "" && want[key] != object.UID {
					return nil, d.ErrNotReady
				}
				want[key] = object.UID
				stopped[key] = true
			}
		}
	}
	return stopped, nil
}

func currentStoppedProCaptureMount(m CurrentStoppedProSourceMaterial, mount CurrentStoppedProMount, base productionInstanceMount) productionInstanceMount {
	relative := path.Join(mount.Layout.SubPath, strings.TrimPrefix(strings.TrimPrefix(mount.Layout.DataPath, mount.Layout.MountPath), "/"))
	if relative == "." {
		relative = ""
	}
	base.InstanceID = m.Source.ID
	base.MountID = mount.Layout.MountID
	base.Source = corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: mount.Layout.Claim, ReadOnly: true}}}
	base.SubPath = relative
	base.NodeName = mount.Node
	if mount.Layout.MountID != "workspace" {
		base.DataOnly = true
		base.Skills = nil
		base.WorkBuddy = nil
	}
	return base
}
