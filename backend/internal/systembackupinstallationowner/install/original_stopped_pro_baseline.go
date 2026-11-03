package install

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

type OriginalStoppedProSelection struct {
	InstanceID     int
	PVCs           []string // legacy dedicated claim mapping; cannot cover a shared PVC
	ControllerName string
	Mounts         []OriginalStoppedProMountSelection
}
type originalStoppedProObservation struct {
	baseline  domain.OriginalStoppedSourceBaseline
	sha       string
	selection OriginalStoppedProSelection
	census    originalMaintenanceKubernetesCensus
	storage   *originalStoppedProStorage
}

// Public hashes only: raw API specs may contain secrets.
type originalMaintenanceKubernetesCensus struct {
	Namespace, NamespaceUID                                                        string
	Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Autoscalers, PVCs []originalMaintenanceObjectPin
}
type originalMaintenanceObjectPin struct {
	Name, UID, SpecSHA256 string
	Generation            int64
}

func originalObjectSHA(v any) string { raw, _ := json.Marshal(v); return hash(raw) }

// Enumerate the entire namespace. No label selector may hide another writer.
func (p *OriginalWriterMaintenance) readKubernetesCensus(ctx context.Context) (originalMaintenanceKubernetesCensus, []corev1.Pod, []appsv1.Deployment, []corev1.PersistentVolumeClaim, error) {
	var out originalMaintenanceKubernetesCensus
	if p.check(ctx) != nil {
		return out, nil, nil, nil, ErrInstall
	}
	k := p.operator.installer.kube
	ns := p.operator.installer.plan.Target.Namespace
	namespace, err := k.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || string(namespace.UID) != p.operator.installer.plan.Target.NamespaceUID || namespace.DeletionTimestamp != nil {
		return out, nil, nil, nil, ErrInstall
	}
	out.Namespace = ns
	out.NamespaceUID = string(namespace.UID)
	pods, err := k.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	deps, err := k.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	sets, err := k.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	daemons, err := k.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	jobs, err := k.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	crons, err := k.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	hpas, err := k.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	pvcs, err := k.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, nil, nil, nil, ErrInstall
	}
	for _, v := range pods.Items {
		out.Pods = append(out.Pods, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(struct {
			Spec     corev1.PodSpec
			Owners   []metav1.OwnerReference
			Phase    corev1.PodPhase
			Statuses []corev1.ContainerStatus
		}{v.Spec, v.OwnerReferences, v.Status.Phase, v.Status.ContainerStatuses}), v.Generation})
	}
	for _, v := range deps.Items {
		out.Deployments = append(out.Deployments, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range sets.Items {
		out.StatefulSets = append(out.StatefulSets, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range daemons.Items {
		out.DaemonSets = append(out.DaemonSets, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range jobs.Items {
		out.Jobs = append(out.Jobs, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range crons.Items {
		out.CronJobs = append(out.CronJobs, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range hpas.Items {
		out.Autoscalers = append(out.Autoscalers, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, v := range pvcs.Items {
		out.PVCs = append(out.PVCs, originalMaintenanceObjectPin{v.Name, string(v.UID), originalObjectSHA(v.Spec), v.Generation})
	}
	for _, rows := range [][]originalMaintenanceObjectPin{out.Pods, out.Deployments, out.StatefulSets, out.DaemonSets, out.Jobs, out.CronJobs, out.Autoscalers, out.PVCs} {
		if len(rows) > 10000 {
			return originalMaintenanceKubernetesCensus{}, nil, nil, nil, ErrInstall
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	}
	return out, pods.Items, deps.Items, pvcs.Items, nil
}

// Real CURRENT stopped baseline. No caller Pod UID, PID, checkpoint, node
// guess, or historical template is accepted. It confers no hold capability.
func (p *OriginalWriterMaintenance) prepareStoppedPro(ctx context.Context, s OriginalStoppedProSelection) (*originalStoppedProObservation, error) {
	if len(s.Mounts) > 0 {
		return p.prepareStoppedProLayout(ctx, s)
	}
	if p.check(ctx) != nil || p.checkInstances(ctx) != nil || s.InstanceID <= 0 || len(s.PVCs) == 0 {
		return nil, ErrInstall
	}
	var source domain.SourceInstance
	found := false
	for _, v := range p.instances {
		if v.ID == s.InstanceID {
			source = v
			found = true
		}
	}
	plan, err := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
	if !found || err != nil || plan.Mode != "pro" || source.Status != "stopped" {
		return nil, ErrInstall
	}
	census, pods, deps, claims, err := p.readKubernetesCensus(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	instance := strconv.Itoa(source.ID)
	user := strconv.Itoa(source.UserID)
	for _, pod := range pods {
		if pod.Name == source.Pod && source.Pod != "" || pod.Labels["instance-id"] == instance {
			if pod.Labels["instance-id"] != instance || pod.Labels["user-id"] != user || pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
				return nil, ErrInstall
			}
		}
	}
	b := domain.OriginalStoppedSourceBaseline{Version: domain.OriginalStoppedSourceBaselineVersion, SourceKey: fmt.Sprintf("instance/%d", source.ID), InstallationID: p.operator.installer.plan.Target.InstallationID, Namespace: census.Namespace, NamespaceUID: census.NamespaceUID, Source: source, SQLProjectionSHA256: originalObjectSHA(p.instances), KubernetesCensusSHA256: originalObjectSHA(census), ControllerKind: "absent"}
	b.SourceKey = "stopped/" + strconv.Itoa(source.ID)
	for _, dep := range deps {
		if dep.Labels["instance-id"] == instance {
			if b.ControllerKind != "absent" || dep.Labels["user-id"] != user || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 || dep.Status.ObservedGeneration < dep.Generation || dep.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			b.ControllerKind = "Deployment"
			b.ControllerName = dep.Name
			b.ControllerUID = string(dep.UID)
			b.ControllerGeneration = dep.Generation
			b.ControllerSpecSHA256 = originalObjectSHA(dep.Spec)
		}
	}
	selected := map[string]bool{}
	for _, name := range s.PVCs {
		if name == "" || selected[name] {
			return nil, ErrInstall
		}
		selected[name] = true
	}
	actual := map[string]bool{}
	for _, claim := range claims {
		if claim.Labels["instance-id"] == instance {
			if !selected[claim.Name] || claim.Labels["user-id"] != user || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
				return nil, ErrInstall
			}
			actual[claim.Name] = true
			pv, err := p.operator.installer.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != b.Namespace || pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
				return nil, ErrInstall
			}
			root := ""
			if pv.Spec.HostPath != nil {
				root = pv.Spec.HostPath.Path
			}
			if pv.Spec.Local != nil {
				if root != "" {
					return nil, ErrInstall
				}
				root = pv.Spec.Local.Path
			}
			if root == "" {
				return nil, ErrInstall
			}
			nodes, err := p.operator.installer.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, ErrInstall
			}
			var chosen *corev1.Node
			for n := range nodes.Items {
				node := &nodes.Items[n]
				matches, err := originalPVMatchesNode(pv.Spec.NodeAffinity.Required, node)
				if err != nil {
					return nil, ErrInstall
				}
				if matches {
					if chosen != nil {
						return nil, ErrInstall
					}
					chosen = node
				}
			}
			if chosen == nil || chosen.UID == "" || chosen.DeletionTimestamp != nil || chosen.Status.NodeInfo.MachineID == "" || chosen.Status.NodeInfo.BootID == "" {
				return nil, ErrInstall
			}
			b.Volumes = append(b.Volumes, domain.OriginalStoppedSourceVolume{ID: fmt.Sprintf("instance/%d/pvc/%s", source.ID, claim.UID), SourcePath: root, Kind: "local_pv", PVCName: claim.Name, PVCUID: string(claim.UID), PVCSpecSHA256: originalObjectSHA(claim.Spec), PVName: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: originalObjectSHA(pv.Spec), ClaimRefUID: string(pv.Spec.ClaimRef.UID), NodeAffinitySHA256: originalObjectSHA(pv.Spec.NodeAffinity), Node: chosen.Name, NodeUID: string(chosen.UID), MachineID: chosen.Status.NodeInfo.MachineID, BootID: chosen.Status.NodeInfo.BootID})
		}
	}
	if len(actual) != len(selected) {
		return nil, ErrInstall
	}
	sort.Slice(b.Volumes, func(i, j int) bool { return b.Volumes[i].ID < b.Volumes[j].ID })
	sha, err := domain.OriginalStoppedSourceBaselineSHA256(b)
	if err != nil {
		return nil, ErrInstall
	}
	after, _, _, _, err := p.readKubernetesCensus(ctx)
	if err != nil || !reflect.DeepEqual(census, after) || p.checkInstances(ctx) != nil {
		return nil, ErrInstall
	}
	return &originalStoppedProObservation{baseline: b, sha: sha, selection: s, census: census}, nil
}

func originalPVMatchesNode(selector *corev1.NodeSelector, node *corev1.Node) (bool, error) {
	if selector == nil || len(selector.NodeSelectorTerms) == 0 || node == nil {
		return false, ErrInstall
	}
	anyTerm := false
	for _, term := range selector.NodeSelectorTerms {
		if len(term.MatchExpressions)+len(term.MatchFields) == 0 {
			continue
		}
		matches := true
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
				return false, ErrInstall
			}
			req, err := labels.NewRequirement(r.Key, op, r.Values)
			if err != nil {
				return false, ErrInstall
			}
			if !req.Matches(labels.Set(node.Labels)) {
				matches = false
			}
		}
		for _, r := range term.MatchFields {
			if r.Key != "metadata.name" || len(r.Values) != 1 {
				return false, ErrInstall
			}
			switch r.Operator {
			case corev1.NodeSelectorOpIn:
				matches = matches && node.Name == r.Values[0]
			case corev1.NodeSelectorOpNotIn:
				matches = matches && node.Name != r.Values[0]
			default:
				return false, ErrInstall
			}
		}
		anyTerm = anyTerm || matches
	}
	return anyTerm, nil
}
