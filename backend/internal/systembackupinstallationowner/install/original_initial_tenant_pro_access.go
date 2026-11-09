package install

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalInitialTenantProAccess struct {
	Namespace, NamespaceUID string
	Volumes                 []originalPhysicalVolumePin
	Pods                    []originalInitialTenantProPod
}

type originalInitialTenantProPod struct {
	InstanceID               int
	Name, UID, Node, NodeUID string
}

// This coordinate read belongs to the original installer, before the limited
// source account exists. The native source author independently reads the
// complete controller census and authenticates the workspace mount later.
func (p *OriginalWriterMaintenance) initialTenantProAccess(ctx context.Context, testScope *domain.RuntimeTestScope) ([]originalInitialTenantProAccess, error) {
	i := p.operator.installer
	system := i.plan.Target.Namespace
	stem, hasStem := strings.CutSuffix(system, "-system")
	tenants := map[string][]domain.SourceInstance{}
	for _, s := range p.instances {
		if testScope.IsDeferred(s) || s.Mode != "pro" || s.OS != "linux" || s.Status != "running" || s.Namespace == system {
			continue
		}
		if !hasStem || stem == "" || s.UserID <= 0 || s.Pod == "" || s.Namespace != stem+"-user-"+strconv.Itoa(s.UserID) {
			return nil, ErrInstall
		}
		tenants[s.Namespace] = append(tenants[s.Namespace], s)
	}
	var out []originalInitialTenantProAccess
	for name, sources := range tenants {
		user := strconv.Itoa(sources[0].UserID)
		ns, err := i.kube.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil || ns.Labels["app"] != "clawreef" ||
			ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != user {
			return nil, ErrInstall
		}
		pin := originalInitialTenantProAccess{Namespace: name, NamespaceUID: string(ns.UID)}
		for _, source := range sources {
			pod, err := i.kube.CoreV1().Pods(name).Get(ctx, source.Pod, metav1.GetOptions{})
			if err != nil || pod.UID == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != core.PodRunning ||
				pod.Spec.NodeName == "" || pod.Labels["app"] != "clawreef" || pod.Labels["managed-by"] != "clawreef" ||
				pod.Labels["user-id"] != user || pod.Labels["instance-id"] != strconv.Itoa(source.ID) {
				return nil, ErrInstall
			}
			node, err := i.kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err != nil || node.UID == "" || node.DeletionTimestamp != nil || node.Labels[core.LabelOSStable] != "linux" {
				return nil, ErrInstall
			}
			pin.Pods = append(pin.Pods, originalInitialTenantProPod{source.ID, pod.Name, string(pod.UID), node.Name, string(node.UID)})
		}
		claims, err := i.kube.CoreV1().PersistentVolumeClaims(name).List(ctx, metav1.ListOptions{})
		if err != nil || claims.Continue != "" || len(claims.Items) == 0 || len(claims.Items) > 10000 {
			return nil, ErrInstall
		}
		for _, claim := range claims.Items {
			if claim.Namespace != name || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Status.Phase != core.ClaimBound || claim.Spec.VolumeName == "" {
				return nil, ErrInstall
			}
			pv, err := i.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil ||
				pv.Spec.ClaimRef.Namespace != name || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID {
				return nil, ErrInstall
			}
			pin.Volumes = append(pin.Volumes, originalPhysicalVolumePin{Namespace: name, ClaimName: claim.Name, ClaimUID: string(claim.UID),
				ClaimSpecSHA256: originalObjectSHA(claim.Spec), PVName: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: originalObjectSHA(pv.Spec)})
		}
		sort.Slice(pin.Volumes, func(a, b int) bool { return pin.Volumes[a].ClaimName < pin.Volumes[b].ClaimName })
		out = append(out, pin)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Namespace < out[b].Namespace })
	return out, ctx.Err()
}
