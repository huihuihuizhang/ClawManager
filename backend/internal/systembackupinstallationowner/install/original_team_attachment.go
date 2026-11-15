package install

import (
	"context"
	"reflect"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/kube"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalTeamAttachmentChoice struct {
	TeamID                int
	Namespace, Pod, Image string
}

type OriginalTeamAttachmentPin struct {
	Choice                                             OriginalTeamAttachmentChoice
	NamespaceUID, PodUID, PodSpecSHA256, Node, NodeUID string
	PVC, PVCUID, PV, PVUID, PVSpecSHA256               string
}

func (s *PreparedOriginalWriterSet) recheckTeamAttachments(ctx context.Context, recovery *originalWriterRecoveryFence) error {
	if len(s.selection.TeamAttachments) > 8 {
		return ErrInstall
	}
	seen := map[int]bool{}
	for _, pin := range s.selection.TeamAttachments {
		if seen[pin.Choice.TeamID] {
			return ErrInstall
		}
		seen[pin.Choice.TeamID] = true
		covered := false
		for _, tenant := range s.selection.TenantPro {
			covered = covered || tenant.Identity.Namespace == pin.Choice.Namespace && tenant.Identity.NamespaceUID == pin.NamespaceUID
		}
		actual, err := s.owner.observeTeamAttachment(ctx, pin.Choice, recovery)
		if !covered || err != nil || !reflect.DeepEqual(actual, pin) {
			return ErrInstall
		}
	}
	return nil
}

// Only a real active team row can designate this exact inert consumer. This
// is preparation/readback, never a CSI freeze or permission to delete the Pod.
func (p *OriginalWriterMaintenance) observeTeamAttachment(ctx context.Context, choice OriginalTeamAttachmentChoice, recovery *originalWriterRecoveryFence) (OriginalTeamAttachmentPin, error) {
	var out OriginalTeamAttachmentPin
	if originalMaintenanceReadCheck(ctx, p, recovery) != nil || choice.TeamID <= 0 || !strings.HasPrefix(choice.Pod, "sbk-team-"+strconv.Itoa(choice.TeamID)+"-") {
		return out, ErrInstall
	}
	var userID int
	var claim, namespace string
	i := p.operator.installer
	stem, ok := strings.CutSuffix(i.plan.Target.Namespace, "-system")
	if !ok || stem == "" || i.db.QueryRowContext(ctx, "SELECT user_id,COALESCE(shared_pvc_name,''),COALESCE(shared_pvc_namespace,'') FROM teams WHERE id=? AND status<>'deleted'", choice.TeamID).Scan(&userID, &claim, &namespace) != nil || claim == "" || namespace != choice.Namespace || userID <= 0 || namespace != stem+"-user-"+strconv.Itoa(userID) {
		return out, ErrInstall
	}
	k := i.kube
	ns, err := k.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil || ns.Labels["app"] != "clawreef" || ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != strconv.Itoa(userID) {
		return out, ErrInstall
	}
	pod, err := k.CoreV1().Pods(namespace).Get(ctx, choice.Pod, metav1.GetOptions{})
	if err != nil || !kube.ValidOriginalTeamAttachmentPodSpec(pod, claim, choice.Image) {
		return out, ErrInstall
	}
	if _, err := originalMaintenancePodIdentity(pod); err != nil {
		return out, ErrInstall
	}
	pvc, err := k.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, claim, metav1.GetOptions{})
	if err != nil || pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != core.ClaimBound || !reflect.DeepEqual(pvc.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteMany}) {
		return out, ErrInstall
	}
	pv, err := k.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle == "" || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Namespace != namespace || pv.Spec.ClaimRef.Name != claim {
		return out, ErrInstall
	}
	node, err := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
		return out, ErrInstall
	}
	return OriginalTeamAttachmentPin{Choice: choice, NamespaceUID: string(ns.UID), PodUID: string(pod.UID), PodSpecSHA256: originalObjectSHA(pod.Spec), Node: node.Name, NodeUID: string(node.UID), PVC: claim, PVCUID: string(pvc.UID), PV: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: originalObjectSHA(pv.Spec)}, nil
}
