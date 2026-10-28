package profile

import (
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/recovery"
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path"
	"strings"
)

type SharedVolumeReceipt struct {
	TeamID                                                     int
	ArtifactID                                                 string
	Namespace, PVC, PVCUID, PV, PVUID, MountPath, StorageClass string
	Contents                                                   recovery.Reference
}

// Owner evidence covers restored content, UID/GID and exclusive isolation.
// This adapter additionally verifies the actual Kubernetes mount identities.
type SharedWorkspaceOwner interface {
	Probe(context.Context, recovery.Reference) error
	Receipts(context.Context, control.Task) ([]SharedVolumeReceipt, error)
	Verify(context.Context, control.Task, SharedVolumeReceipt) error
}

func (d *Driver) teamPlacements(ctx context.Context, t control.Task, receipts []SharedVolumeReceipt) (map[string]domain.Placement, error) {
	if d.Config.SharedWorkspaceModule == nil {
		if len(receipts) > 0 {
			return nil, ErrProfile
		}
		return nil, nil
	}
	if d.SharedWorkspace == nil || d.Client == nil {
		return nil, ErrProfile
	}
	out := map[string]domain.Placement{}
	for _, r := range receipts {
		id := fmt.Sprint(r.TeamID)
		if r.TeamID <= 0 || out[id].PVC != "" || r.ArtifactID != t.Request.Artifact || r.Namespace != d.Config.TargetNamespace || !strings.HasPrefix(r.Namespace, "cm-drill-") || r.Contents.Validate() != nil || r.PVCUID == "" || r.PVUID == "" || !path.IsAbs(r.MountPath) || path.Clean(r.MountPath) != r.MountPath || r.MountPath == "/" || strings.ContainsAny(r.MountPath, "\\\x00\r\n:") {
			return nil, ErrProfile
		}
		pvc, e := d.Client.CoreV1().PersistentVolumeClaims(r.Namespace).Get(ctx, r.PVC, metav1.GetOptions{})
		if e != nil || pvc.DeletionTimestamp != nil || string(pvc.UID) != r.PVCUID || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName != r.PV || pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != r.StorageClass {
			return nil, ErrProfile
		}
		pv, e := d.Client.CoreV1().PersistentVolumes().Get(ctx, r.PV, metav1.GetOptions{})
		if e != nil || pv.DeletionTimestamp != nil || string(pv.UID) != r.PVUID || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != r.PVCUID || pv.Spec.ClaimRef.Namespace != r.Namespace || pv.Spec.ClaimRef.Name != r.PVC {
			return nil, ErrProfile
		}
		if e = d.SharedWorkspace.Verify(ctx, t, r); e != nil {
			return nil, ErrProfile
		}
		out[id] = domain.Placement{PVC: r.PVC, Namespace: r.Namespace, MountPath: r.MountPath, StorageClass: r.StorageClass}
	}
	return out, nil
}
