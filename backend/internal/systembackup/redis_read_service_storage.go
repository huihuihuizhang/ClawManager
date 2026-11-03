package systembackup

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type redisACLStoragePin struct{ Claim, ClaimUID, ClaimSpecSHA256, PV, PVUID, PVSpecSHA256 string }

// Actual namespace-scoped bound PVC and cluster PV identities, not just the
// Pod's volume declaration. Snapshot once before sealing; every subsequent
// native boundary must retain the exact original bindings/specifications.
func (g *RedisReadServiceGate) checkACLStorage(ctx context.Context, pod *corev1.Pod, container corev1.Container) error {
	var current *redisACLStoragePin
	for _, mount := range container.VolumeMounts {
		if mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" || !strings.HasPrefix(g.in.ACLFile, strings.TrimSuffix(mount.MountPath, "/")+"/") {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.Name != mount.Name || volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ReadOnly {
				continue
			}
			if current != nil {
				return ErrRedisReadGate
			}
			claim, e := g.kube.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if e != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
				return ErrRedisReadGate
			}
			pv, e := g.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name {
				return ErrRedisReadGate
			}
			current = &redisACLStoragePin{claim.Name, string(claim.UID), redisGateHash(claim.Spec), pv.Name, string(pv.UID), redisGateHash(pv.Spec)}
		}
	}
	if current == nil {
		return ErrRedisReadGate
	}
	if g.aclStorage == nil {
		copy := *current
		g.aclStorage = &copy
	} else if *current != *g.aclStorage {
		return ErrRedisReadGate
	}
	return g.check(ctx)
}
